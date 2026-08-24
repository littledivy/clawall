package config

import (
	"bytes"
	"encoding/json"
)

// Dump renders the loaded gateway as deterministic, indented JSON for
// golden-file tests. Maps marshal in sorted-key order; entity bodies
// are produced by plugin Build functions and are expected to be
// json-friendly (no cty.Value fields).
//
// The output is NOT a stable serialization format. It changes when
// schema or plugins evolve and goldens regenerate via -update.
func (g *Gateway) Dump() ([]byte, error) {
	out := map[string]any{}
	if g.Settings != nil {
		out["gateway"] = dumpSettings(g.Settings)
	}
	if g.Defaults != nil {
		out["defaults"] = dumpDefaults(g.Defaults)
	}
	if g.Policy != nil {
		out["policy"] = dumpPolicy(g.Policy)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dumpSettings(s *GatewaySettings) map[string]any {
	out := map[string]any{}
	setStr := func(name, v string) {
		if v != "" {
			out[name] = v
		}
	}
	setStr("dashboard_listen", s.DashboardListen)
	setStr("public_url", s.PublicURL)
	setStr("state_dir", s.StateDir)
	setStr("dashboard_session_ttl", s.DashboardSessionTTL)
	setStr("dashboard_name", s.DashboardName)
	setStr("dashboard_logo_url", s.DashboardLogoURL)
	setStr("dashboard_icon_url", s.DashboardIconURL)
	setStr("resolver", s.Resolver)
	setStr("log_path", s.LogPath)
	if s.Telemetry != nil {
		out["telemetry"] = *s.Telemetry
	}
	setStr("session_keep", s.SessionKeep)
	setStr("actions_keep", s.ActionsKeep)
	if s.Limits != nil {
		bl := map[string]any{}
		if s.Limits.BodyBuffer != "" {
			bl["body_buffer"] = s.Limits.BodyBuffer
		}
		if s.Limits.BodyStorage != "" {
			bl["body_storage"] = s.Limits.BodyStorage
		}
		if len(bl) > 0 {
			out["limits"] = bl
		}
	}
	if s.WireGuard != nil {
		out["wireguard"] = dumpWireGuard(s.WireGuard)
	}
	if s.Tailscale != nil {
		out["tailscale"] = dumpTailscale(s.Tailscale)
	}
	return out
}

func dumpWireGuard(w *WireGuardBlock) map[string]any {
	out := map[string]any{}
	if w.SubnetCIDR != "" {
		out["subnet_cidr"] = w.SubnetCIDR
	}
	if w.ListenPort != 0 {
		out["listen_port"] = w.ListenPort
	}
	if w.HostLoopbackPort != 0 {
		out["host_loopback_port"] = w.HostLoopbackPort
	}
	if w.Endpoint != "" {
		out["endpoint"] = w.Endpoint
	}
	if w.Interface != "" {
		out["interface"] = w.Interface
	}
	if w.ServerPub != "" {
		out["server_pub"] = w.ServerPub
	}
	return out
}

func dumpTailscale(t *TailscaleBlock) map[string]any {
	out := map[string]any{}
	if t.AuthKey != "" {
		out["authkey"] = t.AuthKey
	}
	if t.Hostname != "" {
		out["hostname"] = t.Hostname
	}
	if t.ControlURL != "" {
		out["control_url"] = t.ControlURL
	}
	if len(t.Tags) > 0 {
		out["tags"] = t.Tags
	}
	if len(t.Operators) > 0 {
		out["operators"] = t.Operators
	}
	if t.Funnel {
		out["funnel"] = true
	}
	if t.OAuthClientID != "" {
		out["oauth_client_id"] = t.OAuthClientID
	}
	if t.OAuthClientSecret != "" {
		out["oauth_client_secret"] = t.OAuthClientSecret
	}
	return out
}

func dumpDefaults(d *Defaults) map[string]any {
	out := map[string]any{}
	if d.UnknownHost != "" {
		out["unknown_host"] = d.UnknownHost
	}
	if d.LLMFailMode != "" {
		out["llm_fail_mode"] = d.LLMFailMode
	}
	if d.LLMCacheTTL != 0 {
		out["llm_cache_ttl"] = d.LLMCacheTTL
	}
	if d.HumanTimeout != 0 {
		out["human_timeout"] = d.HumanTimeout
	}
	if d.HumanOnTimeout != "" {
		out["human_on_timeout"] = d.HumanOnTimeout
	}
	return out
}

func dumpPolicy(p *Policy) map[string]any {
	out := map[string]any{}
	if v := dumpEntityMap(p.Approvers); v != nil {
		out["approvers"] = v
	}
	if v := dumpEntityMap(p.Credentials); v != nil {
		out["credentials"] = v
	}
	if v := dumpEntityMap(p.Endpoints); v != nil {
		out["endpoints"] = v
	}
	if v := dumpEntityMap(p.Rules); v != nil {
		out["rules"] = v
	}
	if v := dumpEntityMap(p.Tunnels); v != nil {
		out["tunnels"] = v
	}
	if v := dumpProfiles(p.Profiles); v != nil {
		out["profiles"] = v
	}
	return out
}

func dumpEntityMap(m map[string]*Entity) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, ent := range m {
		row := map[string]any{}
		// One-label kinds (rule) carry an empty Plugin.Type — the
		// block header has no type label to dump. Family lives on
		// the built body (rules infer it from their endpoints) and
		// gets serialized there.
		if ent.Plugin.Type != "" {
			row["type"] = ent.Plugin.Type
		}
		if ent.Plugin.Family != "" {
			row["family"] = ent.Plugin.Family
		}
		row["body"] = ent.Body
		// Surface framework-level attrs (e.g. tunnel, credential
		// endpoint/endpoints) at the entity row, not inside the
		// plugin body — matches where the loader extracted them
		// from.
		for _, spec := range frameworkAttrsByKind[ent.Symbol.Kind] {
			switch {
			case spec.Kind == "":
				if v := ent.Framework.Str(spec.Name); v != "" {
					row[spec.Name] = v
				}
			case spec.List:
				if v := ent.Framework.RefList(spec.Name); len(v) > 0 {
					row[spec.Name] = v
				}
			default:
				if v := ent.Framework.Ref(spec.Name); v != "" {
					row[spec.Name] = v
				}
			}
		}
		out[name] = row
	}
	return out
}

func dumpProfiles(m map[string]*Profile) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, p := range m {
		row := map[string]any{"credentials": p.Credentials}
		if len(p.Disambiguators) > 0 {
			row["disambiguators"] = p.Disambiguators
		}
		if p.HITLAsyncGrants {
			row["hitl_async_grants"] = true
		}
		out[name] = row
	}
	return out
}
