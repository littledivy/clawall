package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

const (
	// MinSchemaVersion is the oldest config grammar this binary still
	// decodes. 0 covers unversioned legacy configs (no top-level
	// `schema_version` attribute); they load with a deprecation
	// warning. Bump this only at a major when ancient syntax is
	// finally dropped.
	MinSchemaVersion = 0

	// MaxSchemaVersion is the newest grammar this binary understands.
	// Bump it whenever a breaking grammar change ships. Configs
	// declaring a higher version are rejected with an "upgrade
	// clawpatrol" error rather than a wall of decode noise.
	MaxSchemaVersion = 1

	// DefaultDashboardName is the display name used when the gateway
	// config does not customize dashboard branding.
	DefaultDashboardName = "Claw Patrol"

	// DefaultDashboardLogoURL is the bundled full dashboard logo path.
	DefaultDashboardLogoURL = "/claw-patrol-logo.svg"

	// DefaultDashboardIconURL is the bundled compact dashboard icon path.
	DefaultDashboardIconURL = "/claw-patrol-icon.svg"
)

// schemaVersionSchema matches just the top-level `schema_version`
// attribute, so the version pre-pass can read it via PartialContent
// without consuming (or tripping over) anything else in the body.
var schemaVersionSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "schema_version"}},
}

// readSchemaVersion pulls the top-level `schema_version` off the merged
// body in a lenient pass. PartialContent ignores every other attribute
// and block, so a config written for a newer grammar (unknown
// blocks/attrs) still yields a clean version number here instead of the
// pile of "Unsupported argument" diagnostics a strict gohcl decode would
// produce. Absent ⇒ 0 (unversioned legacy).
func readSchemaVersion(body hcl.Body) (int, hcl.Diagnostics) {
	content, _, diags := body.PartialContent(schemaVersionSchema)
	if diags.HasErrors() {
		return 0, diags
	}
	attr, ok := content.Attributes["schema_version"]
	if !ok {
		return 0, diags
	}
	val, valDiags := attr.Expr.Value(nil)
	diags = append(diags, valDiags...)
	if valDiags.HasErrors() {
		return 0, diags
	}
	var v int
	if err := gocty.FromCtyValue(val, &v); err != nil {
		return 0, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid schema_version",
			Detail:   fmt.Sprintf("`schema_version` must be a whole integer: %v", err),
			Subject:  attr.Expr.Range().Ptr(),
		})
	}
	return v, diags
}

// checkSchemaVersion gates a resolved schema version against the window
// this binary supports, returning the single clean error the caller
// should surface (and nothing else — the caller skips the strict decode
// when this errors, so the upgrade/migrate message isn't buried).
func checkSchemaVersion(v int) hcl.Diagnostics {
	if v > MaxSchemaVersion {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Config schema_version too new",
			Detail:   fmt.Sprintf("schema_version = %d, but this clawpatrol understands up to %d. Upgrade clawpatrol to load this config.", v, MaxSchemaVersion),
		}}
	}
	if v < MinSchemaVersion {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Config schema_version too old",
			Detail:   fmt.Sprintf("schema_version = %d is below the minimum supported version (%d). Update the config to the current grammar.", v, MinSchemaVersion),
		}}
	}
	return nil
}

// Gateway is the fully-loaded clawpatrol gateway config: a single
// `gateway { ... }` block of operational settings (with nested
// `wireguard { ... }` / `tailscale { ... }` transport sub-blocks), an
// optional top-level `defaults { ... }` block of policy defaults, and
// the labeled policy blocks the plugins dispatch on.
type Gateway struct {
	// SchemaVersion is the config grammar this file targets. The
	// gateway accepts a range of versions and rejects anything newer
	// than it understands with an upgrade error. Omitting it loads as
	// legacy grammar (version 0) with a deprecation warning.
	SchemaVersion int `hcl:"schema_version,optional"`

	// Settings carries every operational scalar and the two transport
	// sub-blocks. Required: configs missing the block fail to load.
	Settings *GatewaySettings `hcl:"gateway,block"`

	// Defaults holds the optional `defaults { ... }` block with the
	// policy defaults (unknown_host, llm_*, human_*). nil when the
	// block is absent — every field has a built-in default.
	Defaults *Defaults `hcl:"defaults,block"`

	// Plugins lists every `plugin "<name>" { source = "..." }` block
	// at the top of the file. The loader spawns each subprocess
	// (and registers its declared types) before running pass-1
	// symbol building, so plugin-supplied (kind, type) pairs are
	// available by the time policy blocks are dispatched.
	Plugins []PluginSource `hcl:"plugin,block"`

	// Policy holds the v14-grammar block contents. Populated after
	// the operational decode by Load's pass-1 / pass-2 walk. Set to
	// a non-nil empty value if the file declared no policy blocks.
	Policy *Policy `hcl:"-"`

	// Remain is the part of the file gohcl didn't consume — i.e.
	// every policy block. Pass-2 reads from this. Not exposed in
	// the public API but kept on the struct so gohcl knows to
	// preserve it.
	Remain hcl.Body `hcl:",remain"`
}

// GatewaySettings is the body of the top-level `gateway { ... }`
// block. Every operational scalar lives here; the two transport
// sub-blocks (`wireguard` / `tailscale`) are optional and select
// which transports the gateway exposes.
type GatewaySettings struct {
	// DashboardListen is the bind address for the dashboard + JSON
	// API HTTP server. Default 127.0.0.1:8080. Set to a routable
	// address to expose the dashboard off-host (the same mux is also
	// served on the WG netstack / tsnet stack at this port).
	DashboardListen string `hcl:"dashboard_listen,optional"`

	// PublicURL is the canonical externally-reachable gateway URL.
	// Used in generated control-plane links such as join targets, OAuth
	// redirect URIs, and (when public_url has a host but wireguard.endpoint
	// doesn't) the host clients dial for WireGuard.
	PublicURL string `hcl:"public_url,optional"`

	// StateDir is the directory holding clawpatrol.db (and anything
	// a plugin persists to disk under it). Defaults to ${HOME}/.clawpatrol.
	StateDir string `hcl:"state_dir,optional"`

	// DashboardSessionTTL is how long a dashboard login session stays
	// valid after the operator types the password. time.ParseDuration
	// format ("24h", "30m"). Default 24h.
	DashboardSessionTTL string `hcl:"dashboard_session_ttl,optional"`

	// DashboardConfigWrites allows authenticated dashboard users to
	// append generated config snippets to the gateway HCL. Default
	// false: config remains read-only and changes happen out-of-band.
	DashboardConfigWrites bool `hcl:"dashboard_config_writes,optional"`

	// DashboardName customizes the product name shown in dashboard UI.
	// Empty uses DefaultDashboardName.
	DashboardName string `hcl:"dashboard_name,optional"`

	// DashboardLogoURL customizes the logo image shown in dashboard UI.
	// Absolute URLs, data URLs, and same-origin paths are accepted.
	// Empty uses DefaultDashboardLogoURL.
	DashboardLogoURL string `hcl:"dashboard_logo_url,optional"`

	// DashboardIconURL customizes the compact logo / favicon used by
	// the dashboard. Empty falls back to DashboardLogoURL when set, then
	// DefaultDashboardIconURL.
	DashboardIconURL string `hcl:"dashboard_icon_url,optional"`

	// Resolver is the DNS resolver address the gateway uses for
	// upstream lookups when the runtime needs an explicit resolver.
	Resolver string `hcl:"resolver,optional"`

	// LogPath is an optional file path for gateway log output.
	LogPath string `hcl:"log_path,optional"`

	// Telemetry opts in/out of the update-checker / anonymous usage
	// ping (doc/telemetry.md). nil = default on; explicit `telemetry
	// = false` silences the goroutine. Env vars CLAWPATROL_TELEMETRY=0
	// and DO_NOT_TRACK=1 also work.
	Telemetry *bool `hcl:"telemetry,optional"`

	// SessionKeep is the hard retention floor for the sessions table.
	// Sessions whose last_at is older than this get deleted by the
	// background sweeper. Default 720h (30d), "0" / "off" disables.
	// time.ParseDuration format.
	SessionKeep string `hcl:"session_keep,optional"`

	// ActionsKeep is the global default retention floor for the actions
	// table (captured request/response logs — the gateway's largest
	// table). Rows whose ts_ns is older than this are deleted by the
	// background sweeper. Each endpoint may override this with its own
	// `retention = "..."`. Default 720h (30d), "0" / "off" disables the
	// default sweep (per-endpoint retention still applies).
	// time.ParseDuration format.
	ActionsKeep string `hcl:"actions_keep,optional"`

	// Limits, if present, overrides the two gateway-wide body-size
	// limits (rules-engine body buffer and persisted action body
	// storage). nil uses the DefaultBody*Limit constants, which match
	// today's hardcoded behavior.
	Limits *LimitsBlock `hcl:"limits,block"`

	// GenAITelemetry, if present, enables export of OpenTelemetry GenAI
	// semantic-convention spans (gen_ai.*) for intercepted LLM
	// requests. Requires the OTLP exporter to be configured
	// (OTEL_EXPORTER_OTLP_ENDPOINT); without it there is nothing to
	// export to. The block is opt-in: when absent, no gen_ai.* spans
	// are emitted and there is no added per-request overhead.
	GenAITelemetry *GenAITelemetryBlock `hcl:"genai_telemetry,block"`

	// WireGuard, if present, enables the embedded userspace WireGuard
	// server. Required block when running WG-mode deployments.
	WireGuard *WireGuardBlock `hcl:"wireguard,block"`

	// Tailscale, if present, enables the embedded tsnet node and the
	// Tailscale control plane (OAuth key minting, exit-node routing).
	// Both transports may be enabled simultaneously.
	Tailscale *TailscaleBlock `hcl:"tailscale,block"`
}

// GenAITelemetryBlock is the body of the `genai_telemetry { ... }`
// sub-block inside `gateway { ... }`. Presence of the block enables
// emission of OpenTelemetry GenAI semantic-convention spans for
// intercepted LLM requests (gen_ai.* attributes — semconv v1.27.0).
type GenAITelemetryBlock struct {
	// IncludeMessageContent additionally captures and exports the
	// prompt/completion message content via the GenAI content
	// convention (the gen_ai.input.messages, gen_ai.output.messages,
	// and gen_ai.system_instructions span attributes), and enriches
	// gen_ai.tool.definitions with each tool's description and JSON
	// schema. Default false: message content can be large and
	// sensitive, so it is only captured when an operator explicitly
	// opts in. Independent of the base span export — the gen_ai.*
	// attribute span emits regardless of this flag, including
	// gen_ai.tool.definitions with each tool's name and type.
	IncludeMessageContent bool `hcl:"include_message_content,optional"`
}

// WireGuardBlock is the body of the `wireguard { ... }` sub-block
// inside `gateway { ... }`. Presence of the block enables the WG
// transport.
type WireGuardBlock struct {
	// SubnetCIDR is the private subnet assigned to onboarded clients.
	// Required (e.g. "10.55.0.0/24").
	SubnetCIDR string `hcl:"subnet_cidr,optional"`

	// ListenPort is the UDP port the gateway binds for WG peers.
	// Default 51820.
	ListenPort int `hcl:"listen_port,optional"`

	// HostLoopbackPort is the TCP port the gateway binds on
	// 127.0.0.1 for host-local clients (single-host deployments where
	// clawpatrol-run loops back to the gateway on the same box).
	// Default 8443. Make it operator-controlled so two gateways can
	// coexist on one host (dev/test, blue-green, multi-tenant)
	// without colliding on the loopback landing pad.
	HostLoopbackPort int `hcl:"host_loopback_port,optional"`

	// Endpoint is the host:port advertised in client wg.conf as
	// `Endpoint = ...`. Host defaults to public_url's host; port
	// defaults to listen_port. Set only for split-host deployments
	// (gateway sits behind a different hostname/IP for WG than for
	// the dashboard).
	Endpoint string `hcl:"endpoint,optional"`

	// Interface is the WireGuard interface name the gateway manages.
	// Mostly irrelevant in userspace mode; leave unset.
	Interface string `hcl:"interface,optional"`

	// ServerPub is the WireGuard server public key advertised to
	// clients. Normally derived from gateway state; only set when
	// bootstrapping from an external key.
	ServerPub string `hcl:"server_pub,optional"`
}

// TailscaleBlock is the body of the `tailscale { ... }` sub-block
// inside `gateway { ... }`. Presence of the block enables tsnet.
type TailscaleBlock struct {
	// AuthKey is the Tailscale auth key for the embedded tsnet node.
	// Required when the `tailscale` block is present. Falls back to
	// $TS_AUTHKEY if empty.
	AuthKey string `hcl:"authkey,optional"`

	// Hostname is the device name requested for the tsnet node.
	// Default "clawpatrol-gateway".
	Hostname string `hcl:"hostname,optional"`

	// ControlURL is the Tailscale control-plane URL. Empty →
	// Tailscale's hosted control plane.
	ControlURL string `hcl:"control_url,optional"`

	// Tags is the Tailscale device-tag list applied to keys the
	// gateway mints for onboarded clients (`tag:client` etc.). The
	// autoApprovers exit-node ACL must reference these tags.
	Tags []string `hcl:"tags,optional"`

	// Operators allowlists tailnet logins permitted to use the
	// dashboard without typing the root password. Each entry is
	// either an exact login ("alice@example.com") or a domain
	// wildcard ("*@example.com"). Tagged devices (whose whois login
	// is the tag name, not a user email) never match a wildcard
	// entry — agents on the tailnet can never bypass the gate
	// through this path.
	//
	// Empty / unset → tailnet-allowlist auth is disabled. The stored
	// root password is then the only way in. Lives under `tailscale
	// {}` because matching requires the tsnet whois identity; there
	// is no whois without an active tsnet node.
	Operators []string `hcl:"operators,optional"`

	// Funnel enables Tailscale Funnel on :443 so the join bootstrap
	// and credential webhook paths are internet-reachable via the
	// tsnet cert domain. Requires HTTPS enabled for the tailnet; if
	// public_url is unset the gateway derives it from the tsnet
	// cert domain at startup.
	Funnel bool `hcl:"funnel,optional"`

	// OAuthClientID is the OAuth client id used to mint per-device
	// tailnet auth keys at approval time.
	OAuthClientID string `hcl:"oauth_client_id,optional"`

	// OAuthClientSecret is the OAuth client secret paired with
	// OAuthClientID.
	OAuthClientSecret string `hcl:"oauth_client_secret,optional"`
}

// Defaults is the body of the optional top-level `defaults { ... }`
// block. Every field has a built-in default; the block is only
// needed to override one.
type Defaults struct {
	// UnknownHost controls traffic whose destination does not match
	// any endpoint. "passthrough" relays it; "deny" closes it.
	UnknownHost string `hcl:"unknown_host,optional"`

	// LLMFailMode controls requests guarded by LLM approvers when
	// the model call errors or times out. "closed" denies; "open"
	// allows.
	LLMFailMode string `hcl:"llm_fail_mode,optional"`

	// LLMCacheTTL is the LLM decision cache lifetime in seconds.
	LLMCacheTTL int `hcl:"llm_cache_ttl,optional"`

	// HumanTimeout is the default human-approval timeout in seconds.
	HumanTimeout int `hcl:"human_timeout,optional"`

	// HumanOnTimeout is the default outcome when a human approver
	// does not answer before timeout. "deny" or "allow".
	HumanOnTimeout string `hcl:"human_on_timeout,optional"`
}

// IsWireGuardEnabled reports whether the operator declared a
// `wireguard { ... }` sub-block. Block presence is the single
// switch — there is no `control` field. Both transports may be
// enabled at once.
func (g *Gateway) IsWireGuardEnabled() bool {
	return g != nil && g.Settings != nil && g.Settings.WireGuard != nil
}

// IsTailscaleEnabled reports whether the operator declared a
// `tailscale { ... }` sub-block.
func (g *Gateway) IsTailscaleEnabled() bool {
	return g != nil && g.Settings != nil && g.Settings.Tailscale != nil
}

// settings returns g.Settings, or a zero-value pointer when nil so
// callers can read fields without a nil check. Internal helper —
// validateOperational rejects configs with a nil Settings block.
func (g *Gateway) settings() *GatewaySettings {
	if g == nil || g.Settings == nil {
		return &GatewaySettings{}
	}
	return g.Settings
}

// PublicURL returns the canonical gateway URL or the empty string.
func (g *Gateway) PublicURL() string { return g.settings().PublicURL }

// SetPublicURL overwrites the public URL. Used by the runtime when
// it auto-derives the URL from the tsnet cert domain after Funnel
// comes up.
func (g *Gateway) SetPublicURL(s string) {
	if g == nil {
		return
	}
	if g.Settings == nil {
		g.Settings = &GatewaySettings{}
	}
	g.Settings.PublicURL = s
}

// DashboardListen returns the configured dashboard HTTP bind
// address, or empty string when unset.
func (g *Gateway) DashboardListen() string { return g.settings().DashboardListen }

// DashboardConfigWrites reports whether dashboard-originated config
// mutations are enabled for this gateway.
func (g *Gateway) DashboardConfigWrites() bool {
	return g != nil && g.Settings != nil && g.Settings.DashboardConfigWrites
}

// DashboardName returns the configured dashboard display name, or the
// built-in product name when unset.
func (g *Gateway) DashboardName() string {
	if v := strings.TrimSpace(g.settings().DashboardName); v != "" {
		return v
	}
	return DefaultDashboardName
}

// DashboardLogoURL returns the configured dashboard logo URL, or the
// bundled logo when unset.
func (g *Gateway) DashboardLogoURL() string {
	if v := strings.TrimSpace(g.settings().DashboardLogoURL); v != "" {
		return v
	}
	return DefaultDashboardLogoURL
}

// DashboardIconURL returns the configured compact logo URL. When the
// operator configured only a full logo, reuse it so custom branding
// doesn't fall back to the bundled claw icon on narrow screens.
func (g *Gateway) DashboardIconURL() string {
	if v := strings.TrimSpace(g.settings().DashboardIconURL); v != "" {
		return v
	}
	if v := strings.TrimSpace(g.settings().DashboardLogoURL); v != "" {
		return v
	}
	return DefaultDashboardIconURL
}

// StateDir returns the configured state directory, or empty string.
func (g *Gateway) StateDir() string { return g.settings().StateDir }

// ResolvedStateDir returns the effective state directory: the
// configured state_dir, or ${HOME}/.clawpatrol when unset. This is the
// path the gateway actually uses at runtime, so it is what the plugin
// loader must guard read_paths against — the raw StateDir() is empty by
// default, which would let a read_paths grant of the default dir slip
// past the credential-store overlap check. Returns "" only when
// state_dir is unset and $HOME is unavailable.
func (g *Gateway) ResolvedStateDir() string {
	if d := g.StateDir(); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".clawpatrol")
}

// Operators returns the tailnet-login allowlist from the `tailscale
// {}` block. Empty/nil disables the allowlist gate (and is the only
// value when no tailscale block is declared — without tsnet there's
// no whois identity to match against).
func (g *Gateway) Operators() []string {
	if !g.IsTailscaleEnabled() {
		return nil
	}
	return g.Settings.Tailscale.Operators
}

// DashboardSessionTTL returns the raw TTL string. Empty → default.
func (g *Gateway) DashboardSessionTTL() string { return g.settings().DashboardSessionTTL }

// Resolver returns the explicit DNS resolver address, or empty.
func (g *Gateway) Resolver() string { return g.settings().Resolver }

// LogPath returns the configured log file path, or empty.
func (g *Gateway) LogPath() string { return g.settings().LogPath }

// Telemetry returns the pointer-bool telemetry opt-in. nil = default on.
func (g *Gateway) Telemetry() *bool { return g.settings().Telemetry }

// GenAITelemetryEnabled reports whether OTel GenAI semantic-convention
// span export is opted in (the `genai_telemetry {}` block is present).
func (g *Gateway) GenAITelemetryEnabled() bool {
	return g != nil && g.Settings != nil && g.Settings.GenAITelemetry != nil
}

// GenAITelemetryIncludeContent reports whether message content
// (prompts/completions) should be captured on GenAI spans. Always
// false unless GenAI telemetry is enabled and the operator opted in.
func (g *Gateway) GenAITelemetryIncludeContent() bool {
	return g.GenAITelemetryEnabled() && g.Settings.GenAITelemetry.IncludeMessageContent
}

// SessionKeep returns the raw session-retention string, or empty.
func (g *Gateway) SessionKeep() string { return g.settings().SessionKeep }

// ActionsKeep returns the raw global actions-retention string, or empty.
func (g *Gateway) ActionsKeep() string { return g.settings().ActionsKeep }

// Funnel reports whether the `tailscale { }` block enabled Funnel.
func (g *Gateway) Funnel() bool {
	if !g.IsTailscaleEnabled() {
		return false
	}
	return g.Settings.Tailscale.Funnel
}

// JoinConfig is a parameter bundle of the join/transport-related
// settings. Not an HCL block — the fields are projected from the
// nested `gateway { wireguard {} tailscale {} }` shape. This struct
// exists purely so functions like StartWGServer / newOnboarder can
// take one argument instead of twelve.
type JoinConfig struct {
	AuthKey           string
	ControlURL        string
	Hostname          string
	StateDir          string
	OAuthClientID     string
	OAuthClientSecret string
	TailscaleTags     []string
	WGEnabled         bool
	WGInterface       string
	WGEndpoint        string
	WGListenPort      int
	WGServerPub       string
	WGSubnetCIDR      string
	TailscaleEnabled  bool
	// PublicURL is the operator-facing gateway URL. The WG onboarder
	// uses its host as the default client dial target when
	// WGEndpoint's host portion is wildcard / unset.
	PublicURL string
}

// Join returns the join-related fields as a JoinConfig value bundle.
// Cheap to call — it's a small struct copy.
func (g *Gateway) Join() JoinConfig {
	jc := JoinConfig{
		PublicURL: g.PublicURL(),
		StateDir:  g.StateDir(),
	}
	if g.IsTailscaleEnabled() {
		t := g.Settings.Tailscale
		jc.TailscaleEnabled = true
		jc.AuthKey = t.AuthKey
		jc.ControlURL = t.ControlURL
		jc.Hostname = t.Hostname
		jc.OAuthClientID = t.OAuthClientID
		jc.OAuthClientSecret = t.OAuthClientSecret
		jc.TailscaleTags = t.Tags
	}
	if g.IsWireGuardEnabled() {
		w := g.Settings.WireGuard
		jc.WGEnabled = true
		jc.WGInterface = w.Interface
		jc.WGEndpoint = w.Endpoint
		jc.WGListenPort = w.ListenPort
		jc.WGServerPub = w.ServerPub
		jc.WGSubnetCIDR = w.SubnetCIDR
	}
	return jc
}

// Policy is the resolved set of named policy entities. Maps are keyed
// by entity name (the second label of two-label kinds, the only label
// of one-label kinds). Insertion order is preserved in the parallel
// slices for deterministic emit / dump output.
type Policy struct {
	Approvers   map[string]*Entity
	Credentials map[string]*Entity
	Endpoints   map[string]*Entity
	Rules       map[string]*Entity
	Tunnels     map[string]*Entity

	Profiles map[string]*Profile

	// Order preserves declaration order across all kinds combined.
	// Useful for dashboard rendering and emit round-tripping.
	Order []string
}

// Entity is a successfully-loaded named entity for one of the
// plugin-dispatched kinds. The Body field is whatever the plugin's
// Build returned — the canonical record the runtime reads.
type Entity struct {
	Symbol *Symbol
	Plugin *Plugin
	Body   any
	Refs   *Refs
	// Framework holds the resolved values of framework-level attrs
	// (the FrameworkAttrSpec entries declared for this kind). The
	// loader extracts these from the block body via
	// body.PartialContent before invoking the plugin's gohcl
	// decode, so plugin authors get cross-cutting features
	// (`tunnel = X` on every endpoint) without per-plugin schema
	// boilerplate.
	Framework FrameworkAttrs
}

// FrameworkAttrs is the per-Entity bag of framework-level attr
// values. Keyed by FrameworkAttrSpec.Name. Refs holds singular
// bare-name references, RefLists holds list-of-bare-name references,
// Strings holds primitive (non-ref) string values.
type FrameworkAttrs struct {
	Refs     map[string]string
	RefLists map[string][]string
	Strings  map[string]string
}

// Ref returns the resolved reference for the named framework attr,
// or "" if unset.
func (f FrameworkAttrs) Ref(name string) string {
	if f.Refs == nil {
		return ""
	}
	return f.Refs[name]
}

// RefList returns the resolved bare-name list for the named
// framework attr, or nil if unset.
func (f FrameworkAttrs) RefList(name string) []string {
	if f.RefLists == nil {
		return nil
	}
	return f.RefLists[name]
}

// Str returns the primitive string value for the named framework
// attr, or "" if unset.
func (f FrameworkAttrs) Str(name string) string {
	if f.Strings == nil {
		return ""
	}
	return f.Strings[name]
}

// PluginSource is a top-level `plugin "<name>" { source = "..." }`
// declaration. Name is informational (the manifest name from the
// subprocess wins for type namespacing).
//
// Source is either a local path to the plugin binary or a GitHub
// repository to fetch it from:
//
//   - A local path ("/abs/path", "./rel", "~/p") runs that binary
//     directly.
//   - "github.com/<owner>/<repo>" downloads the binary from the repo's
//     GitHub releases, selecting the newest release tag that satisfies
//     Version, then caches it under the state dir and pins the resolved
//     version + per-platform hashes in clawpatrol.lock.hcl. The running
//     gateway only ever loads the locked version; `clawpatrol plugins
//     update` is the explicit upgrade.
type PluginSource struct {
	Name   string `hcl:"name,label"`
	Source string `hcl:"source"`

	// Version is a semver constraint (hashicorp/go-version syntax,
	// e.g. "~> 1.2", ">= 1.0, < 2.0") applied to a GitHub source's
	// release tags; the newest satisfying tag is selected. Empty
	// selects the newest non-prerelease. It is an error to set Version
	// on a local-path source.
	Version string `hcl:"version,optional"`

	// Provenance controls how a GitHub release's build-provenance
	// attestation is treated. "warn" (the default) verifies an
	// attestation when present and falls back to checksum-only with a
	// warning when absent; "require" refuses a release that carries no
	// (or an invalid) attestation; "off" skips the attestation check
	// (checksum + lockfile pinning still apply). Only valid on a GitHub
	// source. A present-but-invalid attestation always fails closed.
	Provenance string `hcl:"provenance,optional"`

	// Network grants the plugin direct network access. "none" (the
	// default) confines the plugin to its gateway socket — endpoint,
	// credential, and tunnel plugins all reach the network through the
	// gateway's brokered dial (endpoints via the upstream dial, tunnels
	// via the transport dial), so they need no more. "outbound" lets the
	// plugin dial out itself; it's only for the few plugins that can't use
	// the broker — e.g. one that execs helper tools (ssh, kubectl) which
	// open their own connections, or a credential plugin doing its own
	// token exchange.
	Network string `hcl:"network,optional"`

	// Sandbox controls subprocess isolation. "enforce" (the default)
	// runs the plugin inside an OS sandbox — Linux namespaces (or
	// Landlock where user namespaces are unavailable), macOS
	// seatbelt — and fails config load when no sandbox can be
	// established on this host. "off" runs the plugin with the
	// gateway user's full privileges; the gateway's environment is
	// scrubbed either way.
	Sandbox string `hcl:"sandbox,optional"`

	// ReadPaths grants the plugin recursive read-only access to
	// extra host paths (e.g. "~/.ssh" for an SSH tunnel plugin).
	// Paths must be absolute; a leading "~/" expands to the gateway
	// user's home directory. The gateway refuses a path that overlaps
	// the state dir (the secret store). There is deliberately no
	// host-write grant: writing an active location (~/.bashrc, cron,
	// a $PATH dir, ...) is a code-execution-as-the-gateway-user
	// primitive, and no denylist of such locations can be complete.
	// A plugin that genuinely needs host writes runs with
	// sandbox = "off" (the single, explicit full-trust knob);
	// durable plugin storage goes through the gateway's blob store.
	ReadPaths []string `hcl:"read_paths,optional"`
}

// PluginLoader is the gateway-side hook the loader calls before
// policy decoding. It spawns each declared plugin subprocess and
// registers the manifest types in the global plugin registry.
// Returning hcl.Diagnostics with errors aborts the load.
//
// Implemented by *extplugin.Manager — the package-cycle-safe seam
// (config can't import extplugin since extplugin imports config).
type PluginLoader interface {
	// stateDir is the gateway's resolved state directory (where the
	// secret store lives); the loader refuses a plugin read_paths
	// grant that overlaps it.
	LoadPlugins(specs []PluginSource, stateDir string) hcl.Diagnostics
}

// pluginLoader is the package-global hook every Load call uses.
// main.go installs the real *extplugin.Manager via SetPluginLoader
// at startup; the default is a no-op that quietly accepts configs
// with no `plugin {}` blocks. Tests that exercise plugin loading
// install their own loader the same way.
var pluginLoader PluginLoader = noopPluginLoader{}

// SetPluginLoader installs the loader used by every subsequent Load
// / LoadBytes call. Pass nil to revert to the default no-op.
func SetPluginLoader(p PluginLoader) {
	if p == nil {
		pluginLoader = noopPluginLoader{}
		return
	}
	pluginLoader = p
}

// noopPluginLoader is the zero-cost default. Configs without
// `plugin {}` blocks load identically against it; configs with
// such blocks pass them through without spawning anything, which
// then surfaces as an "unknown endpoint type" diagnostic for the
// referencing endpoint blocks.
type noopPluginLoader struct{}

func (noopPluginLoader) LoadPlugins([]PluginSource, string) hcl.Diagnostics { return nil }

// Profile is the lowered shape of a profile "<name>" {} block. Name
// is the block's single label (set by the loader). Credentials is
// the membership list; endpoint membership rides along as the
// transitive closure profile → credential → endpoint, and rules
// attach to endpoints (so they ride along too).
//
// Disambiguators is the per-credential profile-side dispatch
// discriminator. Outer key is credential name; inner map is
// disambiguator-field → value (e.g. {"placeholder": "PH_x"},
// {"user": "ro"}, {"database": "prod"}). Set only for credentials
// listed with inline object syntax in the profile's credentials list
// (`{ credential = name, <field> = "value", ... }`); credentials
// listed as bare names have no entry. The valid set of <field>
// names is per-credential-type — declared by the plugin's
// Plugin.Disambiguators slice — and the loader rejects unsupported
// fields here.
//
// Compile merges these onto each CompiledCredential alongside any
// block-side values; on conflict, profile-inline wins (the operator's
// most-specific declaration).
type Profile struct {
	Name            string                       `json:"name"`
	Credentials     []string                     `json:"credentials"`
	Disambiguators  map[string]map[string]string `json:"disambiguators,omitempty"`
	HITLAsyncGrants bool                         `json:"hitl_async_grants,omitempty"`
}

// CredentialDisambiguatorBody is implemented by a credential
// plugin's decoded body when one or more of its struct fields
// double as dispatch discriminators (e.g. postgres_credential's
// `user`, clickhouse_credential's `database` / `user`). The
// returned map is field-name → value; empty values are dropped.
// Compile merges this with the framework-peeled `placeholder`
// attr and the profile-inline override map to produce the per-
// (profile, endpoint) CompiledCredential dispatch entry.
type CredentialDisambiguatorBody interface {
	CredentialDisambiguators() map[string]string
}

// blockDisambiguators returns the merged disambiguator map for a
// credential block: framework-peeled "placeholder" first, then
// any fields the body's CredentialDisambiguatorBody reports.
// Empty values are dropped so the map distinguishes "field not
// declared" from "field declared but blank".
func blockDisambiguators(ent *Entity) map[string]string {
	if ent == nil {
		return nil
	}
	out := map[string]string{}
	if ph := ent.Framework.Str("placeholder"); ph != "" {
		out["placeholder"] = ph
	}
	if body, ok := ent.Body.(CredentialDisambiguatorBody); ok {
		for k, v := range body.CredentialDisambiguators() {
			if v != "" {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Load parses, validates, and resolves the gateway config at path.
// Returns a populated *Gateway plus any diagnostics. Callers should
// check diagnostics first — a non-nil Gateway can still carry errors
// (some recovery is best-effort).
//
// If path is a regular file, it's parsed as a single HCL document.
// If path is a directory, every `*.hcl` file in it (non-recursive)
// is parsed and merged in lexicographic filename order — the
// Terraform-style "module is a directory of files" model. See
// `doc/multi-file-config.md` for the contract.
//
// Plugin loading goes through the package-global PluginLoader
// installed via SetPluginLoader. main.go installs the real
// *extplugin.Manager once at startup; the default is a no-op so
// non-plugin configs and tests need no setup.
func Load(path string) (*Gateway, hcl.Diagnostics) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Cannot read config path",
			Detail:   err.Error(),
		}}
	}
	if info.IsDir() {
		return LoadDir(path)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Cannot read config file",
			Detail:   err.Error(),
		}}
	}
	return LoadBytes(src, path)
}

// LoadBytes is Load over an in-memory buffer. Used by tests so
// fixtures don't need to round-trip through the filesystem.
func LoadBytes(src []byte, filename string) (*Gateway, hcl.Diagnostics) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	return loadFiles([]*hcl.File{file}, filepath.Dir(filename), diags)
}

// LoadDir parses every `*.hcl` file in dir (non-recursive), merges
// them in lexicographic filename order, and resolves the result as
// a single gateway config — the Terraform-style mental model where a
// "module" is a directory whose files are joined.
//
// Discovery rules:
//
//   - Only direct children of dir are read (no recursion); subdirectories
//     are ignored.
//   - Files whose name ends in `.hcl` are included. Files starting with
//     `.` (dotfiles like `.swp`) are skipped so editor temporaries don't
//     poison the load.
//   - Order is lexicographic by filename (`filepath.Base`). It must not
//     affect semantics — reference resolution runs against the merged
//     symbol table — but it does decide the deterministic order
//     diagnostics, dumps, and emit traverse.
//   - Top-level singleton blocks (`gateway`, `defaults`) must appear in
//     exactly one file; duplicates are rejected with the standard gohcl
//     "Duplicate X block" diagnostic.
//   - Top-level repeatable blocks (`plugin "...", every policy entity)
//     can appear in any file, but each named entity is still unique
//     across the whole module — duplicate names across files surface as
//     `Duplicate <kind> name` from pass-1.
//   - References (`endpoint = X`, `approve = [Y]`) resolve against the
//     merged symbol table, so the order files were read in doesn't
//     determine whether a reference is reachable.
//
// `<<file:NAME>>` markers resolve relative to dir (the directory passed
// here), not relative to the individual file the marker appears in. In
// practice that's the same path since all merged files share a parent,
// but it's worth flagging if we ever extend multi-file to subdirectories.
func LoadDir(dir string) (*Gateway, hcl.Diagnostics) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Cannot read config directory",
			Detail:   err.Error(),
		}}
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, ".") {
			continue
		}
		if !strings.HasSuffix(n, ".hcl") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "No HCL config files found",
			Detail:   fmt.Sprintf("Directory %q contains no `*.hcl` files. Pass a single .hcl file or populate the directory with one or more HCL files.", dir),
		}}
	}

	parser := hclparse.NewParser()
	var diags hcl.Diagnostics
	files := make([]*hcl.File, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cannot read config file",
				Detail:   fmt.Sprintf("%s: %v", path, err),
			})
			continue
		}
		file, parseDiags := parser.ParseHCL(src, path)
		diags = append(diags, parseDiags...)
		if file != nil {
			files = append(files, file)
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}

	return loadFiles(files, dir, diags)
}

// loadFiles is the shared decode pipeline. It accepts an ordered list
// of already-parsed *hcl.File, merges them via hcl.MergeFiles, runs
// the operational gohcl decode + pass-1 + pass-2, and returns the
// resolved *Gateway. configDir is the directory used to resolve
// relative file-include markers (`<<file:NAME>>`).
func loadFiles(files []*hcl.File, configDir string, diags hcl.Diagnostics) (*Gateway, hcl.Diagnostics) {
	// hcl.MergeFiles handles the single-file case as a no-op pass-
	// through, so the multi-file code path is exercised uniformly.
	body := hcl.MergeFiles(files)

	// Read and gate the schema version before the strict decode. This
	// pre-pass is lenient (PartialContent), so a config authored for a
	// newer grammar fails with one "upgrade clawpatrol" line here
	// rather than a wall of unknown-field noise from gohcl below. A
	// version outside the supported window short-circuits the decode
	// entirely. The absent-version warning is deferred to the end of
	// the load so it only fires on otherwise-clean configs.
	ver, verDiags := readSchemaVersion(body)
	diags = append(diags, verDiags...)
	if verDiags.HasErrors() {
		return nil, diags
	}
	if d := checkSchemaVersion(ver); d.HasErrors() {
		return nil, append(diags, d...)
	}

	// Decode operational fields. Policy blocks land in gw.Remain.
	gw := &Gateway{}
	if d := gohcl.DecodeBody(body, nil, gw); d.HasErrors() {
		// Don't bail — gohcl is strict about unknown fields; we
		// downgrade unknown-attribute errors at the file root only
		// after pass-1 has had a chance to catch them as policy
		// blocks. For now, append and continue.
		diags = append(diags, d...)
	}
	if gw.Settings != nil {
		gw.Settings.PublicURL = normalizePublicURL(gw.Settings.PublicURL)
	}

	gw.Policy = &Policy{
		Approvers:   make(map[string]*Entity),
		Credentials: make(map[string]*Entity),
		Endpoints:   make(map[string]*Entity),
		Rules:       make(map[string]*Entity),
		Tunnels:     make(map[string]*Entity),
		Profiles:    make(map[string]*Profile),
	}

	// Spawn external plugins before we look at policy blocks so the
	// types they declare are visible to pass-1 symbol building. The
	// loader is package-global; see SetPluginLoader.
	if len(gw.Plugins) > 0 {
		d := pluginLoader.LoadPlugins(gw.Plugins, gw.ResolvedStateDir())
		if d.HasErrors() {
			return gw, append(diags, d...)
		}
		diags = append(diags, d...)
	}

	diags = append(diags, validateOperational(gw)...)

	// Pass 1: extract the policy blocks from the remainder body. With
	// a merged body, gw.Remain is itself a merged body whose Content
	// fans out to each file's leftover — so cross-file policy blocks
	// surface here as a single flat block list with original-file
	// ranges intact.
	policyBlocks, polDiags := extractPolicyBlocks(gw.Remain)
	diags = append(diags, polDiags...)

	table, symDiags := buildSymbols(policyBlocks)
	diags = append(diags, symDiags...)

	// Pass 2: build the eval context with every name → string, then
	// decode each policy block against its plugin's schema.
	evalCtx := buildEvalContext(table)
	resolveDiags := decodePolicyBlocks(gw.Policy, table, evalCtx, configDir)
	diags = append(diags, resolveDiags...)
	diags = append(diags, validateHITLAsyncConfig(gw)...)

	// Post-decode pass: substitute `<<file:NAME>>` markers in plugin
	// body fields that opted in via FileIncludable. Runs after Build
	// so plugins see fully-populated Bodies; the raw markers reach
	// dump / golden-test output as a side effect, which is fine —
	// goldens compare structural shape, not file contents.
	includeDiags := expandFileIncludes(gw.Policy, configDir)
	diags = append(diags, includeDiags...)

	// Record the resolved version (gohcl already set it from the
	// attribute; this keeps the field authoritative even via paths that
	// bypass the decode) and nag on legacy configs — but only when the
	// load is otherwise clean, so the reminder never crowds out the real
	// errors on a config that fails anyway.
	gw.SchemaVersion = ver
	if ver == 0 && !diags.HasErrors() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  "No schema_version declared",
			Detail:   fmt.Sprintf("This config has no top-level `schema_version`; it loads as legacy grammar. Add `schema_version = %d` to pin the grammar and silence this warning.", MaxSchemaVersion),
		})
	}

	return gw, diags
}

// dedupGohclDiags filters out gohcl's "Unsuitable value type — value
// must be known" follow-up that always pairs with an "Unknown
// variable" error at the same source location. The follow-up is a
// gohcl artifact (it's the cty conversion failing to coerce the
// unknown sentinel), and surfacing both produces noise the user
// can't act on. Dropping it leaves the precise "Unknown variable"
// pointer at the typo site.
func dedupGohclDiags(in hcl.Diagnostics) hcl.Diagnostics {
	if len(in) == 0 {
		return in
	}
	unknownAt := map[string]bool{}
	for _, d := range in {
		if d.Summary == "Unknown variable" && d.Subject != nil {
			unknownAt[d.Subject.String()] = true
		}
	}
	if len(unknownAt) == 0 {
		return in
	}
	var out hcl.Diagnostics
	for _, d := range in {
		if d.Summary == "Unsuitable value type" && d.Subject != nil && unknownAt[d.Subject.String()] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// validateOperational checks cross-field consistency on the operational
// fields that gohcl can't express in a struct tag. Catches the typical
// shapes that boot a gateway in a degraded state (silent fallback to
// plain TCP, missing WireGuard endpoint, dashboard-with-no-auth).
func validateOperational(gw *Gateway) hcl.Diagnostics {
	var diags hcl.Diagnostics

	if gw.Settings == nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Missing gateway block",
			Detail:   "The config must declare a top-level `gateway { ... }` block with operational settings (state_dir, public_url, the wireguard/tailscale transport sub-blocks, etc.).",
		})
		return diags
	}

	if !gw.IsWireGuardEnabled() && !gw.IsTailscaleEnabled() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "No transport enabled",
			Detail:   "Declare at least one of `wireguard { ... }` or `tailscale { ... }` inside the `gateway { ... }` block. Block presence selects the transport; both may be enabled simultaneously.",
		})
	}

	if gw.IsWireGuardEnabled() {
		w := gw.Settings.WireGuard
		if w.SubnetCIDR == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Missing wireguard.subnet_cidr",
				Detail:   "The `wireguard { ... }` block requires `subnet_cidr` (e.g. \"10.55.0.0/24\").",
			})
		}
		// Clients dial host(public_url):port(wireguard.endpoint).
		// wireguard.endpoint with a non-wildcard host is the escape
		// hatch when public_url isn't reachable from clients
		// (split-host deployments). On single-host loopback
		// deployments (gateway and clawpatrol-run on the same box)
		// neither needs to be set — clients dial loopback.
		if !hasWGDialTarget(gw.Settings.PublicURL, w.Endpoint) && !isLoopbackOnlyWG(w) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "WireGuard client dial target not configured",
				Detail:   "set `public_url` on the gateway block, or set `wireguard.endpoint` to a non-wildcard host:port (e.g. \"gw.example.com:51820\") — onboarded clients need one of these to know where to dial. For single-host loopback deployments set `wireguard.endpoint = \"127.0.0.1:51820\"`.",
			})
		}
	}

	// Validate every operators entry — each must be either
	// "user@domain" or "*@domain". Misshapen entries can silently
	// fail to match the intended whois login (or worse, match too
	// broadly), so we refuse to load instead of warning.
	if gw.IsTailscaleEnabled() {
		for i, entry := range gw.Settings.Tailscale.Operators {
			if err := ValidateDashboardOperatorEntry(entry); err != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Invalid operators entry",
					Detail:   fmt.Sprintf("operators[%d] = %q: %v. Use \"user@domain\" or \"*@domain\".", i, entry, err),
				})
			}
		}
	}

	if gw.Settings.DashboardSessionTTL != "" {
		if _, err := DashboardSessionTTLFromString(gw.Settings.DashboardSessionTTL); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid dashboard_session_ttl",
				Detail:   fmt.Sprintf("dashboard_session_ttl = %q: %v. Use a time.ParseDuration string like \"24h\" or \"30m\".", gw.Settings.DashboardSessionTTL, err),
			})
		}
	}

	// Retention floors: reject a malformed duration at load rather than
	// letting the sweeper silently fall back at runtime. "0" / "off"
	// (disable) are valid non-duration values.
	diags = append(diags, validateRetentionDuration("session_keep", gw.Settings.SessionKeep)...)
	diags = append(diags, validateRetentionDuration("actions_keep", gw.Settings.ActionsKeep)...)

	diags = append(diags, validateLimits(gw.Settings.Limits)...)

	return diags
}

// validateRetentionDuration flags a retention setting that is neither
// empty, the "0" / "off" disable sentinels, nor a valid non-negative
// time.ParseDuration string. Zero-valued durations ("0s") are allowed
// and mean the same as "0": disable / keep forever. Negative durations
// are rejected — downstream they would put the sweep cutoff in the
// future and delete everything, the inverse of a retention floor.
func validateRetentionDuration(name, val string) hcl.Diagnostics {
	v := strings.TrimSpace(val)
	if v == "" || v == "0" || v == "off" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid " + name,
			Detail:   fmt.Sprintf("%s = %q: %v. Use a time.ParseDuration string like %q or %q, or %q / %q to disable.", name, val, err, "720h", "30m", "0", "off"),
		}}
	}
	if d < 0 {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid " + name,
			Detail:   fmt.Sprintf("%s = %q: negative durations are not allowed. Use a positive duration like %q, or %q / %q to disable.", name, val, "720h", "0", "off"),
		}}
	}
	return nil
}

// isLoopbackOnlyWG reports whether a WireGuard block has its endpoint
// pinned to loopback. Single-host deployments — gateway under one UID,
// `clawpatrol run` from another, both on the same machine — are a
// supported pattern and need no public_url.
func isLoopbackOnlyWG(w *WireGuardBlock) bool {
	if w == nil || w.Endpoint == "" {
		return false
	}
	h, _, err := net.SplitHostPort(w.Endpoint)
	if err != nil {
		return false
	}
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

// DefaultDashboardSessionTTL is the fallback when gateway.hcl omits
// dashboard_session_ttl. 24 hours is short enough that a stolen
// cookie self-expires within a working day while long enough that
// operators don't re-type the password between coffee breaks.
const DefaultDashboardSessionTTL = 24 * time.Hour

// DashboardSessionTTLFromString parses a string like "24h" / "30m"
// into a positive duration. Empty input returns
// DefaultDashboardSessionTTL. Used by the validator (to surface bad
// input at load) and by the gateway at runtime (to convert to a
// concrete time.Duration before minting sessions).
func DashboardSessionTTLFromString(s string) (time.Duration, error) {
	if s == "" {
		return DefaultDashboardSessionTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return d, nil
}

// hasWGDialTarget reports whether the config provides a host clients
// can dial for WireGuard. Either public_url is set (we use its host),
// or wg_endpoint pins a non-wildcard host (the split-host escape
// hatch).
func hasWGDialTarget(publicURL, wgEndpoint string) bool {
	if publicURL != "" {
		return true
	}
	if wgEndpoint == "" {
		return false
	}
	h, _, err := net.SplitHostPort(wgEndpoint)
	if err != nil {
		return false
	}
	return h != "" && h != "0.0.0.0" && h != "::"
}

// extractPolicyBlocks pulls every recognized top-level block out of
// the remainder body returned by the operational gohcl decode.
// Uses Content (not PartialContent) so unknown block types — left over
// from a stale config file the new loader doesn't know about — surface
// as diagnostics instead of getting silently dropped. (Past incident:
// PR #225 renamed `gateway {}` to top-level fields; a brief deploy
// ordering meant the new binary booted against an old config and
// silently ran without a WireGuard endpoint.)
func extractPolicyBlocks(body hcl.Body) (hcl.Blocks, hcl.Diagnostics) {
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "approver", LabelNames: []string{"type", "name"}},
			{Type: "credential", LabelNames: []string{"type", "name"}},
			{Type: "endpoint", LabelNames: []string{"type", "name"}},
			{Type: "rule", LabelNames: []string{"name"}},
			{Type: "profile", LabelNames: []string{"name"}},
			{Type: "tunnel", LabelNames: []string{"type", "name"}},
		},
	}
	content, diags := body.Content(schema)
	if content == nil {
		return nil, diags
	}
	return content.Blocks, diags
}

// builtinApproverNames are approvers the gateway provides without
// requiring an HCL declaration. They resolve as bare names anywhere
// an approver reference is allowed.
var builtinApproverNames = []string{"dashboard"}

// buildEvalContext installs each declared block as a typed-ref
// variable in the eval context. Two-label kinds bucket by Type:
// `credential.foo` resolves to the string "foo". One-label kinds
// bucket by Kind keyword: `rule.foo`, `profile.foo`.
// Built-in approvers live under a synthetic "builtin" type so
// `approve = [builtin.dashboard]` works without a declaration.
//
// The leaf string stays the bare name so existing plugin decode
// paths (`Credential string`) keep working unchanged — the symbol
// table lookup at compile time uses (kind, name).
func buildEvalContext(table *SymbolTable) *hcl.EvalContext {
	buckets := map[string]map[string]cty.Value{}
	put := func(bucket, name string) {
		m := buckets[bucket]
		if m == nil {
			m = map[string]cty.Value{}
			buckets[bucket] = m
		}
		m[name] = cty.StringVal(name)
	}
	for _, sym := range table.byKey {
		switch sym.Kind.LabelCount() {
		case 2:
			put(sym.Type, sym.Name)
		case 1:
			put(string(sym.Kind), sym.Name)
		}
	}
	vars := make(map[string]cty.Value, len(buckets))
	for bucket, entries := range buckets {
		vars[bucket] = cty.ObjectVal(entries)
	}
	return &hcl.EvalContext{Variables: vars}
}

// decodePolicyBlocks runs pass 2: per-block plugin dispatch + decode +
// ref resolution + Validate + Build, plus the fixed-schema profile
// decoder.
func decodePolicyBlocks(p *Policy, table *SymbolTable, evalCtx *hcl.EvalContext, configDir string) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, sym := range table.byKind[KindProfile] {
		pr, d := decodeProfileBlock(sym, evalCtx)
		diags = append(diags, d...)
		// Cross-check: each credential name resolves to a credential.
		for _, c := range pr.Credentials {
			if table.Get(KindCredential, c) != nil {
				continue
			}
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Unknown credential %q", c),
				Detail:   fmt.Sprintf("Profile %q references credential %q which is not declared.", sym.Name, c),
				Subject:  &sym.Block.DefRange,
			})
		}
		p.Profiles[sym.Name] = pr
		p.Order = append(p.Order, sym.Name)
	}

	// Decode order: credentials and tunnels first (no cross-deps on
	// other kinds), then endpoints (which reference both), then rules
	// (which reference endpoints), then approvers (referenced by
	// rules but with no body-level dep on them at decode time).
	// Symbol-table-backed ref resolution doesn't actually require this
	// ordering — symbols are populated in pass 1 — but matching decode
	// order to compile order keeps Order[] stable across the file's
	// declaration sequence and avoids surprising readers.
	for _, kind := range []Kind{KindApprover, KindCredential, KindTunnel, KindEndpoint, KindRule} {
		for _, sym := range table.byKind[kind] {
			plugin := Lookup(sym.Kind, sym.Type)
			if plugin == nil {
				// Already reported in pass 1.
				continue
			}
			// Peel off framework-level attrs (e.g. `tunnel = X` on
			// endpoints) before gohcl sees the body. The plugin's
			// schema doesn't need to know about them; the loader
			// resolves the refs against the symbol table here.
			fw, body, fwDiags := extractFramework(sym.Block.Body, kind, evalCtx, table)
			diags = append(diags, fwDiags...)
			target := plugin.New()
			var decodeDiags hcl.Diagnostics
			if plugin.DecodeBody != nil {
				decodeDiags = plugin.DecodeBody(body, evalCtx, target)
			} else {
				decodeDiags = dedupGohclDiags(gohcl.DecodeBody(body, evalCtx, target))
			}
			diags = append(diags, decodeDiags...)
			// When decode errors, the struct may be partially populated
			// and feeding it through Validate / Build typically produces
			// cascading "missing required" / "unknown reference" noise
			// pointing at fields gohcl already complained about. Skip
			// the plugin-level passes — the user has actionable errors
			// at the precise expression range from gohcl itself.
			if decodeDiags.HasErrors() {
				continue
			}
			refs, refDiags := resolveRefs(target, sym.Name, plugin, table, sym.Block.DefRange)
			diags = append(diags, refDiags...)
			ctx := &BuildCtx{Refs: refs, Symbols: table, Block: sym.Block}
			if plugin.Validate != nil {
				diags = append(diags, plugin.Validate(target, sym.Name, ctx)...)
			}
			built, buildDiags := plugin.Build(target, sym.Name, ctx)
			diags = append(diags, buildDiags...)
			ent := &Entity{
				Symbol:    sym,
				Plugin:    plugin,
				Body:      built,
				Refs:      refs,
				Framework: fw,
			}
			switch kind {
			case KindApprover:
				p.Approvers[sym.Name] = ent
			case KindCredential:
				p.Credentials[sym.Name] = ent
			case KindTunnel:
				p.Tunnels[sym.Name] = ent
			case KindEndpoint:
				p.Endpoints[sym.Name] = ent
			case KindRule:
				p.Rules[sym.Name] = ent
			}
			p.Order = append(p.Order, sym.Name)
		}
	}

	diags = append(diags, validateCredentialBindings(p)...)
	diags = append(diags, validateProfileDisambiguators(p, table)...)

	_ = configDir // file-include resolution will use this in a follow-up
	return diags
}

// validateCredentialBindings rejects credentials that set both
// `endpoint = X` and `endpoints = [...]`. The cross-credential
// placeholder uniqueness check used to live here too; it has moved
// to validateProfilePlaceholders because placeholders are now scoped
// to the profile that wields the credential, not to the credential
// itself.
func validateCredentialBindings(p *Policy) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, ent := range p.Credentials {
		single := ent.Framework.Ref("endpoint")
		list := ent.Framework.RefList("endpoints")
		if single != "" && len(list) > 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Both endpoint and endpoints set on credential %q", ent.Symbol.Name),
				Detail:   "Use exactly one of `endpoint = X` (singular) or `endpoints = [X, Y, ...]` (list).",
				Subject:  &ent.Symbol.Block.DefRange,
			})
		}
	}
	return diags
}

// validateProfileDisambiguators enforces the post-inversion rules
// for dispatch discriminators across (profile, endpoint) tuples.
//
// A "merged" disambiguator map per credential combines two sources:
//
//  1. Block-side: framework-peeled `placeholder = "..."` and any
//     body fields the plugin exposes via CredentialDisambiguatorBody
//     (e.g. postgres_credential.user, clickhouse_credential.database).
//  2. Profile-side: the inline object entry `{ credential = X,
//     <field> = "...", ... }` in a profile's credentials list.
//     Profile-side values override block-side on conflict.
//
// Three classes of error are surfaced:
//
//   - Per-type field validity: a disambiguator field name set on
//     either side that isn't in the plugin's Plugin.Disambiguators
//     list is rejected. Catches e.g. `placeholder = "PH_x"` on a
//     postgres_credential whose only discriminator is `user`.
//   - Per-(profile, endpoint) uniqueness: the merged signature must
//     be distinct across credentials sharing an endpoint, and at
//     most one no-constraint catchall is allowed.
//   - Disambiguation necessity: a non-empty disambiguator on a
//     credential whose endpoint binding is unique within its
//     profile is rejected as dead config.
func validateProfileDisambiguators(p *Policy, table *SymbolTable) hcl.Diagnostics {
	var diags hcl.Diagnostics
	subject := func(name string) *hcl.Range {
		if table == nil {
			return nil
		}
		sym := table.Get(KindProfile, name)
		if sym == nil || sym.Block == nil {
			return nil
		}
		r := sym.Block.DefRange
		return &r
	}
	credSubject := func(name string) *hcl.Range {
		if table == nil {
			return nil
		}
		sym := table.Get(KindCredential, name)
		if sym == nil || sym.Block == nil {
			return nil
		}
		r := sym.Block.DefRange
		return &r
	}

	// Pass 1 — block-side per-type field validity. Walk every
	// credential block and reject any block-side disambiguator name
	// not listed in the plugin's Disambiguators. Done outside the
	// profile loop so the diagnostic anchors on the credential's
	// declaration range rather than the consuming profile.
	for credName, ent := range p.Credentials {
		blockD := blockDisambiguators(ent)
		if len(blockD) == 0 {
			continue
		}
		allowed := disambiguatorSet(ent)
		for field := range blockD {
			if !allowed[field] {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Credential %q: %q is not a disambiguator for type %q", credName, field, ent.Symbol.Type),
					Detail:   fmt.Sprintf("The %q credential plugin declares disambiguators %s; %q is not one of them.", ent.Symbol.Type, formatStringSet(allowed), field),
					Subject:  credSubject(credName),
				})
			}
		}
	}

	for _, pr := range p.Profiles {
		// Resolve profile.credentials → (credName → []endpoint, merged disambig).
		memberEndpoints := map[string][]string{}
		mergedDisambig := map[string]map[string]string{}
		members := map[string]bool{}
		for _, credName := range pr.Credentials {
			ent, ok := p.Credentials[credName]
			if !ok {
				continue
			}
			members[credName] = true
			memberEndpoints[credName] = CredentialEndpointTargets(ent)
			mergedDisambig[credName] = mergeDisambig(blockDisambiguators(ent), pr.Disambiguators[credName])

			// Per-type field validity on the profile-inline side too.
			if inline := pr.Disambiguators[credName]; len(inline) > 0 {
				allowed := disambiguatorSet(ent)
				for field := range inline {
					if !allowed[field] {
						diags = append(diags, &hcl.Diagnostic{
							Severity: hcl.DiagError,
							Summary:  fmt.Sprintf("Profile %q: %q is not a disambiguator for credential %q (type %q)", pr.Name, field, credName, ent.Symbol.Type),
							Detail:   fmt.Sprintf("The %q credential plugin declares disambiguators %s; %q is not one of them.", ent.Symbol.Type, formatStringSet(allowed), field),
							Subject:  subject(pr.Name),
						})
					}
				}
			}
		}

		// Per-endpoint uniqueness: signature is a stable
		// concatenation of every non-empty (field, value) pair.
		type seen struct {
			bySig    map[string]string // sig → credName
			fallback string            // credName of the no-constraint entry
		}
		perEndpoint := map[string]*seen{}
		for _, credName := range pr.Credentials {
			eps := memberEndpoints[credName]
			d := mergedDisambig[credName]
			for _, ep := range eps {
				s, ok := perEndpoint[ep]
				if !ok {
					s = &seen{bySig: map[string]string{}}
					perEndpoint[ep] = s
				}
				if len(d) == 0 {
					if s.fallback != "" {
						diags = append(diags, &hcl.Diagnostic{
							Severity: hcl.DiagError,
							Summary:  fmt.Sprintf("Profile %q: multiple no-constraint credentials bind endpoint %q", pr.Name, ep),
							Detail:   fmt.Sprintf("Credentials %q and %q both bind endpoint %q in profile %q with no dispatch discriminator set on either the credential block or the profile entry. At most one fallback (catchall) credential per (profile, endpoint).", s.fallback, credName, ep, pr.Name),
							Subject:  subject(pr.Name),
						})
						continue
					}
					s.fallback = credName
					continue
				}
				sig := disambigSignature(d)
				if dup, ok := s.bySig[sig]; ok {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Profile %q: duplicate dispatch constraint %s on endpoint %q", pr.Name, formatDisambig(d), ep),
						Detail:   fmt.Sprintf("Credentials %q and %q both bind endpoint %q in profile %q with the same dispatch constraint (%s). The merged disambiguator signature must be unique per (profile, endpoint).", dup, credName, ep, pr.Name, formatDisambig(d)),
						Subject:  subject(pr.Name),
					})
					continue
				}
				s.bySig[sig] = credName
			}
		}

		// Reject profile-side disambiguators on credentials whose
		// endpoint binding is unique within this profile — they can
		// never fire. Scoped to profile-inline overrides only:
		// block-side body fields often double as auth values (e.g.
		// postgres_credential.user is BOTH the wire-protocol user
		// AND the dispatch discriminator) and have to be set even
		// when the binding doesn't need disambiguation.
		for credName := range members {
			inline := pr.Disambiguators[credName]
			if len(inline) == 0 {
				continue
			}
			eps := memberEndpoints[credName]
			needed := false
			for _, ep := range eps {
				count := 0
				for _, other := range pr.Credentials {
					for _, oep := range memberEndpoints[other] {
						if oep == ep {
							count++
							break
						}
					}
				}
				if count > 1 {
					needed = true
					break
				}
			}
			if !needed {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Profile %q: profile-side disambiguator set on credential %q with unique endpoint binding", pr.Name, credName),
					Detail:   fmt.Sprintf("Credential %q is the only credential in profile %q that binds its endpoint(s). The profile-inline %s entry is only needed when more than one credential in a profile binds the same endpoint.", credName, pr.Name, formatDisambig(inline)),
					Subject:  subject(pr.Name),
				})
			}
		}
	}
	return diags
}

// disambiguatorSet returns the set of allowed disambiguator field
// names declared by the credential entity's plugin. Always at least
// the empty set so unknown plugins fail closed (every disambiguator
// gets rejected) rather than silently allowed.
func disambiguatorSet(ent *Entity) map[string]bool {
	out := map[string]bool{}
	if ent == nil || ent.Plugin == nil {
		return out
	}
	for _, f := range ent.Plugin.Disambiguators {
		out[f] = true
	}
	return out
}

// mergeDisambig returns the union of block + profile maps. Profile
// values override block values for the same field name; empty
// strings on either side are skipped.
func mergeDisambig(block, profile map[string]string) map[string]string {
	if len(block) == 0 && len(profile) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range block {
		if v != "" {
			out[k] = v
		}
	}
	for k, v := range profile {
		if v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// disambigSignature returns a stable key for a disambiguator map —
// fields sorted alphabetically and joined with NULs. Used for
// per-(profile, endpoint) uniqueness checking.
func disambigSignature(d map[string]string) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\x00')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(d[k])
	}
	return b.String()
}

// formatDisambig renders a disambiguator map for diagnostics: keys
// sorted alphabetically, `field="value", field="value"`.
func formatDisambig(d map[string]string) string {
	if len(d) == 0 {
		return "no constraints"
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, d[k]))
	}
	return strings.Join(parts, ", ")
}

// formatStringSet renders a set of allowed field names for diagnostics.
func formatStringSet(s map[string]bool) string {
	if len(s) == 0 {
		return "(none — this credential type cannot disambiguate when multiple bind the same endpoint)"
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q", k))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// decodeProfileBlock parses a profile block body into a Profile. The
// credentials list mixes bare-name entries (no placeholder) with
// `{ placeholder = "PH_...", credential = name }` object literals
// (per-credential dispatch discriminator). gohcl can't express that
// mixed shape, so we drive the body decode manually.
func decodeProfileBlock(sym *Symbol, evalCtx *hcl.EvalContext) (*Profile, hcl.Diagnostics) {
	pr := &Profile{Name: sym.Name}
	schema := &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "credentials", Required: true},
			{Name: "hitl_async_grants"},
		},
	}
	content, diags := sym.Block.Body.Content(schema)
	if hitl, ok := content.Attributes["hitl_async_grants"]; ok {
		hv, hd := hitl.Expr.Value(evalCtx)
		diags = append(diags, hd...)
		if !hd.HasErrors() && hv.Type() == cty.Bool {
			pr.HITLAsyncGrants = hv.True()
		}
	}
	attr, ok := content.Attributes["credentials"]
	if !ok {
		return pr, diags
	}
	val, evalDiags := attr.Expr.Value(evalCtx)
	diags = append(diags, evalDiags...)
	if evalDiags.HasErrors() {
		return pr, diags
	}
	t := val.Type()
	if !t.IsTupleType() && !t.IsListType() {
		rng := attr.Expr.Range()
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Invalid profile %q credentials", sym.Name),
			Detail:   fmt.Sprintf("Expected a list; got %s.", t.FriendlyName()),
			Subject:  &rng,
		})
		return pr, diags
	}
	rng := attr.Expr.Range()
	it := val.ElementIterator()
	for it.Next() {
		_, el := it.Element()
		et := el.Type()
		switch {
		case et == cty.String:
			pr.Credentials = append(pr.Credentials, el.AsString())
		case et.IsObjectType():
			ed := decodeProfileCredEntry(sym.Name, el, &rng)
			diags = append(diags, ed.diags...)
			if ed.cred == "" {
				continue
			}
			pr.Credentials = append(pr.Credentials, ed.cred)
			if len(ed.disambig) > 0 {
				if pr.Disambiguators == nil {
					pr.Disambiguators = map[string]map[string]string{}
				}
				pr.Disambiguators[ed.cred] = ed.disambig
			}
		default:
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid profile %q credentials entry", sym.Name),
				Detail:   fmt.Sprintf("Each entry must be a bare credential name or an object `{ credential = name, <disambiguator> = \"...\", ... }`; got %s.", et.FriendlyName()),
				Subject:  &rng,
			})
		}
	}
	return pr, diags
}

// profileCredEntry is the result of decoding one object-literal entry
// in a profile's credentials list. disambig maps disambiguator-field
// name (e.g. "placeholder", "user", "database") → operator-set value;
// validity per credential type is enforced after decode via the
// owning plugin's Plugin.Disambiguators list.
type profileCredEntry struct {
	cred     string
	disambig map[string]string
	diags    hcl.Diagnostics
}

// decodeProfileCredEntry validates a single object-literal entry in
// a profile's credentials list. The entry must declare a `credential`
// attribute (bare-name reference) and zero or more string-valued
// disambiguator attrs (any non-`credential` attribute). Per-type
// validity of the disambiguator field names is checked later by
// validateProfileDisambiguators against the plugin's
// Plugin.Disambiguators list.
func decodeProfileCredEntry(profile string, v cty.Value, rng *hcl.Range) profileCredEntry {
	out := profileCredEntry{disambig: map[string]string{}}
	t := v.Type()
	if !t.HasAttribute("credential") {
		out.diags = append(out.diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Invalid profile %q credentials entry", profile),
			Detail:   "Object entry is missing the `credential` attribute.",
			Subject:  rng,
		})
		return out
	}
	credV := v.GetAttr("credential")
	if credV.Type() != cty.String {
		out.diags = append(out.diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Invalid profile %q credentials entry", profile),
			Detail:   fmt.Sprintf("`credential` must be a bare-name reference; got %s.", credV.Type().FriendlyName()),
			Subject:  rng,
		})
		return out
	}
	out.cred = credV.AsString()
	for name := range t.AttributeTypes() {
		if name == "credential" {
			continue
		}
		fv := v.GetAttr(name)
		if fv.Type() != cty.String {
			out.diags = append(out.diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid profile %q credentials entry", profile),
				Detail:   fmt.Sprintf("Disambiguator %q must be a string; got %s.", name, fv.Type().FriendlyName()),
				Subject:  rng,
			})
			continue
		}
		s := fv.AsString()
		if s == "" {
			out.diags = append(out.diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid profile %q credentials entry", profile),
				Detail:   fmt.Sprintf("Disambiguator %q must be a non-empty string. Drop the field when no value applies.", name),
				Subject:  rng,
			})
			continue
		}
		out.disambig[name] = s
	}
	if len(out.disambig) == 0 {
		// No disambiguators is fine — the entry behaves like a bare
		// credential name. Normalize to nil so downstream `if len(.)`
		// stays consistent.
		out.disambig = nil
	}
	return out
}
