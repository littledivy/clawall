package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/plugins/approvers"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/denoland/clawpatrol/internal/sandbox"
	"github.com/google/uuid"
	"tailscale.com/client/local"
)

// JoinConfig aliases config.JoinConfig so call sites (newWebMux /
// StartWGServer / newOnboarder / mintTailscaleAuthKey) can refer to
// it as a bare name.
type JoinConfig = config.JoinConfig

// resolveStateDir picks the directory where the gateway keeps its
// sqlite DB. The HCL `state_dir` attribute is the only knob;
// defaults to ${HOME}/.clawpatrol when unset. The DB filename
// (clawpatrol.db) coexists with the client-side ca.crt that lives
// in the same dir on dev machines.
func resolveStateDir(cfg *config.Gateway) string {
	if d := cfg.ResolvedStateDir(); d != "" {
		return d
	}
	log.Fatalf("state_dir unset and $HOME unavailable")
	return ""
}

// checkDirWritable verifies the current process can create files in
// dir. os.MkdirAll is a no-op when the directory already exists, so a
// root-owned directory — the example config's /opt/clawpatrol created
// under sudo, or a Docker `-v` mount owned by root — passes MkdirAll
// but fails every later write. Probing with a temp file surfaces that
// as a clear error instead of an opaque downstream failure (sqlite's
// "unable to open database file (14)" / SQLITE_CANTOPEN when the
// gateway opens clawpatrol.db, a silently-dropped write on join).
func checkDirWritable(dir string) error {
	probe := filepath.Join(dir, ".write-probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		return err
	}
	_ = os.Remove(probe)
	return nil
}

const hitlOperationTerminalRetention = 7 * 24 * time.Hour

func runHITLOperationStartupMaintenance(ctx context.Context, db *sql.DB) (HITLOperationMaintenanceResult, error) {
	store := NewHITLOperationStore(db)
	now := time.Now().UTC()
	retention := hitlOperationTerminalRetention
	var out HITLOperationMaintenanceResult
	recovered, err := store.RecoverStaleInProgressOperations(ctx, now, retention)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.SyncWaitingRecovered = recovered.SyncWaitingRecovered
	out.ExecutingRecovered = recovered.ExecutingRecovered
	expired, err := store.ExpireDueOperations(ctx, now, retention)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.PendingApprovalExpired = expired.PendingApprovalExpired
	out.ApprovedRetryExpired = expired.ApprovedRetryExpired
	purged, err := store.PurgeTerminalOperations(ctx, now)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.PurgedTerminal = purged
	return out, nil
}

// warnIfStateLooselyPermissioned logs a warning when state_dir or
// clawpatrol.db is readable by group / others. The sqlite db holds
// the CA private key, OAuth tokens, and audit log — anything not
// owned and 0700/0600 is a credential-leak path. Non-fatal so a
// fresh-from-mkdir setup that hasn't yet been tightened can still
// boot.
func warnIfStateLooselyPermissioned(stateDir string) {
	check := func(path string, want os.FileMode) {
		st, err := os.Stat(path)
		if err != nil {
			return
		}
		mode := st.Mode().Perm()
		if mode&0o077 != 0 {
			log.Printf("warning: %s has mode %#o (want %#o); CA key + OAuth tokens are readable beyond owner. Tighten with: chmod %#o %s", path, mode, want, want, path)
		}
	}
	check(stateDir, 0o700)
	check(filepath.Join(stateDir, "clawpatrol.db"), 0o600)
}

// seedAgentsFromDevices pre-populates the agent registry from the
// persisted devices table so the dashboard renders every onboarded
// device on boot, before any traffic arrives.
//
// Defined as its own function so the *sql.Rows cleanup is scoped to
// this read instead of riding on runGateway's lifetime (i.e. process
// lifetime). The previous in-place loop tied the pooled sql.Conn to
// the rows handle for the entire gateway run — harmless on shutdown
// but wasted a connection-pool slot for no reason.
func seedAgentsFromDevices(db *sql.DB, agents *AgentRegistry) error {
	rows, err := db.Query("SELECT id FROM devices")
	if err != nil {
		return fmt.Errorf("query devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return fmt.Errorf("scan device row: %w", err)
		}
		agents.Seed(canonicalPeerIP(ip))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate devices: %w", err)
	}
	return nil
}

// emit a terminal request event to both the SSE sink and OTel.
// ev.Action and ev.Ms must be populated. Non-request events (e.g.
// hitl_pending) call g.sink.Emit directly to stay out of the
// request-duration histogram.
func (g *Gateway) emit(ev Event) {
	g.sink.Emit(ev)
	otelRecordVerdict(ev.Action)
	otelRecordRequest(time.Duration(ev.Ms)*time.Millisecond, ev.Action, ev.Status)
}

// emitEnd marks ev as the terminal event for its request and emits.
// Skip-noop for events without an ID (legacy callers that don't have
// the start/end pairing yet — splice end events keep working).
func (g *Gateway) emitEnd(ev Event) {
	if ev.ID != "" {
		ev.Phase = "end"
	}
	g.emit(ev)
}

// parseDurationOr parses an HCL duration string ("30m", "2h"). Empty
// string falls back to def. "0" / "off" disables (returns 0). Used by
// session_keep + similar knobs that need a default with an opt-out.
func parseDurationOr(s string, def time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if s == "0" || s == "off" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("parseDuration %q: %v (using default %s)", s, err, def)
		return def
	}
	return d
}

// newReqID returns a UUIDv7 string. Time-ordered + random tail;
// used both for start/end/frame correlation and as the persistent
// action key in the DB / detail page URL.
func newReqID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// loadConfig parses the gateway HCL via the typed-block grammar and
// compiles it into a runtime CompiledPolicy. Plugin loading goes
// through config's package-global PluginLoader, installed once at
// process startup via config.SetPluginLoader.
func loadConfig(path string) (*config.Gateway, *config.CompiledPolicy, error) {
	gw, diags := config.Load(path)
	if diags.HasErrors() {
		return nil, nil, fmt.Errorf("%s", diags.Error())
	}
	cp, err := config.Compile(gw)
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}
	return gw, cp, nil
}

// orderedProfileNames returns the declared profile names in source
// order. Map iteration over Policy.Profiles isn't deterministic, so
// we re-sort by the Order slice (which buildSymbols populates in
// declaration order) and filter to KindProfile entries.
func orderedProfileNames(p *config.Policy) []string {
	out := []string{}
	if p == nil {
		return out
	}
	seen := map[string]bool{}
	for _, name := range p.Order {
		if seen[name] {
			continue
		}
		if _, ok := p.Profiles[name]; ok {
			out = append(out, name)
			seen[name] = true
		}
	}
	for name := range p.Profiles {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

func peekSNI(c net.Conn) (string, []byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 {
		return "", hdr, errors.New("not TLS")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 42 || recLen > 16384 {
		return "", hdr, errors.New("bad TLS record length")
	}
	rec := make([]byte, recLen)
	if _, err := io.ReadFull(c, rec); err != nil {
		return "", nil, err
	}
	buf := append(hdr, rec...)

	p := rec
	if len(p) < 38 || p[0] != 0x01 {
		return "", buf, errors.New("not ClientHello")
	}
	p = p[38:]
	if len(p) < 1 {
		return "", buf, errors.New("truncated")
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", buf, errors.New("truncated sid")
	}
	p = p[sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return "", buf, errors.New("truncated cs")
	}
	p = p[csLen:]
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen+2 {
		return "", buf, errors.New("truncated cm")
	}
	p = p[cmLen:]
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return "", buf, errors.New("truncated ext")
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		t := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if l > len(exts) {
			return "", buf, errors.New("truncated ext body")
		}
		if t == 0x00 {
			body := exts[:l]
			if len(body) < 5 {
				return "", buf, errors.New("bad sni")
			}
			n := int(body[3])<<8 | int(body[4])
			if 5+n > len(body) {
				return "", buf, errors.New("truncated sni name")
			}
			return string(body[5 : 5+n]), buf, nil
		}
		exts = exts[l:]
	}
	return "", buf, errors.New("no SNI")
}

type peekConn struct {
	net.Conn
	r io.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *peekConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func wrapPeek(c net.Conn, prefix []byte) net.Conn {
	return &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func newUpstreamDialer(resolver string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if resolver == "" {
		return d
	}
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dd net.Dialer
			return dd.DialContext(ctx, network, resolver)
		},
	}
	return d
}

type gatewayDialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Gateway struct {
	// cfg is the live operational *config.Gateway. Stored as an
	// atomic pointer because dashboard handlers and the reload loop
	// read it without holding configMu; configMu only serialises
	// writes (reload + dashboard-driven apply).
	cfg      atomic.Pointer[config.Gateway]
	cfgPath  string // path the HCL config was loaded from
	configMu sync.Mutex
	stateDir string // resolved gateway state dir (sqlite + plugin blobs)
	db       *sql.DB
	policy   atomic.Pointer[config.CompiledPolicy]
	certs    *CertCache
	dialer   gatewayDialer
	sink     *Sink
	// blobs is the gateway-side plugin blob store (sqlite-backed).
	// Used by endpoint plugins that need per-endpoint persistent
	// bytes — SSH host keys today, future JWT signing keys.
	// Exposed to plugins via ConnHandle.Blobs.
	blobs runtime.BlobStore
	// pluginMgr supervises the external plugin subprocesses; the
	// dashboard reads it for the Plugins page.
	pluginMgr *extplugin.Manager
	oauth     *OAuthRegistry
	agents    *AgentRegistry
	hitl      *HITLRegistry
	onboard   *onboardRegistry
	// secrets hands credential plugins the secret bytes they inject
	// at request time. gatewaySecretStore stacks the credential_secrets
	// table (dashboard slots), OAuthRegistry (refreshed access tokens),
	// and CLAWPATROL_SECRET_<NAME> env vars in that priority.
	secrets runtime.SecretStore
	// connIdx maps WG-forwarder dstIPs back to the endpoint that
	// claims them — populated by every endpoint plugin whose body
	// implements runtime.ConnRouter (postgres today, future binary
	// protocols). Rebuilt on every policy load.
	connIdx atomic.Pointer[runtime.ConnIndex]
	// dnsvip owns the hostname↔virtual-IP table for endpoints whose
	// wire protocol can't be disambiguated at TCP-accept time (SSH
	// today).
	dnsvip *dnsvip.Allocator
	// tunnels is the lifecycle manager for endpoints whose
	// CompiledEndpoint.Tunnel is non-nil. Refcounts runtime tunnel
	// instances across endpoints; the dispatcher consults it from
	// dialUpstream / ConnHandle.DialUpstream callbacks.
	tunnels *TunnelManager
	// transports memoizes one http.Transport per endpoint. Avoids the
	// per-request allocation + idle-conn-pool reset of the old path.
	transports sync.Map // *config.CompiledEndpoint -> *http.Transport
	// tailscaleIP is the gateway's own Tailscale IPv4 (100.x.x.x).
	// Set at startup in Tailscale control mode; included in onboard join
	// responses so clients can write tailnet-url without a peer-name lookup.
	tailscaleIP string
	// tailscaleHostname is the actual registered node name (e.g.
	// "clawpatrol-gateway-1") — may differ from cfg.Hostname when tsnet
	// resolves a conflict. Included in onboard join responses as
	// gateway_host so clawpatrol-run peer lookups succeed.
	tailscaleHostname string
	// tsnetLC is the embedded tsnet's LocalClient. Used to resolve a
	// peer's full address set (e.g. IPv4 → IPv6 ULA) when seeding
	// profile mappings — tsnet whole-machine traffic arrives on the
	// IPv6 ULA, so the IPv4 entry alone isn't enough.
	tsnetLC *local.Client
}

// transportFor returns the cached http.Transport for ep, building it
// on first use. dialBrowserTLS for Cloudflare-fronted hosts; mTLS
// endpoints stay on dialUpstream so credential plugins run.
func (g *Gateway) transportFor(ep *config.CompiledEndpoint) *http.Transport {
	if v, ok := g.transports.Load(ep); ok {
		return v.(*http.Transport)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.dialer.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				h = addr
			}
			if needsBrowserTLS(h) && !endpointWantsClientCert(ep) {
				return g.dialBrowserTLS(ctx, network, addr, h, ep)
			}
			profile, _ := ctx.Value(profileCtxKey{}).(string)
			return g.dialUpstream(ctx, network, addr, h, ep, profile)
		},
		ForceAttemptHTTP2:   false,
		IdleConnTimeout:     5 * time.Second,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 8,
	}
	actual, _ := g.transports.LoadOrStore(ep, tr)
	return actual.(*http.Transport)
}

// Policy returns the current snapshot of the lowered runtime policy.
// nil before the first successful Load. Cheap (atomic load).
func (g *Gateway) Policy() *config.CompiledPolicy {
	return g.policy.Load()
}

// profileFor returns the profile name to use when applying rules /
// looking up OAuth credentials for a given peer IP. Falls back to the
// "default" profile when declared, otherwise to the first declared
// profile (single-tenant default).
func (g *Gateway) profileFor(peerIP string) string {
	if g.onboard != nil {
		if p := g.onboard.ProfileForIP(peerIP); p != "" {
			return p
		}
		// Lazy alias resolution via tsnet WhoIs. Two cases this catches:
		//
		//   1. Same Tailscale node, different address family — whole-
		//      machine tsnet traffic arrives on the peer's IPv6 ULA
		//      (fd7a:115c:a1e0::/48) but only the IPv4 is registered.
		//   2. Same logical host, new Tailscale node — the host rejoined
		//      the tailnet and got a fresh 100.x; without coalescing the
		//      dashboard sprouts a phantom row per rejoin.
		//
		// ClaimAliasResolve guards against re-running WhoIs per packet
		// for peers that have no matching device.
		if g.tsnetLC != nil && g.onboard.ClaimAliasResolve(peerIP, 5*time.Minute) {
			if canonical := g.resolveTsnetAlias(peerIP); canonical != "" {
				if p := g.onboard.ProfileForIP(canonical); p != "" {
					return p
				}
			}
		}
	}
	return defaultProfileName(g.cfg.Load().Policy)
}

// resolveTsnetAlias does a one-shot tsnet WhoIs for peerIP and, on a
// match, registers an alias from peerIP onto the existing device IP.
// Returns the canonical device IP on success, or "" when no match is
// found. Both passes (address-match and hostname-match) only consider
// IPs that already have a devices row, so an unknown tailnet peer with
// no devices entry can never accidentally absorb traffic from another
// peer.
//
// Hostname matches require exactly one devices row with that name (see
// UniqueIPForHostname) so ephemeral pools that share a hostname — e.g.
// the clawpatrol-run-* nodes Tailscale auto-suffixes on collision — are
// never collapsed into one another.
func (g *Gateway) resolveTsnetAlias(peerIP string) string {
	if g.tsnetLC == nil || g.onboard == nil || peerIP == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	w, err := g.tsnetLC.WhoIs(ctx, net.JoinHostPort(peerIP, "0"))
	if err != nil || w == nil || w.Node == nil {
		return ""
	}
	for _, addr := range w.Node.Addresses {
		ip := addr.Addr().String()
		if ip == peerIP {
			continue
		}
		if g.onboard.HasDevice(ip) {
			g.onboard.RegisterIPAlias(peerIP, ip)
			return ip
		}
	}
	hostname := w.Node.ComputedName
	if hostname == "" && w.Node.Hostinfo.Valid() {
		hostname = w.Node.Hostinfo.Hostname()
	}
	if canonical := g.onboard.UniqueIPForHostname(hostname); canonical != "" && canonical != peerIP {
		g.onboard.RegisterIPAlias(peerIP, canonical)
		return canonical
	}
	return ""
}

// seedTsnetIPv6Alias resolves peerIP (IPv4) to the peer's IPv6 ULA via
// tsnet WhoIs and mirrors the same profile mapping onto the v6 in the
// onboard registry. Whole-machine tsnet traffic frequently arrives on
// the fd7a:115c:a1e0::/48 ULA rather than the 100.x IPv4 — without
// the alias profileFor falls back to "default" and dispatch misses
// every endpoint declared on the actual profile.
func (g *Gateway) seedTsnetIPv6Alias(peerIP string) {
	if g.tsnetLC == nil || g.onboard == nil || peerIP == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w, err := g.tsnetLC.WhoIs(ctx, net.JoinHostPort(peerIP, "0"))
	if err != nil || w == nil || w.Node == nil {
		return
	}
	for _, addr := range w.Node.Addresses {
		ip := addr.Addr()
		if !ip.Is6() {
			continue
		}
		alias := ip.String()
		g.onboard.RegisterIPAlias(alias, peerIP)
		// Drop any ghost agent row that was seeded under the v6 before
		// the alias landed — traffic now folds to the v4 parent.
		if g.agents != nil {
			g.agents.Delete(alias)
		}
	}
}

// agentIPFor returns the IP to use for traffic attribution. Ephemeral
// peers are remapped to their parent device's IP so all activity shows
// under a single device in the dashboard.
func (g *Gateway) agentIPFor(c net.Conn) string {
	ip := peerIP(c)
	if g.onboard == nil {
		return ip
	}
	// Mirror the lazy WhoIs lookup in profileFor here so callers that
	// reach agentIPFor without first going through profileFor (e.g. the
	// LLM-session bookkeeping paths) still benefit from alias resolution.
	// Both functions use the same ClaimAliasResolve guard, so the WhoIs
	// runs at most once per peer per 5-minute window regardless of which
	// one is called first.
	if g.tsnetLC != nil && g.onboard.ClaimAliasResolve(ip, 5*time.Minute) {
		g.resolveTsnetAlias(ip)
	}
	return g.onboard.AgentIPFor(ip)
}

// defaultProfileName returns the profile a freshly-onboarded peer
// should attach to. Prefers a profile literally named "default";
// otherwise the first declared profile in source order. Empty when
// no profiles are configured (legacy single-tenant mode).
func defaultProfileName(p *config.Policy) string {
	names := orderedProfileNames(p)
	for _, n := range names {
		if n == "default" {
			return "default"
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// watchConfig polls the config file's mtime every 3s. On change it
// re-decodes the HCL and atomically swaps in the new rules + admin_email
// + integrations list. Listen ports / CA dir / OAuth dir / Tailscale
// block changes still require a restart (logged but not applied).
// watchPluginUpdates periodically checks GitHub for newer releases of
// pinned plugins and records "update available" for the dashboard. It
// never downloads or applies anything — upgrading is the operator's
// explicit `clawpatrol plugins update`. The first check runs shortly
// after startup, then daily.
func (g *Gateway) watchPluginUpdates() {
	if g.pluginMgr == nil {
		return
	}
	time.Sleep(30 * time.Second)
	for {
		specs := g.cfg.Load().Plugins
		if len(specs) > 0 {
			// CheckUpdates reloads the shared lockfile store, so it must
			// not interleave with a config-reload's LoadPlugins (which does
			// its own load -> TOFU -> save). configMu serializes them.
			g.configMu.Lock()
			g.pluginMgr.CheckUpdates(context.Background(), specs)
			g.configMu.Unlock()
		}
		time.Sleep(24 * time.Hour)
	}
}

func (g *Gateway) watchConfig(path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	last := st.ModTime()
	for {
		time.Sleep(3 * time.Second)
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().After(last) {
			continue
		}
		last = st.ModTime()
		g.configMu.Lock()
		err = g.reloadConfigFromFileLocked(path)
		g.configMu.Unlock()
		if err != nil {
			log.Printf("config reload: %v", err)
		}
	}
}

// reloadConfigFromFileLocked reloads the HCL config and hot-swaps the
// runtime policy. g.configMu must be held by the caller so file-watch
// reloads and dashboard writes cannot race each other.
func (g *Gateway) reloadConfigFromFileLocked(path string) error {
	next, policy, err := loadConfig(path)
	if err != nil {
		return err
	}
	g.policy.Store(policy)
	registerOAuthCredentials(g.oauth, policy)
	g.connIdx.Store(runtime.BuildConnIndex(policy))
	if g.tunnels != nil {
		g.tunnels.SetPolicy(context.Background(), policy)
	}
	if g.dnsvip != nil {
		if err := g.dnsvip.RebuildFromPolicy(policy); err != nil {
			return fmt.Errorf("dnsvip rebuild on reload: %w", err)
		}
	}
	// Hot-swap the operational *config.Gateway too. Listen / CA dir /
	// Tailscale process changes are still restart-only.
	g.cfg.Store(next)
	log.Printf("config reloaded: %d endpoints across %d profile(s)",
		len(policy.Endpoints), len(policy.Profiles))
	logDashboardAuthState(g.db, next)
	return nil
}

// logDashboardAuthState emits a one-line summary of dashboard-auth
// state every time the config (re)loads, so an uninitialized or
// misconfigured dashboard shows up in `journalctl -u clawpatrol-
// gateway` even when nobody opens the dashboard in a browser.
//
// The root password lives in clawpatrol.db, not in gateway.hcl —
// so we resolve its presence by querying the DB.
func logDashboardAuthState(db *sql.DB, cfg *config.Gateway) {
	_, rootSet, err := lookupDashboardUser(db, dashboardRootUsername)
	if err != nil {
		log.Printf("dashboard auth: UNKNOWN — lookup failed: %v", err)
		return
	}
	tailnetMode := cfg.IsTailscaleEnabled()
	operators := cfg.Operators()
	allowlist := len(operators) > 0

	switch {
	case rootSet && allowlist && tailnetMode:
		log.Printf("dashboard auth: enabled (root password + %d-entry tailnet operator allowlist)", len(operators))
	case rootSet && allowlist && !tailnetMode:
		log.Printf("dashboard auth: enabled (root password); operators is set but ignored — no tailscale block, no tailnet whois")
	case rootSet:
		log.Printf("dashboard auth: enabled (root password)")
	case !rootSet && allowlist && tailnetMode:
		log.Printf("dashboard auth: pending — no root password yet; tailnet operator allowlist alone cannot bootstrap. Open the dashboard or run `clawpatrol gateway --set-dashboard-password <pw>`.")
	default:
		log.Printf("dashboard auth: pending — no root password yet. Open the dashboard at dashboard_listen %q to set one, or run `clawpatrol gateway --set-dashboard-password <pw>`.", cfg.DashboardListen())
	}
}

// sweepDashboardSessions deletes expired session rows on a slow tick.
// Lazy expiry on lookup already filters expired sessions out of auth
// decisions; this loop is purely a vacuum so a long-running gateway
// doesn't accumulate rows for browsers that never come back. Runs
// for the life of the gateway.
func (g *Gateway) sweepDashboardSessions() {
	const interval = 15 * time.Minute
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if n, err := sweepExpiredDashboardSessions(g.db); err != nil {
			log.Printf("dashboard session sweep: %v", err)
		} else if n > 0 {
			log.Printf("dashboard session sweep: deleted %d expired row(s)", n)
		}
	}
}

// applyDashboardPasswordFlags handles --set-dashboard-password and
// --reset-dashboard-password before the HTTP listener boots. The
// flags are deliberately verbose: each one log-prints what it did so
// the journalctl trail shows when an operator intervened.
//
// Mutual exclusion: --reset wins if both are passed. Empty
// --set-dashboard-password is a no-op (Go's flag package treats it
// the same as not passing the flag at all).
func applyDashboardPasswordFlags(db *sql.DB, setPassword string, reset bool) {
	if reset {
		if err := deleteDashboardUser(db, dashboardRootUsername); err != nil {
			log.Fatalf("--reset-dashboard-password: %v", err)
		}
		log.Printf("dashboard auth: root password cleared via --reset-dashboard-password (next dashboard hit will re-run first-run setup)")
		return
	}
	if setPassword == "" {
		return
	}
	if err := setDashboardUser(db, dashboardRootUsername, setPassword); err != nil {
		log.Fatalf("--set-dashboard-password: %v", err)
	}
	log.Printf("dashboard auth: root password set via --set-dashboard-password")
}

// trackCodexWSUsage parses a single WebSocket text-frame payload from
// chatgpt.com/codex traffic. Codex sends JSON envelopes containing the
// user prompt (client→server) and usage info (server→client). Sessions
// key on the per-connection wsSessionID supplied by handleWSUpgrade
// — usually codex's own `Session_id` request header so two parallel
// `clawpatrol run codex` instances on the same device land in
// distinct rows. Empty wsSessionID falls back to a per-remoteAddr
// hash so older code paths still produce one row per connection.
func (g *Gateway) trackCodexWSUsage(remoteAddr, wsSessionID string, payload []byte) {
	ip := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = h
	}
	sid := wsSessionID
	if sid == "" {
		sid = "ws_" + shortHash(remoteAddr)
	} else {
		sid = "s_" + shortHash(sid)
	}
	// Codex Responses-API frames. Shapes we care about:
	//   client → server: full request envelope w/ `input` (user prompt)
	//     {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]}],
	//      "model":"...", ...}
	//   server → client:
	//     {"type":"response.created","response":{"id":"...","model":"..."}}
	//     {"type":"response.output_item.added","item":{"type":"function_call",
	//        "name":"shell"|"apply_patch"|...,"arguments":"<json string>"}}
	//     {"type":"response.completed","response":{"usage":{...},
	//        "output":[{"type":"message","content":[{"type":"output_text","text":"..."}]}]}}
	var msg struct {
		Type     string `json:"type"`
		Model    string `json:"model"`
		Response struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Usage struct {
				InputTokens           int64 `json:"input_tokens"`
				CachedInputTokens     int64 `json:"cached_input_tokens"`
				OutputTokens          int64 `json:"output_tokens"`
				ReasoningOutputTokens int64 `json:"reasoning_output_tokens"`
			} `json:"usage"`
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		} `json:"response"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
		Item struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"item"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	model := msg.Response.Model
	if model == "" {
		model = msg.Model
	}
	in := msg.Response.Usage.InputTokens + msg.Response.Usage.CachedInputTokens + msg.Usage.InputTokens
	out := msg.Response.Usage.OutputTokens + msg.Response.Usage.ReasoningOutputTokens + msg.Usage.OutputTokens
	// Title selection — latest wins. recordLLMUsage overwrites Title
	// on every non-empty pass, so the dashboard shows whatever the
	// session is doing right now:
	//   - user prompt frame → "<first input_text>"
	//   - tool-call frame   → "▸ <name>(<first arg snippet>)"
	//   - completion frame  → "↩ <assistant text head>"
	title := codexInputTitle(msg.Input)
	if title == "" && msg.Type == "response.output_item.added" && msg.Item.Type == "function_call" {
		title = codexToolTitle(msg.Item.Name, msg.Item.Arguments)
	}
	if title == "" && msg.Type == "response.completed" {
		title = codexCompletedTitle(msg.Response.Output)
	}
	if in == 0 && out == 0 && model == "" && title == "" {
		return
	}
	g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
}

// codexWSTurn assembles a GenAI turn from a Codex WebSocket frame
// sequence. Codex's /backend-api/codex/responses runs over a WS upgrade
// (see the WS-upgrade branch in mitmHTTPS) rather than the HTTP/SSE path
// trackLLMUsage handles, so a turn's request and response arrive on
// separate frames: the client→server request envelope carries the
// prompt / model / tools, and the server→client response.completed frame
// carries the output and usage. observeRequest stashes the envelope;
// observeResponse returns a ready-to-record completion when the terminal
// frame lands. The two WS pump goroutines (client→server and
// server→client) call these concurrently, so the stashed state is mutex
// guarded.
type codexWSTurn struct {
	mu          sync.Mutex
	reqEnvelope []byte
	start       time.Time
	// outputItems holds the finished output items (message / reasoning /
	// function_call) accumulated from response.output_item.done frames,
	// keyed by output_index (latest-wins); outputOrder preserves first-seen
	// order. Codex's terminal response.completed frame carries an empty
	// output array — the real output rides these per-item frames — so they
	// are spliced into the response body when the terminal frame lands.
	outputItems map[int]json.RawMessage
	outputOrder []int
}

// observeRequest records a client→server request envelope — the frame
// carrying the `input` array. Latest-wins: the most recent envelope seen
// before a completion is the one paired with it. A new request envelope
// starts a new turn, so any output items accumulated for a prior,
// terminal-less turn are dropped.
func (t *codexWSTurn) observeRequest(payload []byte, now time.Time) {
	var probe struct {
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(payload, &probe) != nil || len(probe.Input) == 0 {
		return
	}
	t.mu.Lock()
	t.reqEnvelope = append([]byte(nil), payload...)
	t.start = now
	t.outputItems = nil
	t.outputOrder = nil
	t.mu.Unlock()
}

// codexWSCompletion is the assembled pieces of one Codex WS turn, ready to
// hand to recordGenAITurn. respBody is the inner `response` object of the
// terminal frame — a Responses-API response body that maps through
// mapOpenAITurn exactly like the HTTP path's; reqBody is the paired request
// envelope (nil if no request frame was seen on this connection).
type codexWSCompletion struct {
	reqBody   []byte
	respBody  []byte
	reqModel  string
	respModel string
	in, out   int64
	start     time.Time
}

// observeResponse inspects a server→client frame. On a terminal
// response.completed / .incomplete / .failed frame it returns the assembled
// completion; every other frame returns nil. The request envelope is
// consumed so a stray duplicate terminal frame can't re-emit a span.
func (t *codexWSTurn) observeResponse(payload []byte) *codexWSCompletion {
	var msg struct {
		Type        string          `json:"type"`
		Response    json.RawMessage `json:"response"`
		Item        json.RawMessage `json:"item"`
		OutputIndex int             `json:"output_index"`
	}
	if json.Unmarshal(payload, &msg) != nil {
		return nil
	}
	// A finished output item (message / reasoning / function_call). Codex
	// streams the real output on these frames; the terminal frame's output
	// is always empty. Stash by output_index (latest-wins) to splice in
	// when the terminal frame lands.
	if msg.Type == "response.output_item.done" && len(msg.Item) > 0 {
		t.mu.Lock()
		if t.outputItems == nil {
			t.outputItems = map[int]json.RawMessage{}
		}
		if _, seen := t.outputItems[msg.OutputIndex]; !seen {
			t.outputOrder = append(t.outputOrder, msg.OutputIndex)
		}
		t.outputItems[msg.OutputIndex] = append([]byte(nil), msg.Item...)
		t.mu.Unlock()
		return nil
	}
	if !isResponsesTerminalEvent(msg.Type) || len(msg.Response) == 0 {
		return nil
	}
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(msg.Response, &resp)

	t.mu.Lock()
	reqBody := t.reqEnvelope
	start := t.start
	items := t.outputItems
	order := t.outputOrder
	t.reqEnvelope = nil
	t.outputItems = nil
	t.outputOrder = nil
	t.mu.Unlock()

	// Codex's terminal response carries output:[]; splice the accumulated
	// per-item output in so mapOpenAITurn extracts gen_ai.output.messages.
	respBody := codexSpliceOutput(msg.Response, items, order)

	// Prefer the request's model (e.g. "gpt-5-codex"); the response may
	// echo a dated variant. Fall back to the response model when the
	// request frame wasn't captured.
	reqModel := codexRequestModel(reqBody)
	if reqModel == "" {
		reqModel = resp.Model
	}
	return &codexWSCompletion{
		reqBody:   reqBody,
		respBody:  respBody,
		reqModel:  reqModel,
		respModel: resp.Model,
		in:        resp.Usage.InputTokens,
		out:       resp.Usage.OutputTokens,
		start:     start,
	}
}

// codexSpliceOutput returns the terminal response object with its `output`
// array replaced by the items accumulated from response.output_item.done
// frames, keyed by output_index in first-seen order. Codex's terminal frame
// always carries output:[], so without this the assistant output is lost.
// When the response already carries a non-empty output (e.g. a future Codex
// change, or the standard OpenAI Responses API), or no items were collected,
// the response is returned unchanged.
func codexSpliceOutput(response json.RawMessage, items map[int]json.RawMessage, order []int) []byte {
	verbatim := append([]byte(nil), response...)
	if len(items) == 0 {
		return verbatim
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(response, &obj) != nil {
		return verbatim
	}
	var existing []json.RawMessage
	if json.Unmarshal(obj["output"], &existing) == nil && len(existing) > 0 {
		return verbatim
	}
	arr := make([]json.RawMessage, 0, len(order))
	for _, i := range order {
		arr = append(arr, items[i])
	}
	outJS, err := json.Marshal(arr)
	if err != nil {
		return verbatim
	}
	obj["output"] = outJS
	spliced, err := json.Marshal(obj)
	if err != nil {
		return verbatim
	}
	return spliced
}

// codexToolTitle formats a tool-call frame into "▸ name(arg)". Codex's
// `arguments` field is a JSON string whose shape varies per tool —
// shell.command[], apply_patch.input, file_search.query, etc. We pull
// the first usefully-named argument when present, else show the raw
// args truncated.
func codexToolTitle(name, args string) string {
	if name == "" {
		return ""
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(args), &generic); err != nil {
		return "▸ " + name
	}
	// Preferred argument keys, in order. Most codex tools surface one
	// of these as the human-meaningful value.
	for _, k := range []string{"command", "path", "file_path", "input", "query", "url"} {
		v, ok := generic[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			return "▸ " + name + " " + truncate(t, 40)
		case []any:
			parts := make([]string, 0, len(t))
			for _, p := range t {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			joined := strings.Join(parts, " ")
			if joined != "" {
				return "▸ " + name + " " + truncate(joined, 40)
			}
		}
	}
	return "▸ " + name
}

// codexCompletedTitle returns the assistant's final text from a
// response.completed frame. Walks output[].content[] looking for the
// first output_text block and uses its head as the title — gives the
// dashboard a glimpse of what the model just said when no tool call
// followed.
func codexCompletedTitle(output []struct {
	Type    string `json:"type"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}) string {
	for _, o := range output {
		for _, c := range o.Content {
			if c.Text != "" {
				return "↩ " + truncate(c.Text, 60)
			}
		}
	}
	return ""
}

// codexInputTitle returns the LATEST user text from a Codex
// Responses-API `input` array. Codex sends the full conversation
// history on every turn; the most-recent user message lives at the
// tail. Walking forward (the old behavior) returned the system-y
// first prompt ("You are deno node-compat fixer …") every time and
// title never changed across turns.
func codexInputTitle(input []struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}) string {
	for i := len(input) - 1; i >= 0; i-- {
		m := input[i]
		if m.Role != "user" {
			continue
		}
		text := stripCodexWrappers(joinUserContent(m.Content))
		if text != "" {
			return truncate(text, 80)
		}
	}
	return ""
}

// codexInputFirstTitle returns the FIRST real user message from a Codex
// input array — used as a stable session ID seed across turns (since the
// full conversation history is resent every turn, the first message never
// changes, giving a consistent shortHash).
func codexInputFirstTitle(input []struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}) string {
	for _, m := range input {
		if m.Role != "user" {
			continue
		}
		text := stripCodexWrappers(joinUserContent(m.Content))
		if text != "" {
			return truncate(text, 80)
		}
	}
	return ""
}

// joinUserContent flattens a Codex/OpenAI message Content (string OR
// array of typed blocks). Blocks are joined with newlines so a single
// user message that mixes <environment_context> + the actual prompt
// (sent as separate input_text blocks) yields the full text after
// stripCodexWrappers peels off the wrapper.
func joinUserContent(c json.RawMessage) string {
	var s string
	if err := json.Unmarshal(c, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(c, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

// stripCodexWrappers removes Codex CLI's auto-injected XML wrapper
// blocks (environment_context, user_instructions) so the session
// title shows the actual user prompt.
func stripCodexWrappers(s string) string {
	return stripXMLBlocks(s, "environment_context", "user_instructions")
}

// trackKindFor returns the usage-parsing flavor for a given host (and,
// for chatgpt.com, also gates HTTP-mode codex tracking). Tracking is
// always-on; operators don't configure it per rule. chatgpt.com matches
// by suffix — codex HTTP POSTs hit backend-api.chatgpt.com, WS upgrades
// hit chatgpt.com bare; both need the codex parser.
func trackKindFor(host string) string {
	h := strings.ToLower(host)
	switch h {
	case "api.anthropic.com":
		return "claude_usage"
	case "api.openai.com":
		return "openai_usage"
	}
	if strings.HasSuffix(h, "chatgpt.com") {
		return "codex_ws_usage"
	}
	return ""
}

// preCreateLLMSession parses just the request body and seeds a session
// row with title + model so the dashboard reflects an in-flight turn
// before the SSE stream completes. Token counts arrive later via
// trackLLMUsage. Mirrors trackLLMUsage's path/kind gating but skips
// any work that depends on the response body.
// sessionHint is the value of the Session_id / Session-Id request header
// when present — used as a stable session key for codex_ws_usage HTTP requests.
func (g *Gateway) preCreateLLMSession(c net.Conn, kind, path string, reqBody []byte, sessionHint string) {
	if g.agents == nil {
		return
	}
	ip := g.agentIPFor(c)
	switch kind {
	case "claude_usage":
		if path != "/v1/messages" {
			return
		}
		reqInfo := parseClaudeRequest(reqBody)
		sid := reqInfo.SessionID
		title := reqInfo.Title
		if sid == "" {
			if title == "" {
				return
			}
			sid = shortHash(title)
		}
		g.agents.recordLLMUsage(ip, "claude", sid, title, reqInfo.Model, 0, 0)
	case "openai_usage":
		if !strings.HasPrefix(path, "/v1/chat/completions") &&
			!strings.HasPrefix(path, "/v1/responses") &&
			!strings.HasPrefix(path, "/v1/completions") {
			return
		}
		title := openaiFirstUserMessage(reqBody)
		if title == "" {
			return
		}
		g.agents.recordLLMUsage(ip, "codex", shortHash(title), title, "", 0, 0)
	case "codex_ws_usage":
		if !strings.Contains(path, "/codex/responses") {
			return
		}
		title := codexResponsesRequestTitle(reqBody)
		if title == "" {
			return
		}
		sid := shortHash(sessionHint)
		if sid == "" {
			sid = shortHash(codexResponsesRequestFirstTitle(reqBody))
		}
		g.agents.recordLLMUsage(ip, "codex", sid, title, codexRequestModel(reqBody), 0, 0)
	}
}

// codexRequestModel pulls the top-level "model" field from a codex
// /backend-api/codex/responses request body. The Codex SSE stream
// doesn't include model in the JSON payload (it ships in the
// OpenAI-Model response header instead), so the request body is the
// only place to source it before the turn completes.
func codexRequestModel(body []byte) string {
	var r struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Model
}

// trackLLMUsage parses LLM API request/response bodies for session id,
// title, model, and token usage. Only fires on actual model-invocation
// endpoints; ignores heartbeat / event_logging / mcp / oauth probes.
func (g *Gateway) trackLLMUsage(c net.Conn, kind, host, path string, reqBody, respBody []byte, sessionHint string, reqStart time.Time) {
	ip := g.agentIPFor(c)
	switch kind {
	case "claude_usage":
		if path != "/v1/messages" {
			return
		}
		reqInfo := parseClaudeRequest(reqBody)
		respModel, in, out := parseClaudeResponse(respBody)
		model := reqInfo.Model
		if model == "" {
			model = respModel
		}
		// Prefer Claude Code's session id from metadata; fall back to
		// hash of first real user message. Skip usage if neither.
		sid := reqInfo.SessionID
		title := reqInfo.Title
		if sid == "" && title != "" {
			sid = shortHash(title)
		}
		g.recordGenAITurn("anthropic", sid, host, reqInfo.Model, respModel, in, out, reqBody, respBody, reqStart, ip)
		if sid == "" {
			return // heartbeat/probe with no session info
		}
		g.agents.recordLLMUsage(ip, "claude", sid, title, model, in, out)
	case "openai_usage":
		if !strings.HasPrefix(path, "/v1/chat/completions") &&
			!strings.HasPrefix(path, "/v1/responses") &&
			!strings.HasPrefix(path, "/v1/completions") {
			return
		}
		title := openaiFirstUserMessage(reqBody)
		sid := shortHash(title)
		model, in, out := parseOpenAIResponse(respBody)
		if model == "" && in == 0 && out == 0 && title == "" {
			return
		}
		g.recordGenAITurn("openai", sid, host, model, model, in, out, reqBody, respBody, reqStart, ip)
		g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
	case "codex_ws_usage":
		// chatgpt.com Codex backend. Two transports:
		//   1. POST /backend-api/codex/responses (SSE stream) — usual path
		//   2. WSS upgrade (handled separately in handleWSUpgrade via
		//      trackCodexWSUsage frame parser). This case only fires for
		//      HTTP-mode requests since WS upgrades return early before
		//      trackLLMUsage.
		if !strings.Contains(path, "/codex/responses") {
			return
		}
		title := codexResponsesRequestTitle(reqBody)
		respModel, in, out := parseOpenAIResponse(respBody)
		// gen_ai.request.model must be the model the client asked for
		// (e.g. "gpt-5-codex"), not the dated variant the response echoes
		// ("gpt-5-codex-2026"). Codex's SSE response body carries neither
		// the request model (it rides the OpenAI-Model response header) nor,
		// on many turns, token usage, so source the request model from the
		// request body — the same split the WS path (handleWSUpgrade →
		// codexWSTurn) uses, so both transports emit identical spans. Fall
		// back to the response model when the request body wasn't captured
		// (e.g. oversized/truncated), which also keeps recordGenAITurn's
		// model/usage guard satisfied so the turn is still recorded.
		reqModel := codexRequestModel(reqBody)
		if reqModel == "" {
			reqModel = respModel
		}
		if reqModel == "" && in == 0 && out == 0 && title == "" {
			return
		}
		sid := shortHash(sessionHint)
		if sid == "" {
			sid = shortHash(codexResponsesRequestFirstTitle(reqBody))
		}
		g.recordGenAITurn("openai", sid, host, reqModel, respModel, in, out, reqBody, respBody, reqStart, ip)
		g.agents.recordLLMUsage(ip, "codex", sid, title, reqModel, in, out)
	}
}

// codexResponsesRequestTitle parses a chatgpt.com /backend-api/codex/responses
// POST body and returns the latest user message text. Body shape mirrors
// OpenAI Responses API: {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]},...]}.
// Reuses codexInputTitle so HTTP and WS paths agree — backward walk skips
// the stale environment_context wrapper that fronts every turn.
func codexResponsesRequestTitle(body []byte) string {
	var req struct {
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return codexInputTitle(req.Input)
}

// codexResponsesRequestFirstTitle returns the first real user message from
// the request body — stable across turns, used as a session ID seed.
func codexResponsesRequestFirstTitle(body []byte) string {
	var req struct {
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return codexInputFirstTitle(req.Input)
}

func parseOpenAIResponse(body []byte) (model string, in, out int64) {
	var jr struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			InputTokens      int64 `json:"input_tokens"`
			OutputTokens     int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && jr.Model != "" {
		in = jr.Usage.PromptTokens + jr.Usage.InputTokens
		out = jr.Usage.CompletionTokens + jr.Usage.OutputTokens
		return jr.Model, in, out
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var ev struct {
			Model    string `json:"model"`
			Response struct {
				Model string `json:"model"`
				Usage struct {
					InputTokens  int64 `json:"input_tokens"`
					OutputTokens int64 `json:"output_tokens"`
				} `json:"usage"`
			} `json:"response"`
			Usage struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
				InputTokens      int64 `json:"input_tokens"`
				OutputTokens     int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		if ev.Model != "" {
			model = ev.Model
		} else if ev.Response.Model != "" {
			model = ev.Response.Model
		}
		in += ev.Usage.PromptTokens + ev.Usage.InputTokens + ev.Response.Usage.InputTokens
		out += ev.Usage.CompletionTokens + ev.Usage.OutputTokens + ev.Response.Usage.OutputTokens
	}
	return
}

// parseClaudeResponse handles both JSON (non-streaming) and SSE
// (streaming) Anthropic /v1/messages responses. Returns model + total
// input/output tokens.
func parseClaudeResponse(body []byte) (model string, in, out int64) {
	// non-streaming JSON
	var jr struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && jr.Model != "" {
		in = jr.Usage.InputTokens + jr.Usage.CacheCreationInputTokens + jr.Usage.CacheReadInputTokens
		out = jr.Usage.OutputTokens
		return jr.Model, in, out
	}
	// SSE: walk lines, parse data: payloads
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Message struct {
				Model string `json:"model"`
				Usage struct {
					InputTokens              int64 `json:"input_tokens"`
					CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
					CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens             int64 `json:"output_tokens"`
				InputTokens              int64 `json:"input_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		if ev.Type == "message_start" && ev.Message.Model != "" {
			model = ev.Message.Model
			in = ev.Message.Usage.InputTokens + ev.Message.Usage.CacheCreationInputTokens + ev.Message.Usage.CacheReadInputTokens
		}
		if ev.Type == "message_delta" {
			out += ev.Usage.OutputTokens
		}
	}
	return
}

type claudeReqInfo struct {
	Model     string
	SessionID string
	Title     string
}

// parseClaudeRequest extracts Claude session metadata + first real user
// message (stripped of system-reminder hook noise) from an Anthropic
// /v1/messages POST body.
func parseClaudeRequest(body []byte) claudeReqInfo {
	var req struct {
		Model    string `json:"model"`
		Metadata struct {
			UserID         string `json:"user_id"`
			SessionID      string `json:"session_id"`
			ConversationID string `json:"conversation_id"`
		} `json:"metadata"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return claudeReqInfo{}
	}
	out := claudeReqInfo{Model: req.Model}
	// Claude Code packs the real session_id inside metadata.user_id as
	// an escaped JSON string: "{\"device_id\":\"...\",\"session_id\":\"<uuid>\"}".
	// Prefer the inner session_id since it's stable across restarts of
	// a single CLI session; fall back to the wrapper hash otherwise.
	innerSession := ""
	if req.Metadata.UserID != "" && strings.HasPrefix(req.Metadata.UserID, "{") {
		var inner struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal([]byte(req.Metadata.UserID), &inner) == nil {
			innerSession = inner.SessionID
		}
	}
	switch {
	case req.Metadata.SessionID != "":
		out.SessionID = "s_" + shortHash(req.Metadata.SessionID)
	case req.Metadata.ConversationID != "":
		out.SessionID = "c_" + shortHash(req.Metadata.ConversationID)
	case innerSession != "":
		out.SessionID = "s_" + shortHash(innerSession)
	case req.Metadata.UserID != "":
		out.SessionID = "u_" + shortHash(req.Metadata.UserID)
	}
	// Title heuristic: take FIRST user message. Skip known probe payloads
	// Claude Code sends to check quota/health (those would otherwise
	// overwrite a real title since recordLLMUsage locks title once set).
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		clean := stripSystemReminders(messageText(m.Content))
		if clean == "" {
			continue
		}
		if isClaudeProbeMessage(clean) {
			break
		}
		out.Title = truncate(clean, 80)
		break
	}
	return out
}

// isClaudeProbeMessage matches single-token health / quota / capability
// probes Claude Code sends (e.g., "quota"). Real prompts like "Hello"
// or "Hi" are NOT probes — we want them as titles.
func isClaudeProbeMessage(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quota", "ping", "health":
		return true
	}
	return false
}

// messageText concatenates all text from a Claude message Content
// (which is either a string or an array of typed blocks). Joining is
// required because Claude Code packs <system-reminder> blocks and the
// actual user prompt as SEPARATE text blocks; returning only the
// first one yields the reminder, which then gets stripped to empty.
func messageText(c json.RawMessage) string {
	var s string
	if err := json.Unmarshal(c, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(c, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

// stripSystemReminders removes <system-reminder>...</system-reminder>
// blocks (Claude Code injects these via hooks) and returns trimmed text.
func stripSystemReminders(s string) string {
	return stripXMLBlocks(s, "system-reminder")
}

// stripXMLBlocks removes all <tag>...</tag> blocks from s. Used to peel
// off agent-injected wrappers (system-reminder for Claude Code,
// environment_context / user_instructions for Codex CLI) so we can
// surface the human-typed prompt as the session title.
func stripXMLBlocks(s string, tags ...string) string {
	for _, tag := range tags {
		open := "<" + tag + ">"
		closing := "</" + tag + ">"
		for {
			i := strings.Index(s, open)
			if i < 0 {
				break
			}
			j := strings.Index(s[i:], closing)
			if j < 0 {
				s = s[:i]
				break
			}
			s = s[:i] + s[i+j+len(closing):]
		}
	}
	return strings.TrimSpace(s)
}

func openaiFirstUserMessage(body []byte) string {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			return truncate(s, 80)
		}
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			for _, b := range blocks {
				if b.Text != "" {
					return truncate(b.Text, 80)
				}
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (g *Gateway) handle(raw net.Conn, dstIP string, dstPort uint16) {
	defer func() { _ = raw.Close() }()
	defer otelTrackConn("https_mitm")()
	host, prefix, err := peekSNI(raw)
	if err != nil {
		// No SNI — fall back to direct-IP endpoint lookup for kubernetes/https
		// endpoints whose `server` field is an IP literal (kubectl connects
		// by IP and never sends SNI).
		if dstIP != "" {
			c := wrapPeek(raw, prefix)
			if g.isInternalVIP(dstIP) {
				// Fixed-IP fallback for `curl https://<internal-vip>/`
				// when DNS interception isn't active — no SNI on an IP
				// literal, so the dst VIP is the only signal.
				g.serveInternal(c, dstIP)
				return
			}
			pip := peerIP(c)
			profile := g.profileFor(pip)
			ep, authority, certHost := g.httpsMITMEndpoint(profile, dstIP, dstPort)
			if ep != nil && isHTTPSMITMFamily(ep.Family) {
				log.Printf("sni-fallback: %s → %s", authority, ep.Name)
				g.mitmHTTPSWithCertHost(c, authority, certHost, ep)
				return
			}
		}
		log.Printf("sni: %v", err)
		return
	}
	c := wrapPeek(raw, prefix)
	log.Printf("sni-peek: %s", host)
	if isInternalHost(host) {
		// Reserved internal API name: serve the caller's profile
		// manifest (and CA/info) locally and never proxy upstream.
		g.serveInternal(c, internalHostname)
		return
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	ep, authority, certHost := g.httpsMITMEndpoint(profile, host, dstPort)
	if ep == nil {
		if policy := g.Policy(); policy != nil && policy.UnknownHost == "deny" {
			log.Printf("sni: %s: unknown host denied", host)
			return
		}
		g.splice(c, host)
		return
	}
	if isHTTPSMITMFamily(ep.Family) {
		// Every facet whose Transport() is "https-mitm" — https and
		// k8s today, future plugins tomorrow — terminates TLS here
		// and runs the request loop through mitmHTTPS. The facet's
		// PrepareRequest hook derives any per-family metadata
		// (URL → Meta for k8s) before the matcher walks.
		g.mitmHTTPSWithCertHost(c, authority, certHost, ep)
		return
	}
	// External plugin endpoints that terminate TLS themselves (e.g. an
	// `aws_api` bound to `*.amazonaws.com`) pump the raw agent conn to
	// the subprocess over gRPC, so they aren't an https-mitm facet.
	// They're matched here purely by SNI: the agent resolves and dials
	// the real upstream IP and the forwarder intercepts :443
	// promiscuously, so no VIP or conn-index entry is needed — which
	// matters for a wildcard host, since it has neither (it can't be
	// DNS-resolved to an IP for the conn-index, and an HTTPS plugin
	// isn't RequiresVIP). Gate on the plugin body's TLS-terminate
	// marker, not just ConnEndpointRuntime: built-in wire-protocol
	// runtimes (postgres / clickhouse / ssh) also satisfy that
	// interface but can't read a raw ClientHello, and route via
	// VIP/direct-IP rather than SNI-on-443.
	if tt, ok := ep.Body.(interface{ TLSTerminates() bool }); ok && tt.TLSTerminates() {
		log.Printf("sni-conn: %s → %s", host, ep.Name)
		g.dispatchConnEndpoint(c, dstIP, dstPort, ep, host)
		return
	}
	// Wire-protocol families (postgres / clickhouse_* / future
	// native plugins) dispatch through their own port handlers,
	// not through SNI peek on 443. Anything that lands here is
	// either an unknown family or a family without an HTTPS
	// transport — splice through.
	log.Printf("endpoint %s family %q: no https-mitm transport; passthrough", ep.Name, ep.Family)
	g.splice(c, host)
}

func (g *Gateway) shouldHandleHTTPSMITM(c net.Conn, dstIP string, dstPort uint16) bool {
	if dstPort == 443 {
		return true
	}
	if dstIP == "" || dstPort == 0 {
		return false
	}
	profile := g.profileFor(peerIP(c))
	ep, _, _ := g.httpsMITMEndpoint(profile, dstIP, dstPort)
	return ep != nil && isHTTPSMITMFamily(ep.Family)
}

func (g *Gateway) httpsMITMEndpoint(profile, host string, dstPort uint16) (*config.CompiledEndpoint, string, string) {
	policy := g.Policy()
	exact := runtime.HostEndpoint(policy, profile, host)
	if exact != nil && isHTTPSMITMFamily(exact.Family) {
		return exact, host, host
	}
	if host != "" && dstPort != 0 {
		authority := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))
		if ep := runtime.HostEndpoint(policy, profile, authority); ep != nil {
			return ep, authority, host
		}
	}
	if exact != nil {
		return exact, host, host
	}
	return nil, host, host
}

// isHTTPSMITMFamily reports whether the facet registered for family
// drives its wire through the HTTPS MITM handler. Replaces what used
// to be a hardcoded `case "http", "k8s"` so new HTTPS-shaped
// protocol facets (e.g. a future "openai" or "anthropic" family that
// wants per-family report fields beyond what http_rule offers) drop
// in without touching the dispatch switch.
func isHTTPSMITMFamily(family string) bool {
	if family == "" {
		return false
	}
	f := facet.Lookup(family)
	return f != nil && f.Transport() == "https-mitm"
}

// handlePostgresConn dispatches an inbound 5432 connection to the
// postgres endpoint runtime. The dstIP comes from the WG forwarder —
// agents resolve real RDS hostnames via public DNS and the gateway
// intercepts at L3, so dstIP is the upstream RDS / postgres server
// address. The endpoint is selected from the device's profile via
// dnsvip (tunneled endpoints) or ConnIndex (non-tunneled, dst-IP
// indexed). An unclaimed dst — no endpoint declares this host — is
// relayed verbatim so the connection fails on the real network
// rather than being silently routed to an unrelated postgres.
func (g *Gateway) handlePostgresConn(c net.Conn, dstIP string) {
	defer func() { _ = c.Close() }()
	defer otelTrackConn("pg_relay")()
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)

	policy := g.Policy()
	// Dispatch order:
	//
	//   1. dnsvip.LookupVIP — tunneled endpoints reach upstream via
	//      a synthetic hostname routed through a VIP, and conn-index
	//      intentionally skips them (would double-route past the
	//      tunnel).
	//   2. ConnIndex — non-tunneled endpoints indexed by DNS-resolved
	//      upstream IP. Filtered by profile so writer / readonly
	//      pointing at one RDS still picks the right one.
	//
	// No third "pick any postgres endpoint" fallback: an unclaimed
	// dst means no endpoint declares this host, and guessing routes
	// the connection to an unrelated database (e.g. an RDS hostname
	// silently terminating on a Cloud SQL tunnel).
	var ep *config.CompiledEndpoint
	var hostname string
	if g.dnsvip != nil {
		if hn, hits := g.dnsvip.LookupVIP(dstIP); len(hits) > 0 {
			hostname = hn
			cand := make([]*config.CompiledEndpoint, 0, len(hits))
			for _, h := range hits {
				if h.Endpoint != nil {
					cand = append(cand, h.Endpoint)
				}
			}
			ep = pickEndpointForProfile(cand, policy, profile)
		}
	}
	if ep == nil {
		if idx := g.connIdx.Load(); idx != nil {
			candidates := idx.Lookup(dstIP)
			ep = pickEndpointForProfile(candidates, policy, profile)
		}
	}
	if ep == nil {
		// No endpoint claims dstIP → relay verbatim. Closes when
		// either side hangs up.
		log.Printf("pg %s: no postgres endpoint in profile %q; relaying", dstIP, profile)
		g.wgRelay(c, dstIP, 5432)
		return
	}

	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		log.Printf("pg endpoint %q plugin lacks ConnEndpointRuntime", ep.Name)
		return
	}

	upstreamAddr := dstIP + ":5432"
	// Event Host carries the agent-dialed hostname when the dst is a
	// dnsvip VIP (tunneled endpoint), else the raw dst IP. Without
	// this the dashboard shows the synthetic VIP (e.g. fdXX::N) and
	// the operator can't tell which database the connection hits.
	eventHost := hostname
	if eventHost == "" {
		eventHost = dstIP
	}
	ch := &runtime.ConnHandle{
		Conn:     c,
		Endpoint: ep,
		Policy:   policy,
		Profile:  profile,
		PeerIP:   pip,
		Secrets:  g.secrets,
		Blobs:    g.blobs,
		DialUpstream: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Plugin asks for ep.Hosts[0]:port; we bypass DNS by
			// dialing the original upstream IP the WG forwarder
			// gave us. Plugin-supplied addr is ignored when it's
			// the endpoint's declared host (the common case).
			// dialThrough degrades to the direct dialer when ep
			// has no tunnel; this path is used by non-tunneled
			// postgres endpoints today (tunneled ones land in the
			// VIP dispatch path, not here).
			return g.dialThrough(ctx, ep, network, upstreamAddr)
		},
		Emit: func(ev runtime.ConnEvent) {
			if g.sink == nil {
				return
			}
			g.sink.Emit(Event{
				Mode: "pg", Family: ep.Family, Host: eventHost, AgentIP: agentPip,
				Method: ev.Verb, Path: ev.Summary,
				Action: ev.Action, Reason: ev.Reason,
				Facets:   ev.Facets,
				Endpoint: ep.Name, Rule: ev.Rule,
				Approver:     ev.Approver,
				ApproverType: ev.ApproverType,
				ApproverBy:   ev.ApproverBy,
			})
		},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			return g.runApproveChain(context.Background(), req.Stages, runApproveCtx{
				AgentIP: agentPip, Host: eventHost, Method: req.Verb, Path: req.Summary,
				Reason:   ifNotEmpty(req.Rule, func(r *config.CompiledRule) string { return r.Outcome.Reason }),
				Endpoint: ep, Rule: req.Rule, Profile: profile,
			})
		},
	}
	if err := connRT.HandleConn(context.Background(), ch); err != nil {
		log.Printf("pg %s: %v", dstIP, err)
	}
}

// handleVIPConn dispatches an inbound TCP connection whose dst IP
// falls in the dnsvip range. The VIP table maps the IP back to the
// hostname → endpoints that claimed a VIP at policy build; profile
// filter picks the one for this device. Today the only RequiresVIP
// plugin is "ssh", but the path is generic so future binary
// protocols (clickhouse_native with a hostname-keyed dispatch quirk,
// for instance) can plug in without a separate forwarder branch.
func (g *Gateway) handleVIPConn(c net.Conn, dstIP string, dstPort uint16) {
	defer otelTrackConn("vip_conn")()

	hostname, hits := g.dnsvip.LookupVIP(dstIP)
	if hostname == "" || len(hits) == 0 {
		log.Printf("vip %s:%d: VIP allocated but no endpoint binding (stale?); dropping", dstIP, dstPort)
		_ = c.Close()
		return
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	policy := g.Policy()
	// Profile-filter the hits, then port-match. Port match handles
	// the case where one hostname is bound to multiple endpoints on
	// different ports (rare but legal).
	var ep *config.CompiledEndpoint
	var matchedPort uint16
	for _, h := range hits {
		if h.Endpoint == nil {
			continue
		}
		if profile != "" {
			if prof, ok := policy.Profiles[profile]; ok {
				if _, in := prof.Endpoints[h.Endpoint.Name]; !in {
					continue
				}
			}
		}
		if dstPort != 0 && h.Port != 0 && dstPort != h.Port {
			continue
		}
		ep = h.Endpoint
		matchedPort = h.Port
		break
	}
	if ep == nil {
		log.Printf("vip %s:%d (host %q): no endpoint matches profile %q + port", dstIP, dstPort, hostname, profile)
		_ = c.Close()
		return
	}
	g.dispatchConnEndpoint(c, dstIP, matchedPort, ep, hostname)
}

// tryDirectIPConn is the post-VIP fallback that dispatches inbound
// connections to ConnEndpointRuntime plugins whose endpoint hosts are
// IP literals (or hostnames whose resolved IP happens to land in the
// conn-index). Returns true when a matching endpoint claimed the
// connection so the caller skips wgRelay.
//
// Mirrors handlePostgresConn's index-then-dispatch pattern, but
// generalised: any endpoint whose body implements ConnRouter +
// whose plugin Runtime satisfies ConnEndpointRuntime is eligible.
// The clickhouse_native plugin uses this path when an operator binds
// it to bare-IP hosts (`hosts = ["172.17.0.1"]`) — those entries are
// skipped by dnsvip (no DNS query to intercept) so direct-IP dispatch
// is the only way they reach the plugin. profile filter prevents one
// device from punching into another profile's endpoint by IP.
func (g *Gateway) tryDirectIPConn(c net.Conn, dstIP string, dstPort uint16) bool {
	idx := g.connIdx.Load()
	if idx == nil {
		return false
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	policy := g.Policy()
	candidates := idx.Lookup(dstIP)
	ep := pickEndpointForProfile(candidates, policy, profile)
	if ep == nil {
		return false
	}
	if _, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime); !ok {
		return false
	}
	g.dispatchConnEndpoint(c, dstIP, dstPort, ep, "")
	return true
}

// dispatchConnEndpoint hands one accepted conn to the endpoint's
// ConnEndpointRuntime. Shared between handleVIPConn and
// tryDirectIPConn; hostname is the agent-dialed name (set by the VIP
// path, empty for direct-IP). Closes c on a runtime-mismatch fail
// path; otherwise the plugin owns the conn lifetime.
func (g *Gateway) dispatchConnEndpoint(c net.Conn, dstIP string, dstPort uint16, ep *config.CompiledEndpoint, hostname string) {
	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		log.Printf("conn dispatch: endpoint %q plugin lacks ConnEndpointRuntime", ep.Name)
		_ = c.Close()
		return
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)
	policy := g.Policy()
	mode := ep.Plugin.Type
	// Event Host carries the hostname when known (VIP path), else the
	// dst IP — keeps the dashboard's "where is this traffic going"
	// column populated for both dispatch shapes.
	eventHost := hostname
	if eventHost == "" {
		eventHost = dstIP
	}
	ch := &runtime.ConnHandle{
		Conn:         c,
		Endpoint:     ep,
		Policy:       policy,
		Profile:      profile,
		PeerIP:       pip,
		Secrets:      g.secrets,
		Blobs:        g.blobs,
		StateDir:     g.stateDir,
		DstPort:      dstPort,
		UpstreamHost: hostname,
		MintCert: func(host string) (*tls.Certificate, error) {
			return g.certs.mint(host)
		},
		DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Plugin passes the *real* upstream host:port — the
			// gateway's host network resolves it (the VIP only
			// exists inside the WG netstack; direct-IP dispatch
			// already has the real IP). When the endpoint declares
			// a tunnel, dialThrough routes the dial through the
			// TunnelManager; otherwise it falls back to the
			// gateway's direct dialer.
			if addr == "" {
				return nil, fmt.Errorf("conn dispatch: plugin gave empty upstream addr")
			}
			return g.dialThrough(ctx, ep, network, addr)
		},
		DialUpstreamTLS: func(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
			if addr == "" {
				return nil, fmt.Errorf("conn dispatch: plugin gave empty upstream addr")
			}
			return g.dialUpstream(ctx, network, addr, serverName, ep, profile)
		},
		BodyStorageCap: g.cfg.Load().BodyStorageLimit(),
		Emit: func(ev runtime.ConnEvent) {
			if g.sink == nil {
				return
			}
			g.sink.Emit(Event{
				Mode: mode, Family: ep.Family, Host: eventHost, AgentIP: agentPip,
				ID: ev.ID, Phase: ev.Phase, Status: ev.Status,
				Method: ev.Verb, Path: ev.Summary,
				Action: ev.Action, Reason: ev.Reason,
				Facets:   ev.Facets,
				Endpoint: ep.Name, Rule: ev.Rule,
				Approver:     ev.Approver,
				ApproverType: ev.ApproverType,
				ApproverBy:   ev.ApproverBy,
				RespBody:     ev.RespBody,
				RespSha:      ev.RespSha,
			})
		},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			return g.runApproveChain(context.Background(), req.Stages, runApproveCtx{
				AgentIP: agentPip, Host: eventHost, Method: req.Verb, Path: req.Summary,
				Reason:   ifNotEmpty(req.Rule, func(r *config.CompiledRule) string { return r.Outcome.Reason }),
				Endpoint: ep, Rule: req.Rule, Profile: profile,
			})
		},
	}
	// Cancel on return so a pump goroutine still parked on the plugin
	// stream (e.g. blocked in Send after the other direction finished)
	// unblocks and the gRPC stream tears down instead of leaking.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := connRT.HandleConn(ctx, ch); err != nil {
		if hostname != "" {
			log.Printf("%s vip %s (%s): %v", mode, dstIP, hostname, err)
		} else {
			log.Printf("%s direct %s:%d: %v", mode, dstIP, dstPort, err)
		}
	}
}

// handleDNSTCPConn dispatches an inbound TCP/53 flow to the dnsvip
// allocator's TCP serving loop. The udpDispatch closure handles the
// UDP variant; this is its TCP twin so DNS-over-TCP queries (large
// answers, axfr-style retries, or simply `dig +tcp`) keep working.
func (g *Gateway) handleDNSTCPConn(c net.Conn, dstIP string) {
	defer otelTrackConn("dns_tcp")()
	if dstIP == g.tailscaleIP {
		// Avoid self-relay loop: relayUpstream would dial ourselves.
		dstIP = ""
	}
	g.dnsvip.ServeTCP(c, dstIP)
}

// pickEndpointForProfile takes ConnIndex.Lookup candidates and returns
// the one whose name belongs to the device's profile. Returns nil when
// none of them do — caller should refuse the connection rather than
// silently route through an endpoint the device isn't supposed to
// touch. Single-tenant configs (no profile bound) fall through to
// the first candidate.
func pickEndpointForProfile(candidates []*config.CompiledEndpoint, policy *config.CompiledPolicy, profile string) *config.CompiledEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	if policy == nil || profile == "" {
		return candidates[0]
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return candidates[0]
	}
	for _, c := range candidates {
		if _, in := prof.Endpoints[c.Name]; in {
			return c
		}
	}
	return nil
}

func (g *Gateway) splice(c net.Conn, host string) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		log.Printf("dial %s: %v", host, err)
		g.emit(Event{Mode: "splice", Host: host, AgentIP: g.onboard.AgentIPFor(peerIP(c)), Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer func() { _ = up.Close() }()
	agentAddr := g.onboard.AgentIPFor(peerIP(c)) // capture BEFORE pipe — RemoteAddr() goes nil once netstack closes the conn
	in, out := pipeProgress(c, up, g.streamTracker(agentAddr, host))
	g.emit(Event{Mode: "splice", Host: host, AgentIP: agentAddr, Action: "allow", In: in, Out: out, Ms: time.Since(start).Milliseconds()})
}

// serveTSNetDirect handles a direct (non-PROXY) TLS connection in tsnet mode.
// These come from admins opening the dashboard, clawpatrol join, etc. We
// terminate TLS using our CA (minting a cert for whatever SNI the client
// sends) and then serve the dashboard HTTP mux over the decrypted connection.
func (g *Gateway) serveTSNetDirect(c net.Conn, mux http.Handler) {
	defer func() { _ = c.Close() }()
	host, prefix, err := peekSNI(c)
	conn := wrapPeek(c, prefix)
	if err != nil {
		// No SNI — client connected via IP literal (common during `clawpatrol join`
		// before the CA is trusted). Fall back to the server-side IP so mint() can
		// produce a cert with an IP SAN that Go's TLS stack will accept.
		if local := c.LocalAddr().String(); local != "" {
			if h, _, splitErr := net.SplitHostPort(local); splitErr == nil {
				host = h
			}
		}
		if host == "" {
			log.Printf("tsnet-direct: sni: %v (no fallback)", err)
			return
		}
	}
	cert, err := g.certs.mint(host)
	if err != nil {
		log.Printf("tsnet-direct: mint %s: %v", host, err)
		return
	}
	tc := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("tsnet-direct: tls %s: %v", host, err)
		return
	}
	defer func() { _ = tc.Close() }()
	_ = http.Serve(&oneShotListener{c: tc}, mux)
}

// serveTsnetDNSUDP pumps UDP/53 datagrams from the tsnet listener
// through dnsvip.HandlePacket. Used for whole-machine exit-node
// clients so the gateway allocates VIPs for intercepted hostnames
// before the client's TCP follow-up arrives. dstIP is always "" —
// the gateway IS the resolver on this path, so non-VIP A/AAAA fall
// through to synthIPResponse and other types hit relayUpstream's
// SERVFAIL guard (no self-relay loop).
func serveTsnetDNSUDP(pc net.PacketConn, vip *dnsvip.Allocator) {
	defer func() { _ = pc.Close() }()
	buf := make([]byte, 4<<10)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := vip.HandlePacket(buf[:n], "")
		if resp == nil {
			continue
		}
		_, _ = pc.WriteTo(resp, src)
	}
}

func pipeProgress(a, b net.Conn, onTick func(rx, tx int64)) (rx, tx int64) {
	var rxC, txC atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 256<<10)
		_, _ = io.CopyBuffer(&countWriter{Writer: b, n: &txC}, a, buf)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 256<<10)
		_, _ = io.CopyBuffer(&countWriter{Writer: a, n: &rxC}, b, buf)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	stop := make(chan struct{})
	if onTick != nil {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					onTick(rxC.Load(), txC.Load())
				}
			}
		}()
	}
	<-done
	<-done
	close(stop)
	return rxC.Load(), txC.Load()
}

// countWriter wraps an io.Writer and atomically tallies bytes written
// so a concurrent ticker can read in-flight progress.
type countWriter struct {
	io.Writer
	n *atomic.Int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.n.Add(int64(n))
	}
	return n, err
}

// maxHTTPMatchBody is the default rules-engine body cap. The live cap
// comes from gateway.limits.body_buffer (config.BodyBufferLimit); this
// constant remains the fallback and matches that field's default.
const maxHTTPMatchBody = int(config.DefaultBodyBufferLimit)

func bufferHTTPBodyForMatch(req *http.Request, capBytes int) []byte {
	b, _ := bufferHTTPBodyForMatchTruncated(req, capBytes)
	return b
}

// bufferHTTPBodyForMatchTruncated is bufferHTTPBodyForMatch with the
// overflow signal exposed: it reads one byte past the cap to detect
// truncation, then re-attaches whatever it pulled (cap + 1 byte) in
// front of the original stream so upstream still receives the body
// byte-for-byte. truncated is true iff the body extended beyond
// maxHTTPMatchBody; callers stash this on match.Request.Truncated so
// http.body / http.body_json become CEL unknowns and rules whose
// outcome depends on them fail-close.
func bufferHTTPBodyForMatchTruncated(req *http.Request, capBytes int) (body []byte, truncated bool) {
	if req.Body == nil {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, int64(capBytes)+1))
	if err != nil {
		return nil, false
	}
	if len(b) > capBytes {
		// Pulled one byte past the cap — body is over-sized. Keep
		// the cap-sized prefix as the matcher's view; re-attach the
		// full read (including the probe byte) in front of the
		// remaining stream so the upstream forward stays byte-exact.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), req.Body))
		return b[:capBytes], true
	}
	// Body fit inside the cap (or was exactly cap bytes). Re-attach
	// what we read — req.Body may still hold bytes past it on a
	// chunked / unknown-length stream that just hadn't surfaced
	// before the ReadAll returned.
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), req.Body))
	return b, false
}

const maxMITMRequestReadLogHostBytes = 255

func sanitizeMITMRequestReadLogHost(host string) string {
	if len(host) > maxMITMRequestReadLogHostBytes {
		host = host[:maxMITMRequestReadLogHostBytes]
	}
	if host == "" {
		return "unknown"
	}
	b := []byte(host)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':', c == '[', c == ']':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

func mitmRequestReadErrorReason(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "incomplete_request"
	}
	if errors.Is(err, bufio.ErrBufferFull) {
		return "request_too_large"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network_error"
	}
	return "invalid_request"
}

func logMITMRequestReadError(host string, err error) {
	// net/http parser errors can embed the request line or malformed
	// header verbatim. Keep err out of the log and emit only a fixed
	// category derived from its type.
	log.Printf("mitm_request_read_error host=%q reason=%s", sanitizeMITMRequestReadLogHost(host), mitmRequestReadErrorReason(err))
}

// mitmHTTPS handles an SNI-matched TLS connection for an HTTPS-family
// endpoint (https, kubernetes). It mints a leaf cert, terminates TLS,
// then loops reading HTTP requests and dispatching each through the
// compiled policy: runtime.MatchRequest picks the rule, the rule's
// Outcome decides verdict / approve. Allowed requests forward upstream
// over plain TLS with credential injection applied by the credential
// plugin's HTTPCredentialRuntime / HTTPRequestSigner / WebSocket hooks.
func (g *Gateway) mitmHTTPS(c net.Conn, host string, ep *config.CompiledEndpoint) {
	g.mitmHTTPSWithCertHost(c, host, host, ep)
}

func (g *Gateway) mitmHTTPSWithCertHost(c net.Conn, host, certHost string, ep *config.CompiledEndpoint) {
	agentAddr := peerIP(c)
	profile := g.profileFor(agentAddr)
	agentAddr = g.agentIPFor(c)
	if certHost == "" {
		certHost = host
	}
	cert, err := g.certs.mint(certHost)
	if err != nil {
		log.Printf("mint %s: %v", certHost, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("mitm tls handshake %s: %v", host, err)
		return
	}
	defer func() { _ = tc.Close() }()

	// transport is shared across all requests for this endpoint.
	// Old path allocated a fresh http.Transport per mitmHTTPS call,
	// which threw away the idle-conn pool and racked up ~10KB of
	// internal map allocations per request. Per-endpoint cache lets
	// repeat requests to the same upstream reuse keep-alives.
	transport := g.transportFor(ep)

	br := bufio.NewReader(tc)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logMITMRequestReadError(host, err)
			}
			return
		}
		_ = tc.SetReadDeadline(time.Time{})

		start := time.Now()
		pip := peerIP(c)

		// Body buffering. Any rule with a `body_json` or
		// `body_contains` match facet needs the body up-front; we
		// don't know which yet, so for any POST/PUT/PATCH with a
		// body we read up to 1 MiB and re-attach. Retry-grant
		// requests additionally buffer regardless of method: the
		// one-shot grant fingerprint is a same-request check, so a
		// body-bearing DELETE/GET must bind the exact bytes that will
		// continue to upstream. Reads beyond 1 MiB stream through
		// unbuffered (rare for agent traffic) but surface as
		// Truncated=true so the dispatcher/retry relay can fail-close
		// any path that needed the complete body.
		var matchBody []byte
		var truncated bool
		retryOperationID := strings.TrimSpace(req.Header.Get(hitlRetryOperationHeader))
		if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" || retryOperationID != "" {
			matchBody, truncated = bufferHTTPBodyForMatchTruncated(req, g.cfg.Load().BodyBufferLimit())
		}

		mreq := &match.Request{
			Family:    ep.Family,
			Method:    req.Method,
			URL:       req.URL,
			Headers:   req.Header,
			Body:      matchBody,
			PeerIP:    pip,
			Truncated: truncated,
		}
		// clickhouse_https carries the agent-declared database in
		// `?database=` or `X-ClickHouse-Database` (query wins). Other
		// HTTPS-family endpoints don't have a database concept; leave
		// mreq.Database empty for them.
		if ep.Plugin != nil && ep.Plugin.Type == "clickhouse_https" {
			mreq.Database = endpoints.ClickhouseHTTPSDatabaseFromRequest(req)
		}
		fac := facet.Lookup(ep.Family)
		if fac != nil {
			fac.PrepareRequest(mreq)
		}

		// Resolve the dispatching credential *before* matching so rules
		// carrying a `credential = bearer_token.X` pin can fire:
		// runtime.MatchRequest compares mreq.Credential (the bare
		// credential name) against each rule's pin. The wire-protocol
		// frontends (postgres/clickhouse) already resolve-then-match; the
		// HTTPS path historically matched first and resolved only at
		// injection time, leaving mreq.Credential empty — so every
		// credential-pinned rule silently fell through to the endpoint's
		// default rule. Resolve once here and reuse the entry for
		// credential injection further down.
		resolvedCred := runtime.ResolveCredential(g.Policy(), profile, ep, mreq)
		if resolvedCred != nil {
			mreq.Credential = resolvedCred.Credential.Symbol.Name
		}

		ev := Event{
			ID:     newReqID(),
			Mode:   "mitm",
			Family: ep.Family,
			Host:   host,
			Method: req.Method, Path: req.URL.Path,
			AgentIP:  agentAddr,
			Endpoint: ep.Name,
		}
		if fac != nil {
			ev.Facets = fac.Report(mreq)
		}
		// Emit start event so the dashboard renders the request as
		// in-flight immediately. The end event with the same ID
		// arrives when resp.Write finishes — long-poll / SSE / WS
		// requests no longer wait for connection close to surface.
		startEv := ev
		startEv.Phase = "start"
		startEv.Action = "in_flight"
		g.emit(startEv)

		cr := runtime.MatchRequest(ep, mreq)
		if cr != nil {
			ev.Rule = cr.Name
		}

		hitlRetryBypassedApproval := false
		var hitlRetryConsumedOperation *HITLOperation
		if retryOperationID != "" {
			principalID := hitlPeerPrincipalID(agentAddr)
			consumed, err := g.consumeHITLRetryGrantForRequest(req.Context(), hitlRetryRelayInput{
				OperationID: retryOperationID,
				ProfileID:   profile,
				PrincipalID: principalID,
				Endpoint:    ep,
				Rule:        cr,
				MatchReq:    mreq,
				HTTPRequest: req,
				RawBody:     matchBody,
				Truncated:   truncated,
			})
			if err != nil {
				status, contentType, body := hitlRetryRelayFailure(err)
				log.Printf("hitl retry rejected %s %s %s operation %q: %v", host, req.Method, req.URL.Path, retryOperationID, err)
				_, _ = fmt.Fprintf(tc, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), contentType, len(body), body)
				ev.Status = strconv.Itoa(status)
				ev.Action = "hitl_retry_rejected"
				ev.Reason = hitlRetryMismatchErrorValue
				if status == http.StatusNotFound {
					ev.Reason = hitlOperationNotFoundErrorValue
				}
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				return
			}
			hitlRetryConsumedOperation = &consumed
			hitlRetryBypassedApproval = true
			ev.Action = "hitl_retry_approved"
			log.Printf("hitl retry approved %s %s %s operation %q by %s", host, req.Method, req.URL.Path, retryOperationID, principalID)
		}

		// Approve chain — dispatch each stage to its approver
		// runtime (config/plugins/approvers). All stages must
		// allow; first deny short-circuits.
		var asyncOp HITLOperation
		var asyncSyncWait time.Duration
		if cr != nil && len(cr.Outcome.Approve) > 0 && !hitlRetryBypassedApproval {
			if approverID, asyncApprover, ok := g.asyncHumanApproverFor(cr.Outcome.Approve); ok {
				start, started, err := g.maybeStartAsyncHITLOperation(req.Context(), hitlAsyncOperationInput{
					ProfileID:   profile,
					PrincipalID: hitlPeerPrincipalID(agentAddr),
					Endpoint:    ep,
					Rule:        cr,
					ApproverID:  approverID,
					Approver:    asyncApprover,
					MatchReq:    mreq,
					HTTPRequest: req,
					RawBody:     matchBody,
					Truncated:   truncated,
					Now:         time.Now().UTC(),
				})
				if err != nil {
					log.Printf("hitl async operation start %s %s: %v", host, req.URL.Path, err)
				} else if started {
					asyncOp = start.Operation
					asyncSyncWait = start.SyncWaitTimeout
				}
			}
			v := g.runApproveChain(req.Context(), cr.Outcome.Approve, runApproveCtx{
				AgentIP: agentAddr, Host: host, Method: req.Method, Path: req.URL.RequestURI(),
				UA: req.Header.Get("User-Agent"), BodySample: string(matchBody), Reason: cr.Outcome.Reason,
				ThreadTS:      req.Header.Get("X-HITL-Thread-TS"),
				NotifyChannel: req.Header.Get("X-HITL-Channel"),
				Endpoint:      ep, Rule: cr, Profile: profile, Request: mreq,
				AsyncOperationID: asyncOp.ID, AsyncPendingOnSyncTimeout: asyncOp.ID != "", AsyncSyncWaitTimeout: asyncSyncWait,
			})
			if v.Decision != "allow" {
				if v.Decision == runtime.ApproveDecisionAsyncPending && asyncOp.ID != "" {
					updated, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStatePendingApproval, "")
					if err != nil {
						log.Printf("hitl async operation pending %s: %v", asyncOp.ID, err)
					} else {
						asyncOp = updated
					}
					_ = tc.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := writeHITLOperationAcceptedToConn(tc, asyncOp, g.cfg.Load().PublicURL()); err != nil {
						log.Printf("hitl async pending response write %s: %v", asyncOp.ID, err)
					}
					_ = tc.SetWriteDeadline(time.Time{})
					ev.Status = "202"
					ev.Action = "hitl_async_pending"
					ev.Approver = v.ApproverName
					ev.ApproverType = v.ApproverType
					ev.ApproverBy = v.By
					ev.Reason = v.Reason
					ev.Ms = time.Since(start).Milliseconds()
					g.emitEnd(ev)
					return
				}
				if asyncOp.ID != "" {
					if _, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateDenied, v.Reason); err != nil {
						log.Printf("hitl async operation deny %s: %v", asyncOp.ID, err)
					}
				}
				reason := v.Reason
				if reason == "" {
					reason = "denied by approver"
				}
				log.Printf("denied %s %s %s: %s (by %s/%s/%s)",
					host, req.Method, req.URL.Path, reason, v.ApproverType, v.ApproverName, v.By)
				_, _ = fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
				ev.Status = "403"
				ev.Action = "denied"
				ev.Approver = v.ApproverName
				ev.ApproverType = v.ApproverType
				ev.ApproverBy = v.By
				ev.Reason = reason
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				return
			}
			if asyncOp.ID != "" {
				if updated, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateExecutingUpstream, ""); err != nil {
					log.Printf("hitl async operation executing %s: %v", asyncOp.ID, err)
				} else {
					asyncOp = updated
				}
			}
			log.Printf("approved %s %s %s by %s/%s/%s",
				host, req.Method, req.URL.Path, v.ApproverType, v.ApproverName, v.By)
			ev.Action = "approved"
			ev.Approver = v.ApproverName
			ev.ApproverType = v.ApproverType
			ev.ApproverBy = v.By
		}

		// Verdict.
		if cr != nil && cr.Outcome.Verdict == "deny" {
			reason := cr.Outcome.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			log.Printf("deny %s %s %s: %s (rule %q)", host, req.Method, req.URL.Path, reason, cr.Name)
			if hitlRetryConsumedOperation != nil {
				if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamFailed, reason); err != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamFailed, err)
				}
			}
			_, _ = fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
			ev.Status = "403"
			ev.Action = "deny"
			ev.Reason = reason
			ev.Ms = time.Since(start).Milliseconds()
			g.emitEnd(ev)
			return
		}

		// Forward upstream. Hop-by-hop / proxy-leak headers stripped
		// per RFC 7230 §6.1 plus chatgpt.com / Cloudflare flagged set.
		// WS upgrade requests skip this strip block — Connection +
		// Upgrade are part of the handshake (codex hits chatgpt.com
		// /backend-api/codex/responses as a WS upgrade and the server
		// flags requests with Sec-Websocket-* but no Upgrade as
		// "Attack detected"). isWSUpgrade is checked again below to
		// route through handleWSUpgrade after credential injection.
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.Host = host
		req.RequestURI = ""
		req.Header.Del(hitlRetryOperationHeader)
		if !isWSUpgrade(req) {
			for _, h := range []string{
				"Connection", "Keep-Alive", "Proxy-Authenticate",
				"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
				"Cf-Worker", "Cf-Ray", "Cf-Ew-Via", "Cf-Connecting-Ip", "Cdn-Loop",
				"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Via",
				"X-HITL-Thread-TS",
				"X-HITL-Channel",
			} {
				req.Header.Del(h)
			}
		}

		// Endpoint-level synthetic-response hook. The endpoint
		// plugin's runtime can short-circuit specific paths and
		// return a clawpatrol-generated response without forwarding
		// upstream — used by openai_codex_https to serve the JWKS +
		// agent-task-register stubs that anchor codex's Agent
		// Identity flow on hosts we MITM. Endpoints without a
		// responder (the default https plugin) fall through.
		if responder, ok := ep.Plugin.Runtime.(runtime.HTTPSyntheticResponder); ok {
			if r, handled, err := responder.RespondHTTP(req.Context(), req); err != nil {
				log.Printf("respond %s: %v", ep.Name, err)
			} else if handled {
				if r.Body != nil {
					defer func() { _ = r.Body.Close() }()
				}
				ev.Status = strconv.Itoa(r.StatusCode)
				ev.Action = "synth"
				// Synthetic responses are clawpatrol-generated, so the
				// stock plugins don't set auth-bearing headers — but
				// the no-injected-credential-reaches-the-agent guarantee
				// shouldn't rely on plugin authors remembering that.
				// Strip the same list as the upstream-forwarded path
				// so a future plugin that mirrors response headers from
				// an upstream lookup can't accidentally leak them.
				stripAuthResponseHeaders(r.Header)
				stripAuthResponseHeaders(r.Trailer)
				stripAltSvc(r.Header)
				writeErr := r.Write(tc)
				if hitlRetryConsumedOperation != nil {
					toState := HITLOperationStateUpstreamSucceeded
					lastErr := ""
					if writeErr != nil {
						toState = HITLOperationStateUpstreamFailed
						lastErr = writeErr.Error()
					}
					if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, toState, lastErr); err != nil {
						log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, toState, err)
					}
				}
				if writeErr != nil {
					log.Printf("synth write %s %s: %v", host, req.URL.Path, writeErr)
				}
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				continue
			}
		}

		// Credential injection. Pick the credential entry that
		// applies to this request (singular binding short-circuits;
		// multi-credential dispatch asks the endpoint plugin's
		// PlaceholderDetector which placeholder the agent sent),
		// fetch the secret bytes from the configured store, and
		// hand both to the credential plugin's request-time runtime hooks
		// to stamp HTTP auth or rewrite server-bound WS token placeholders.
		// Schema-only credential types leave Runtime nil; we pass through
		// verbatim and rely on policy alone.
		var rewriteWSPayload wsPayloadRewriter
		var reqBodySecretRedactions []string
		if cc := resolvedCred; cc != nil {
			// Plugin.Runtime is a typed-nil sentinel used only for
			// interface-compliance assertions; the actual decoded HCL
			// values (BearerToken.IdempotencyKey, PostgresCredential.User,
			// etc.) live on Body. Invoke methods through Body so the
			// receiver is the real instance.
			injector, wantsHTTP := cc.Credential.Body.(runtime.HTTPCredentialRuntime)
			signer, wantsSign := cc.Credential.Body.(runtime.HTTPRequestSigner)
			wsRewriter, wantsWS := cc.Credential.Body.(runtime.WebSocketCredentialRuntime)
			if wantsHTTP || wantsSign || (wantsWS && isWSUpgrade(req)) {
				sec, err := g.secrets.Get(cc.Credential.Symbol.Name)
				if err != nil {
					log.Printf("secret %s: %v — forwarding without injection", cc.Credential.Symbol.Name, err)
				} else if len(sec.Bytes) == 0 && len(sec.Extras) == 0 {
					log.Printf("secret %s: not configured (set CLAWPATROL_SECRET_%s)", cc.Credential.Symbol.Name, secretEnvName(cc.Credential.Symbol.Name))
				} else {
					// SignHTTPRequest takes precedence over InjectHTTP:
					// signing schemes (SigV4) read the endpoint to
					// pick up service/region, span the whole request,
					// and replace any auth headers the agent stamped.
					// No built-in credential implements both, but the
					// branch is harmless if one ever does.
					switch {
					case wantsSign:
						reqBodySecretRedactions = appendCredentialSecretRedactions(reqBodySecretRedactions, sec)
						if err := signer.SignHTTPRequest(req.Context(), req, sec, ep.Body); err != nil {
							log.Printf("sign %s: %v", cc.Credential.Symbol.Name, err)
						}
					case wantsHTTP:
						reqBodySecretRedactions = appendCredentialSecretRedactions(reqBodySecretRedactions, sec)
						// Match existing request-signing behavior: an injection failure is logged,
						// then the request continues with the agent's placeholder. The upstream
						// service should reject that placeholder without exposing gateway secrets.
						//
						// Exception: a transform credential (one that rewrites the URL/body)
						// consumes the request body during injection, so on failure the request
						// is corrupted, not merely un-injected — fail closed instead of
						// forwarding a half-transformed request.
						if err := injector.InjectHTTP(req.Context(), req, sec); err != nil {
							if rw, ok := injector.(runtime.HTTPRequestRewriter); ok && rw.RewritesHTTPRequest() {
								log.Printf("transform %s: %v; failing closed", cc.Credential.Symbol.Name, err)
								_, _ = fmt.Fprintf(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
								ev.Status = "502"
								ev.Action = "error"
								ev.Reason = err.Error()
								ev.Ms = time.Since(start).Milliseconds()
								g.emitEnd(ev)
								return
							}
							log.Printf("inject %s: %v; forwarding without injection", cc.Credential.Symbol.Name, err)
						}
						if rp, ok := injector.(runtime.HTTPCredentialRedactionProvider); ok {
							for _, secret := range rp.ConsumeHTTPRedactions(req) {
								reqBodySecretRedactions = appendCredentialSecretRedaction(reqBodySecretRedactions, secret)
							}
						}
					}
					if wantsWS && isWSUpgrade(req) {
						wsSec := sec
						rewriteWSPayload = func(payload []byte) ([]byte, bool, error) {
							return wsRewriter.RewriteWebSocketPayload(req.Context(), payload, wsSec)
						}
					}
				}
			}
		}

		// WebSocket upgrade. http.Transport.RoundTrip mangles the
		// 101 response and Cloudflare's WAF rejects unexpectedly modified
		// frames, so we hand off to a raw byte bridge. Frames remain
		// byte-faithful unless the selected credential provides an explicit
		// WS token-placeholder rewriter (for example Discord Gateway
		// IDENTIFY). The handler runs until either side closes — when it
		// returns, the caller's request loop ends naturally.
		if isWSUpgrade(req) {
			log.Printf("ws-upgrade %s %s", host, req.URL.Path)
			ev.Action = "ws"
			// Frame-level observability: handleWSUpgrade emits one
			// frame event per WS message in either direction so the
			// dashboard can render them like pg queries instead of
			// surfacing a single "ws" row at session close. Carries
			// the same request ID as the upgrade so the dashboard
			// nests them under the parent row.
			frameEmit := func(direction string, sample string) {
				g.sink.Emit(Event{
					Ts:        time.Now().UTC(),
					ID:        ev.ID,
					Phase:     "frame",
					Mode:      "mitm",
					Host:      host,
					Method:    "WS",
					Path:      req.URL.Path,
					AgentIP:   ev.AgentIP,
					Frame:     sample,
					Direction: direction,
				})
			}
			g.handleWSUpgrade(tc, br, req, host, frameEmit, ep, profile, rewriteWSPayload)
			if hitlRetryConsumedOperation != nil {
				if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamSucceeded, ""); err != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamSucceeded, err)
				}
			}
			ev.Status = "101"
			ev.Ms = time.Since(start).Milliseconds()
			g.emitEnd(ev)
			return
		}

		trackKind := trackKindFor(host)
		var trackedReqBody []byte
		if trackKind != "" {
			trackedReqBody = bufferHTTPBodyForMatch(req, g.cfg.Load().BodyBufferLimit())
		}
		// Pre-create session from the request body so streaming SSE
		// responses (codex /backend-api/codex/responses, anthropic
		// /v1/messages with stream:true) surface in the dashboard at
		// turn-start, not at turn-end. trackLLMUsage below runs after
		// resp.Write completes — which for codex can be minutes. WS
		// reports per-frame; HTTP needs this kickoff so it doesn't lag.
		sessionHint := req.Header.Get("Session_id")
		if sessionHint == "" {
			sessionHint = req.Header.Get("Session-Id")
		}
		if trackKind != "" && len(trackedReqBody) > 0 && g.agents != nil {
			g.preCreateLLMSession(c, trackKind, req.URL.Path, trackedReqBody, sessionHint)
		}
		reqS := newSampler(g.cfg.Load().BodyStorageLimit())
		if req.Body != nil {
			req.Body = wrapBodySampler(req.Body, reqS)
		}

		rtStart := time.Now()
		resp, err := transport.RoundTrip(req.WithContext(context.WithValue(req.Context(), profileCtxKey{}, profile)))
		rtDur := time.Since(rtStart)
		if err != nil {
			if asyncOp.ID != "" {
				if _, trErr := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateUpstreamFailed, hitlAsyncFailureReason(err)); trErr != nil {
					log.Printf("hitl async operation upstream failed %s: %v", asyncOp.ID, trErr)
				}
			}
			log.Printf("mitm upstream %s %s: %v", host, req.URL.Path, err)
			if hitlRetryConsumedOperation != nil {
				if transitionErr := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamFailed, err.Error()); transitionErr != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamFailed, transitionErr)
				}
			}
			_, _ = fmt.Fprintf(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			ev.Status = "502"
			ev.Action = "error"
			ev.Reason = err.Error()
			ev.Ms = time.Since(start).Milliseconds()
			ev.ReqSha = reqS.sha()
			ev.ReqBody = redactCredentialSample(reqS.sample(req.Header.Get("Content-Encoding")), reqBodySecretRedactions)
			ev.In = reqS.n
			g.emitEnd(ev)
			return
		}
		var trackBuf *bytes.Buffer
		if trackKind != "" && resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			// Codex's /backend-api/codex/responses SSE responses come back
			// through Cloudflare with NO Content-Type header, so an empty ct
			// is treated as eligible too — otherwise the codex HTTP/SSE turn
			// is never buffered and trackLLMUsage (the GenAI span source)
			// never fires, while WS codex and Content-Type-bearing providers
			// (Anthropic) record fine. trackKind is only set for the LLM
			// hosts and trackLLMUsage re-gates on path, so this won't capture
			// unrelated traffic.
			if ct == "" || strings.Contains(ct, "json") || strings.Contains(ct, "event-stream") {
				trackBuf = &bytes.Buffer{}
				resp.Body = io.NopCloser(io.TeeReader(resp.Body, trackBuf))
			}
		}
		respS := newSampler(g.cfg.Load().BodyStorageLimit())
		resp.Body = wrapBodySampler(resp.Body, respS)
		// Close-delimited responses (no Content-Length, no Transfer-
		// Encoding) come from h2 upstreams that we forced to http/1.1
		// via ALPN — Go's transport leaves cl=-1 and te=[] in that
		// case. Without an explicit terminator, peers (curl, browsers)
		// idle until the conn closes, which the 60s ReadRequest
		// deadline then triggers — a ~60s perceived delay per request.
		// Re-frame as chunked so the peer sees a proper end-of-body.
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 && !resp.Close {
			resp.TransferEncoding = []string{"chunked"}
		}
		// Snapshot the upstream's response headers for the audit log
		// before stripping credential-bearing ones — the dashboard
		// still wants to show what the upstream actually sent.
		ev.RespHeaders = flatHeaders(resp.Header)
		stripAuthResponseHeadersPreservingBasicChallenge(resp.Header)
		stripAltSvc(resp.Header)
		// Trailers fall outside resp.Header — Go's http.Transport
		// surfaces them on resp.Trailer and http.Response.Write
		// emits them after the chunked body. RFC 9110 §6.5.1 bans
		// Set-Cookie / auth fields in trailers, but a hostile or
		// buggy upstream can still try it, so we strip the same
		// list off the trailer block before resp.Write streams it.
		stripAuthResponseHeaders(resp.Trailer)
		writeErr := resp.Write(tc)
		_ = rtDur
		_ = resp.Body.Close()
		if trackBuf != nil && g.agents != nil {
			body := trackBuf.Bytes()
			if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
				if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
					if d, err := io.ReadAll(zr); err == nil {
						body = d
					}
					_ = zr.Close()
				}
			}
			g.trackLLMUsage(c, trackKind, host, req.URL.Path, trackedReqBody, body, sessionHint, rtStart)
		}

		if hitlRetryConsumedOperation != nil {
			toState := HITLOperationStateUpstreamSucceeded
			lastErr := ""
			if writeErr != nil {
				toState = HITLOperationStateUpstreamFailed
				lastErr = writeErr.Error()
			}
			if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, toState, lastErr); err != nil {
				log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, toState, err)
			}
		}

		if ev.Action == "" {
			ev.Action = "allow"
		}
		if asyncOp.ID != "" {
			to := HITLOperationStateUpstreamSucceeded
			lastErr := ""
			if writeErr != nil {
				to = HITLOperationStateUpstreamFailed
				lastErr = hitlAsyncFailureReason(writeErr)
			}
			if _, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, to, lastErr); err != nil {
				log.Printf("hitl async operation upstream terminal %s: %v", asyncOp.ID, err)
			}
		}
		ev.Status = strconv.Itoa(resp.StatusCode)
		ev.ReqHeaders = flatHeadersRedacted(req.Header, reqBodySecretRedactions)
		ev.In = reqS.n
		ev.Out = respS.n
		ev.ReqSha = reqS.sha()
		ev.ReqBody = redactCredentialSample(reqS.sample(req.Header.Get("Content-Encoding")), reqBodySecretRedactions)
		ev.RespSha = respS.sha()
		ev.RespBody = respS.sample(resp.Header.Get("Content-Encoding"))
		ev.Ms = time.Since(start).Milliseconds()
		g.emitEnd(ev)
		if g.agents != nil && agentAddr != "" {
			g.agents.trackUA(agentAddr, host, req.UserAgent(), reqS.n, respS.n)
		}

		if writeErr != nil {
			log.Printf("mitm resp write %s: %v", host, writeErr)
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

// secretEnvName mirrors EnvSecretStore's lookup key derivation so log
// messages can hint at the exact var name an operator should set.
// Uppercase, hyphens → underscores.
func secretEnvName(credName string) string {
	return strings.ToUpper(strings.ReplaceAll(credName, "-", "_"))
}

// runApproveCtx is the context blob the dispatcher passes per stage —
// HITL prompt fields + the matching rule + the device's profile.
type runApproveCtx struct {
	AgentIP                   string
	Host                      string
	Method                    string
	Path                      string
	UA                        string
	BodySample                string
	Reason                    string
	ThreadTS                  string
	NotifyChannel             string
	Endpoint                  *config.CompiledEndpoint
	Rule                      *config.CompiledRule
	Profile                   string
	Request                   *match.Request
	AsyncOperationID          string
	AsyncPendingOnSyncTimeout bool
	AsyncSyncWaitTimeout      time.Duration
}

// runApproveChain dispatches each stage of an approve = [...] list to
// the matching approver entity's runtime. All-must-allow semantics —
// the first non-allow verdict short-circuits and is returned. Built-in
// `dashboard` is handled inline (no policy entity needed).
func (g *Gateway) runApproveChain(ctx context.Context, stages []config.ApproveStage, c runApproveCtx) runtime.ApproveVerdict {
	policy := g.Policy()
	for _, st := range stages {
		var ar runtime.ApproverRuntime
		approverType := ""
		if st.Name == "dashboard" {
			ar = approvers.DashboardApprover{}
			approverType = "dashboard"
		} else if policy != nil {
			if ent, ok := policy.Approvers[st.Name]; ok {
				if rt, ok := ent.Body.(runtime.ApproverRuntime); ok {
					ar = rt
				}
				if ent.Plugin != nil {
					approverType = ent.Plugin.Type
				}
			}
		}
		if ar == nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: "approver " + st.Name + " not found", By: "gateway", ApproverName: st.Name}
		}
		stageCtx := ctx
		var stageCancel context.CancelFunc = func() {}
		if c.AsyncPendingOnSyncTimeout && c.AsyncSyncWaitTimeout > 0 && c.AsyncOperationID != "" {
			// Per-stage timeout: scope to the iteration so cancels don't
			// accumulate via deferred-in-loop. A long approve chain
			// (rare but legal) previously held one CancelFunc on the
			// defer stack per stage; releasing each stage's context as
			// soon as the call returns keeps memory bounded.
			stageCtx, stageCancel = context.WithTimeout(ctx, c.AsyncSyncWaitTimeout)
		}
		req := runtime.ApproveRequest{
			Stage:                     st,
			Endpoint:                  c.Endpoint,
			Rule:                      c.Rule,
			Request:                   c.Request,
			ApproverName:              st.Name,
			AgentIP:                   c.AgentIP,
			Profile:                   c.Profile,
			Method:                    c.Method,
			Host:                      c.Host,
			Path:                      c.Path,
			UA:                        c.UA,
			BodySample:                c.BodySample,
			Reason:                    c.Reason,
			ThreadTS:                  c.ThreadTS,
			NotifyChannel:             c.NotifyChannel,
			AsyncOperationID:          c.AsyncOperationID,
			AsyncPendingOnSyncTimeout: c.AsyncPendingOnSyncTimeout,
			Pool:                      g.hitl,
			Secrets:                   g.secrets,
			DashboardURL:              g.cfg.Load().PublicURL(),
			Policy:                    policy,
			MessageUpdateSink:         g.recordHITLOperationMessageRef,
			PendingMessageUpdateSink:  g.hitl.RecordMessageRef,
		}
		v, err := ar.Approve(stageCtx, req)
		stageCancel()
		// Stamp the entity name + plugin type on every verdict so the
		// dispatcher labels its `approved` / `denied` events with the
		// deciding approver — runtimes don't have to remember.
		if v.ApproverName == "" {
			v.ApproverName = st.Name
		}
		if v.ApproverType == "" {
			v.ApproverType = approverType
		}
		if err != nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: err.Error(), By: "gateway", ApproverName: v.ApproverName, ApproverType: v.ApproverType}
		}
		if v.Decision != "allow" {
			if v.Decision == "" {
				v.Decision = "deny"
				if v.Reason == "" {
					v.Reason = "approver " + st.Name + " timed out"
				}
			}
			return v
		}
	}
	return runtime.ApproveVerdict{Decision: "allow"}
}

// ifNotEmpty returns f(v) when v != nil, else "".
func ifNotEmpty(r *config.CompiledRule, f func(*config.CompiledRule) string) string {
	if r == nil {
		return ""
	}
	return f(r)
}

func main() {
	// Must run before anything else: when this process is the
	// re-exec'd sandbox stage-1 child for an external plugin, Stage1
	// sets the sandbox up and execs the plugin binary in place.
	sandbox.Stage1()
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gateway":
		runGateway(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	case "run":
		runRun(os.Args[2:])
	case "daemon-internal":
		// internal: re-exec'd by `clawpatrol run` (Linux only) to host
		// the per-user tsnet daemon. Hidden from usage(); name carries
		// the -internal suffix so it doesn't read like a user-facing
		// command if it leaks into help text or shell history.
		runDaemon(os.Args[2:])
	case "relay-supervisor":
		// internal: re-exec'd by `clawpatrol run` to host the auto-expose
		// supervisor in the host netns. Hidden from usage.
		runRelaySupervisor(os.Args[2:])
	case "relay-worker":
		// internal: re-exec'd from inside the agent netns to host the
		// auto-expose worker. Hidden from usage.
		runRelayWorker(os.Args[2:])
	case "__run-privileged":
		// internal: re-exec'd via sudo by `clawpatrol run` on hosts with
		// passwordless sudo, to set up the netns as real root (so the
		// wrapped command can sudo). Hidden from usage.
		runRunPrivileged(os.Args[2:])
	case "env":
		runEnv(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "plugins":
		runPlugins(os.Args[2:])
	case "test":
		runTest(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version", "-v", "--version":
		printVersion()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
	}
}

func peerIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return canonicalPeerIP(host)
}

// canonicalPeerIP collapses a wg-side v6 source (fd77::<n>) into its
// v4 equivalent (<wg-subnet-prefix>.<n>) so the agent registry,
// onboard registry, and dashboard track one device per peer
// regardless of which IP family the inbound flow used. Non-wg
// addresses pass through unchanged.
func canonicalPeerIP(ip string) string {
	if !strings.Contains(ip, ":") {
		return ip
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return ip
	}
	b := a.As16()
	if b[0] != 0xfd || b[1] != 0x77 {
		return ip
	}
	last := b[15]
	// Use the configured wg subnet prefix to reconstruct the v4. Fall
	// back to 10.55.0.0/24 — same default the example config uses —
	// when nothing's loaded yet (early-boot).
	prefixV4 := defaultWGV4Prefix
	if globalWG != nil && globalWG.serverIP.Is4() {
		s := globalWG.serverIP.As4()
		prefixV4 = [3]byte{s[0], s[1], s[2]}
	}
	v4 := netip.AddrFrom4([4]byte{prefixV4[0], prefixV4[1], prefixV4[2], last})
	return v4.String()
}

// defaultWGV4Prefix matches the example config's wg_subnet_cidr
// (10.55.0.0/24). Lets canonicalPeerIP work before the WGServer is
// up.
var defaultWGV4Prefix = [3]byte{10, 55, 0}

func printVersion() {
	v := buildVersion
	if buildGitSHA != "" {
		v += " (" + buildGitSHA + ")"
	}
	fmt.Println("clawpatrol", v)
}

func usage() {
	fmt.Fprintln(os.Stderr, `clawpatrol — secret-injection MITM proxy for AI agents

usage:
  clawpatrol gateway <config.hcl>        run the gateway server
  clawpatrol join [flags] <gateway-url>  onboard this machine via wg device flow
                  --hostname NAME        device name to register (default: os.Hostname)
                  --profile NAME         suggest a profile for the approver
                  --whole-machine        bring up wg-quick (route all traffic)
                  --login                interactive tailnet login for gateways
                                         with no public URL (creds discarded
                                         once join completes)
  clawpatrol run -- <cmd> [args...]      route one process tree through gateway
  clawpatrol status                      report install + tunnel state
  clawpatrol uninstall                   remove local join state and tunnel config
  clawpatrol env                         print shell exports for sourcing
  clawpatrol validate <config.hcl>       parse + compile a config and exit
  clawpatrol test <config> <path>        replay action fixtures against a candidate policy
  clawpatrol plugins <cmd> <config.hcl>  install / update / lock / approve plugins
  clawpatrol version | -v | --version    print version and exit

Documentation: https://clawpatrol.dev/docs/`)
	os.Exit(2)
}

// gatewayHelp is shown for `clawpatrol gateway -h` and any wrong
// invocation. The example HCL + config-reference URL is the
// discoverability path for first-time users.
const gatewayHelp = `usage: clawpatrol gateway [flags] <config.hcl>

flags:
  --set-dashboard-password <pw>   upsert the dashboard root password from this
                                  value, then start (skips the first-run web
                                  flow). The password is stored bcrypt-hashed
                                  in clawpatrol.db.
  --reset-dashboard-password      delete the stored dashboard root password,
                                  then start. The next dashboard request will
                                  re-run first-run setup.

Start from the example config:
  https://github.com/denoland/clawpatrol/blob/main/examples/gateway.example.hcl

HCL reference:
  https://clawpatrol.dev/docs/config-reference`

// runGateway is the entry point for the `clawpatrol gateway` subcommand.
//
// Exit-site discipline:
//   - usage errors (bad/missing config path) use `os.Exit(2)` — the
//     flag package's convention for "invalid invocation".
//   - boot-time failures that leave the gateway in an unusable state
//     (config parse, state-dir create, DB open, CA load, sink init,
//     OAuth registry init, dnsvip init, onboard load, WG init,
//     listener bind) use `log.Fatalf` — there's no usable partial
//     state to recover into, and dragging the process forward only
//     hides the root cause in later errors.
//   - SIGINT / SIGTERM is the clean-exit path: installGatewayShutdown
//     flushes telemetry + closes the DB, then `os.Exit(0)`.
//
// The retained Fatal sites are deliberate; do not "clean them up" into
// `return err` without owning the new contract for what the caller is
// supposed to do with a half-initialized gateway.
func runGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	setDashboardPassword := fs.String("set-dashboard-password", "",
		"upsert the dashboard root password from this value, then continue starting (skips the first-run web flow)")
	resetDashboardPassword := fs.Bool("reset-dashboard-password", false,
		"delete the stored dashboard root password before starting (the next dashboard hit goes back to first-run)")
	seedHook := devSeedAttach(fs)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, gatewayHelp) }
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, gatewayHelp)
		os.Exit(2)
	}
	cfgPath := rest[0]

	startModelRefresh()
	pluginMgr := extplugin.New(log.Default())
	// Record approved plugin permissions in clawpatrol.lock.hcl beside
	// the config (committed to VCS); trust-on-first-use, fail closed on
	// escalation.
	pluginMgr.SetLockfile(extplugin.LockfilePathFor(cfgPath), false)
	// Verify the GitHub build-provenance attestation of any plugin
	// downloaded on a cache miss; a plugin with no attestation falls back
	// to the checksum + lockfile check with a warning.
	pluginMgr.VerifyProvenance(true)
	config.SetPluginLoader(pluginMgr)
	cfg, policy, err := loadConfig(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(os.Stderr, "config file %q does not exist.\n\n%s\n", cfgPath, gatewayHelp)
			os.Exit(2)
		}
		log.Fatalf("config: %v", err)
	}
	stateDir := resolveStateDir(cfg)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatalf("state dir: %v", err)
	}
	if err := checkDirWritable(stateDir); err != nil {
		log.Fatalf("state dir: cannot create files in state_dir %s as uid %d: %v\n      Fix: run the gateway as the user that owns it, `chown` it to that user, or set a writable state_dir in the gateway block of %s.", stateDir, os.Getuid(), err, cfgPath)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	if result, err := runHITLOperationStartupMaintenance(context.Background(), db); err != nil {
		log.Fatalf("hitl operation maintenance: %v", err)
	} else if result.PendingApprovalExpired != 0 || result.ApprovedRetryExpired != 0 || result.SyncWaitingRecovered != 0 || result.ExecutingRecovered != 0 || result.PurgedTerminal != 0 {
		log.Printf("hitl operation maintenance: expired pending=%d retry=%d recovered sync=%d executing=%d purged=%d", result.PendingApprovalExpired, result.ApprovedRetryExpired, result.SyncWaitingRecovered, result.ExecutingRecovered, result.PurgedTerminal)
	}
	warnIfStateLooselyPermissioned(stateDir)
	setDB(db)
	applyDashboardPasswordFlags(db, *setDashboardPassword, *resetDashboardPassword)
	if err := seedRBAC(db, cfg.Operators()); err != nil {
		log.Printf("rbac seed: %v", err)
	}
	logDashboardAuthState(db, cfg)
	blobs := newGatewayBlobStore(db)
	endpoints.SetBlobStore(blobs)
	// Back the external-plugin HostState service with the same sqlite blob
	// store. Wired after the first config load (the state dir it lives in
	// is part of that config); the service resolves the store lazily, so
	// plugins spawned during that load still get state from their runtime
	// callbacks (HandleConn/InjectHTTP/OpenTunnel/Dial). State is not
	// available during a plugin's Build callback on this first load — see
	// pluginsdk.State.
	pluginMgr.SetBlobStore(blobs)
	certs, err := loadOrMintCA(db)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	sink, err := NewSink(db, 4096)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	// OAuthRegistry seeds at boot from the policy via
	// registerOAuthCredentials below — credential plugins own credential
	// discovery, the registry just persists per-owner tokens + handles
	// refresh. gatewaySecretStore consults it for OAuth-flow credentials.
	oauthReg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	g := &Gateway{
		cfgPath:   cfgPath,
		stateDir:  stateDir,
		db:        db,
		certs:     certs,
		dialer:    newUpstreamDialer(cfg.Resolver()),
		sink:      sink,
		blobs:     blobs,
		pluginMgr: pluginMgr,
		oauth:     oauthReg,
		agents:    NewAgentRegistry(),
		hitl:      newHITLRegistry(sink),
		onboard:   newOnboardRegistry(),
	}
	g.cfg.Store(cfg)
	// A tunnel plugin opens its transport through the gateway's brokered
	// dial (HostTunnel.DialUpstream); when the tunnel has no `via` parent
	// the gateway dials it directly with its own upstream dialer.
	pluginMgr.SetTransportDialer(func(network, addr string) (net.Conn, error) {
		return g.dialer.Dial(network, addr)
	})
	if cfg.DashboardConfigWrites() {
		log.Printf("config: dashboard writes enabled (generated rules can be appended to gateway.hcl)")
	} else {
		log.Printf("config: read-only (the dashboard cannot edit gateway.hcl)")
	}
	g.secrets = newGatewaySecretStore(db, oauthReg)
	g.hitl.asyncGrantResolver = g.resolveAsyncHITLGrant
	g.hitl.pendingMessageUpdater = g.updatePendingHITLMessage
	g.tunnels = NewTunnelManager(g.secrets, stateDir)
	registerOAuthCredentials(oauthReg, policy)
	g.policy.Store(policy)
	g.connIdx.Store(runtime.BuildConnIndex(policy))
	g.tunnels.SetPolicy(context.Background(), policy)
	// Sweep tunnel pods orphaned by a previous daemon lifetime (a
	// SIGKILL / OOM / panic skips the SIGTERM-driven CloseAll). Runs in
	// the background so a slow or unreachable cluster can't stall
	// startup, and only here at boot — never on reload, when live
	// tunnels may own pods a sweep would wrongly delete.
	go g.tunnels.ReconcileOrphans(context.Background(), policy)
	// dnsvip is opt-in by policy: if no endpoint requires VIPs, the
	// allocator stays empty and ServeUDP / ServeTCP are never called
	// (no endpoint dispatches port-53 to them). Construct
	// unconditionally so reloads that *add* an SSH endpoint don't
	// have to re-init. Persists to <stateDir>/dnsvip.json so VIPs
	// survive restarts.
	dvip, err := dnsvip.New(db, dnsvip.DefaultCIDR4, dnsvip.DefaultCIDR6)
	if err != nil {
		log.Fatalf("dnsvip init: %v", err)
	}
	g.dnsvip = dvip
	if err := g.dnsvip.RebuildFromPolicy(policy); err != nil {
		log.Fatalf("dnsvip build: %v", err)
	}
	log.Printf("policy: %d endpoints across %d profiles", len(policy.Endpoints), len(policy.Profiles))
	go g.sweepDashboardSessions()
	go g.watchConfig(cfgPath)
	go g.watchPluginUpdates()
	if err := g.onboard.Load(db); err != nil {
		log.Fatalf("onboard load: %v", err)
	}
	g.agents.onboard = g.onboard
	// Seed agent entries for every persisted device so the dashboard
	// renders them on boot, before any traffic arrives. Without this,
	// devices disappear after every gateway restart and only reappear
	// on the next request from each peer.
	// Clean fd77:: ghost rows (WG) and fd7a:: ghost rows (Tailscale IPv6)
	// left by builds that upserted IPv6 peer addresses as separate device
	// IDs. Drop them on every boot — the v4 row carries the same metadata.
	if _, err := db.Exec("DELETE FROM devices WHERE id LIKE 'fd77:%' OR id LIKE 'fd7a:%'"); err != nil {
		log.Printf("gateway: prune ghost device rows: %v", err)
	}
	if err := seedAgentsFromDevices(db, g.agents); err != nil {
		log.Printf("gateway: seed agents from devices: %v", err)
	}

	// Sessions: rehydrate persisted rows + start the sweeper.
	//   session_keep — hard retention floor by last_at (default
	//                  720h / 30d, "0" / "off" disables sweep).
	// Sessions can revive on new activity at any time, so there's no
	// "closed" intermediate state — keep is the only knob.
	g.agents.LoadSessions(db)
	g.agents.startSessionSweeper(parseDurationOr(cfg.SessionKeep(), 10*time.Minute))

	// Actions log: the gateway's largest table (captured req/resp
	// bodies). A global default retention floor by ts_ns (default 720h /
	// 30d, "0" / "off" disables the default sweep), plus per-endpoint
	// `retention` overrides applied in sweepActions.
	g.startActionsSweeper(parseDurationOr(cfg.ActionsKeep(), 720*time.Hour))

	// HITL notifications fan-out via the approver runtimes
	// (config/plugins/approvers); the registry's Add hook emits
	// the SSE event for the dashboard.

	otelShutdown, err := StartOtel(g)
	if err != nil {
		log.Printf("otel: %v", err)
	}

	startTelemetry(g)

	// Graceful-shutdown handler. SIGINT / SIGTERM flushes telemetry
	// (so traces / metrics buffered in BatchSpanProcessor don't get
	// dropped at process exit) and closes the SQLite handle (so WAL
	// checkpointing finishes before the file descriptor goes away).
	// The listen loop below blocks runGateway, so the goroutine
	// terminates via os.Exit — preserves the daemon-style single-
	// exit-site discipline (the loop never returns).
	installGatewayShutdown(g, otelShutdown)

	seedHook.Run(context.Background(), g)

	dashListen := cfg.DashboardListen()
	if dashListen != "" {
		mux := newWebMux(g, cfg.Join(), cfg.PublicURL())
		go serveHTTPLogged("dashboard", dashListen, mux)
		log.Printf("dashboard: http://%s", dashListen)
	}
	go serveHTTPLogged("pprof", "127.0.0.1:6060", nil)
	go g.servePorts()

	// Embedded userspace WireGuard server. When the `wireguard {}`
	// block is present, the clawpatrol process becomes the WG endpoint
	// — peers established at onboard time route ALL traffic into our
	// netstack (AllowedIPs=0.0.0.0/0). The promiscuous forwarder
	// accepts SYNs to any dst IP/port:
	//   - 443    → MITM (g.handle does SNI peek + rule dispatch)
	//   - dash   → dashboard mux
	//   - else   → transparent relay to the real upstream
	// No /etc/hosts hack needed on clients — agents resolve real
	// hostnames via public DNS and the gateway intercepts at L3.
	if cfg.IsWireGuardEnabled() {
		wg, err := StartWGServer(cfg.Join())
		if err != nil {
			log.Fatalf("wireguard: %v", err)
		}
		setWGServer(wg)
		dashMux := newWebMux(g, cfg.Join(), cfg.PublicURL())
		dashPort := portOf(dashListen)
		tcpDispatch := func(c net.Conn, dstIP string, dstPort uint16) {
			log.Printf("wg-fwd: %s:%d", dstIP, dstPort)
			switch {
			case g.shouldHandleHTTPSMITM(c, dstIP, dstPort):
				g.handle(c, dstIP, dstPort)
			case dstPort == 5432:
				g.handlePostgresConn(c, dstIP)
			case dstPort == 53:
				g.handleDNSTCPConn(c, dstIP)
			case g.dnsvip.IsVIP(dstIP):
				// Any port on a VIP belongs to the SSH endpoint that
				// hostname maps to. Future RequiresVIP plugins can
				// branch on ep.Plugin.Type inside handleVIPConn.
				g.handleVIPConn(c, dstIP, dstPort)
			case dashPort != 0 && int(dstPort) == dashPort:
				_ = http.Serve(&oneShotListener{c: c}, dashMux)
			default:
				// Direct-IP dispatch via conn-index: catches
				// clickhouse_native and friends when the operator
				// binds them to IP-literal hosts (dnsvip skips
				// those — they don't need DNS interception). Falls
				// through to transparent relay when no endpoint
				// claims the dst.
				if g.tryDirectIPConn(c, dstIP, dstPort) {
					return
				}
				g.wgRelay(c, dstIP, int(dstPort))
			}
		}
		udpDispatch := func(c net.Conn, dstIP string, dstPort uint16) bool {
			if dstPort == 53 {
				g.dnsvip.ServeUDP(c, dstIP)
				return true
			}
			if dstPort == 443 && g.dnsvip.IsVIP(dstIP) {
				// QUIC / HTTP-3 to an intercepted (VIP'd) host: drop so
				// the client falls back to TCP/443, which we MITM.
				// Relaying it would let that host's HTTPS bypass
				// interception. UDP/443 to a passed-through host falls
				// through to relayUDP — we don't intercept it.
				_ = c.Close()
				return true
			}
			return false
		}
		if err := wg.EnablePromiscuousForwarder(tcpDispatch, udpDispatch); err != nil {
			log.Fatalf("wireguard forwarder: %v", err)
		}
		log.Printf("wireguard promiscuous forwarder ready (any dst → :443=mitm, UDP/443→drop(quic) for VIPs, :5432=pg, :53=dns-vip, VIP=ssh|ch_native, :%d=dash, plugins=conn-index, else=relay)", dashPort)
	}

	tsnetServer, ln, err := openListener(cfg, stateDir)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if tsnetServer != nil {
		// Advertise exit routes plus the dnsvip CIDRs as subnet routes;
		// without the latter, exit-node clients can't reach any v4 VIP
		// (the local inbound filter shrinks a /0 advertisement to
		// public space only). See advertiseExitRoutes.
		vip4, vip6 := g.dnsvip.CIDRs()
		go advertiseExitRoutes(tsnetServer, vip4, vip6)
	}
	if ln != nil {
		log.Printf("gateway listening on %s, %d endpoints across %d profiles",
			ln.Addr(), len(policy.Endpoints), len(policy.Profiles))
	} else {
		log.Printf("gateway listening on tsnet (exit-node routed), %d endpoints across %d profiles",
			len(policy.Endpoints), len(policy.Profiles))
	}

	if tsnetServer != nil && cfg.Funnel() && cfg.PublicURL() == "" {
		// Auto-derive public_url from the tsnet cert domain so that
		// join responses, HITL status links, and OAuth redirect URIs use
		// the correct internet-reachable URL when funnel = true. Cert
		// provisioning can lag Funnel listener start by a few seconds,
		// so retry async.
		go func() {
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				if domain := tsnetCertDomain(tsnetServer); domain != "" {
					cfg.SetPublicURL(domain)
					log.Printf("tsnet: funnel public_url auto-derived: %s", domain)
					return
				}
				time.Sleep(2 * time.Second)
			}
			log.Printf("tsnet: funnel public_url not derived after 60s — dashboard will show the loopback URL in join hints")
		}()
	}
	tsnetDashMux := newWebMux(g, cfg.Join(), cfg.PublicURL())
	tsnetDashPort := portOf(dashListen)
	if tsnetServer != nil {
		// Seed gateway tailscale IP for /api/join responses so clients
		// know the tailnet-direct URL without a DNS lookup.
		// Retry status query — DNSName populates after netmap arrives from
		// control, which can lag Listen() by a second or two. Without retry
		// we'd read empty DNSName and fall back to OS hostname, which is
		// often wrong (tsnet may have registered under a different name
		// from saved state). Retry for up to 15s.
		go func() {
			lc2, err2 := tsnetServer.LocalClient()
			if err2 != nil {
				log.Printf("tsnet: LocalClient err: %v", err2)
				return
			}
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				st, err3 := lc2.StatusWithoutPeers(context.Background())
				if err3 != nil || st.Self == nil {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				if g.tailscaleIP == "" {
					for _, ip := range st.Self.TailscaleIPs {
						if ip.Is4() {
							g.tailscaleIP = ip.String()
							break
						}
					}
				}
				hn := st.Self.DNSName
				if i := strings.IndexByte(hn, '.'); i > 0 {
					hn = hn[:i]
				}
				if hn != "" {
					g.tailscaleHostname = hn
					log.Printf("tsnet: node name %q IP %s", hn, g.tailscaleIP)
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
			log.Printf("tsnet: never got DNSName from status — gateway_host may be wrong")
		}()
		// Replace the default system-tailscaled LocalClient with the tsnet
		// one so that whois lookups (dashboard auth, identity derivation)
		// work on machines without a system tailscaled daemon.
		if lc, err := tsnetServer.LocalClient(); err == nil {
			g.agents.SetLocalClient(lc)
			g.tsnetLC = lc
		} else {
			log.Printf("tsnet: LocalClient for whois: %v", err)
		}
		// Serve the dashboard mux on tsnet's virtual network so
		// clawpatrol-run clients connecting to this tsnet IP on the
		// dashboard port can mint ephemeral auth keys and reach the
		// dashboard.
		if dashPort := portOf(dashListen); dashPort != 0 {
			if tsnetDashLn, err := tsnetServer.Listen("tcp", fmt.Sprintf(":%d", dashPort)); err != nil {
				log.Printf("tsnet: dashboard listen :%d: %v", dashPort, err)
			} else {
				go func() {
					if err := http.Serve(tsnetDashLn, tsnetDashMux); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Printf("tsnet: dashboard serve: %v", err)
					}
				}()
				log.Printf("tsnet: dashboard also listening on tsnet :%d", dashPort)
			}
		}
		if cfg.Funnel() {
			startFunnelListener(tsnetServer, tsnetDashMux)
		}
		// UDP/53 DNS server on the tsnet node. Whole-machine clients with
		// the gateway as exit-node send DNS via UDP/53 to the gateway's
		// tailnet IP; dnsvip allocates a VIP per intercepted hostname so
		// the subsequent TCP connection has a VIP the gateway recognises
		// and dispatches. WG mode's promiscuous forwarder caught this
		// already; tsnet exit-node needs an explicit listener.
		//
		// ListenPacket requires a concrete IP (not the wildcard). Wait
		// for the tailnet IP to be assigned, then bind there.
		if g.dnsvip != nil {
			go func() {
				for i := 0; i < 60 && g.tailscaleIP == ""; i++ {
					time.Sleep(500 * time.Millisecond)
				}
				if g.tailscaleIP == "" {
					log.Printf("tsnet: dnsvip UDP listener skipped — no tailscale IP")
					return
				}
				pc, err := tsnetServer.ListenPacket("udp", g.tailscaleIP+":53")
				if err != nil {
					log.Printf("tsnet: udp %s:53 (dns): %v", g.tailscaleIP, err)
					return
				}
				log.Printf("tsnet: dnsvip UDP listener on %s:53", g.tailscaleIP)
				serveTsnetDNSUDP(pc, g.dnsvip)
			}()
			// Layer a UDP catch-all onto tsnet's underlying netstack so
			// exit-node clients' UDP reaches clawpatrol: UDP/53 to any
			// resolver IP reaches dnsvip (the IP-bound listener above only
			// catches packets aimed at the gateway's own tailnet IP), and
			// other UDP from onboarded peers is relayed. tsnet has no public
			// UDP fallback hook, so this reaches through Sys().Netstack (see
			// installTsnetUDPCatchAll).
			g.installTsnetUDPCatchAll(tsnetServer)
		}
		// Intercept all TCP forwarded through this exit node (whole-machine
		// clients). dst is the original internet destination — same dispatch
		// as the per-process PROXY-header path and the WG promiscuous forwarder.
		tsnetServer.RegisterFallbackTCPHandler(func(_, dst netip.AddrPort) (func(net.Conn), bool) {
			dstIP := dst.Addr().String()
			dstPort := dst.Port()
			return func(c net.Conn) {
				switch {
				case g.shouldHandleHTTPSMITM(c, dstIP, dstPort):
					g.handle(c, dstIP, dstPort)
				case dstPort == 5432:
					g.handlePostgresConn(c, dstIP)
				case dstPort == 53:
					g.handleDNSTCPConn(c, dstIP)
				case g.dnsvip.IsVIP(dstIP):
					g.handleVIPConn(c, dstIP, dstPort)
				case tsnetDashPort != 0 && int(dstPort) == tsnetDashPort:
					_ = http.Serve(&oneShotListener{c: c}, tsnetDashMux)
				default:
					if g.tryDirectIPConn(c, dstIP, dstPort) {
						return
					}
					g.wgRelay(c, dstIP, int(dstPort))
				}
			}, true
		})
	}
	if ln == nil {
		// Tailscale mode: nothing more to accept here. All client TCP
		// arrives via the tsnet fallback handler above; UDP/53 via the
		// dnsvip listener; HTTPS/info via the Funnel + tsnet info
		// listeners. Block forever so runGateway doesn't return.
		select {}
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			// Host-local TCP listener (only opened when wireguard is
			// enabled). Used by single-host deployments where the
			// gateway runs under one user account and clawpatrol-run
			// is invoked from another on the same machine — both
			// loop back through 127.0.0.1:8443. No PROXY framing in
			// this mode — terminate TLS, serve the dashboard mux.
			g.serveTSNetDirect(c, tsnetDashMux)
		}(c)
	}
}

func serveHTTPLogged(name, addr string, handler http.Handler) {
	if err := http.ListenAndServe(addr, handler); err != nil {
		logHTTPServerExit(name, addr, err)
	}
}

// installGatewayShutdown spawns a goroutine that waits for SIGINT or
// SIGTERM, flushes telemetry, drains the action sink, closes tunnels
// and the DB handle, then exits the process. otelShutdown may be nil
// when otel was not configured.
//
// Why a goroutine + os.Exit rather than threading shutdown back into
// runGateway: the gateway's main accept loop (ln.Accept inside
// runGateway) is intentionally infinite — letting it return would
// drop any pending sweeper / config-watch / sink-drain goroutines on
// the floor without their own cleanup. The signal handler is the
// single exit site; everything that needs to flush hooks into it.
//
// Best-effort: each step has its own budget so one wedged collaborator
// can't block the rest. Order is load-bearing — Sink.Close has to
// drain into the DB before db.Close, and TunnelManager.CloseAll has
// to run while goroutines still have a chance to react (Tailscale
// logout in particular wants a live tsnet.Server).
const (
	gatewayOtelShutdownTimeout   = 5 * time.Second
	gatewaySinkShutdownTimeout   = 5 * time.Second
	gatewayTunnelShutdownTimeout = 5 * time.Second
)

func installGatewayShutdown(g *Gateway, otelShutdown func(context.Context) error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("gateway: received %s, shutting down", sig)
		runGatewayShutdown(g, otelShutdown)
		log.Printf("gateway: shutdown complete")
		os.Exit(0)
	}()
}

// runGatewayShutdown executes the shutdown sequence in dependency
// order. Extracted from the signal-handler goroutine so the order is
// testable without the surrounding os.Exit wrapper. Each step is
// best-effort: any single failure logs and moves on so a wedged
// collaborator can't strand WAL checkpointing.
func runGatewayShutdown(g *Gateway, otelShutdown func(context.Context) error) {
	runShutdownFlush(otelShutdown, gatewayOtelShutdownTimeout)
	if g != nil && g.sink != nil {
		ctx, cancel := context.WithTimeout(context.Background(), gatewaySinkShutdownTimeout)
		if err := g.sink.Close(ctx); err != nil {
			log.Printf("gateway: sink drain: %v", err)
		}
		cancel()
	}
	if g != nil && g.tunnels != nil {
		ctx, cancel := context.WithTimeout(context.Background(), gatewayTunnelShutdownTimeout)
		if err := g.tunnels.CloseAll(ctx); err != nil {
			log.Printf("gateway: tunnel close: %v", err)
		}
		cancel()
	}
	if g != nil && g.db != nil {
		if err := g.db.Close(); err != nil {
			log.Printf("gateway: db close: %v", err)
		}
	}
}

// runShutdownFlush invokes the otel shutdown closure (when non-nil)
// under a bounded context, logging any error. Split out from
// installGatewayShutdown so the timeout-and-error contract is testable
// without the surrounding signal / os.Exit wrapper.
func runShutdownFlush(otelShutdown func(context.Context) error, timeout time.Duration) {
	if err := runShutdownFlushErr(otelShutdown, timeout); err != nil {
		log.Printf("gateway: otel shutdown: %v", err)
	}
}

// runShutdownFlushErr is the pure variant: returns the flush error
// instead of logging it. Used by tests; the production wrapper above
// pipes the error to the log.
func runShutdownFlushErr(otelShutdown func(context.Context) error, timeout time.Duration) error {
	if otelShutdown == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return otelShutdown(ctx)
}

func logHTTPServerExit(name, addr string, err error) {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	log.Printf("%s http server on %s stopped: %v", name, addr, err)
}

// portOf extracts the numeric port from a "host:port" or ":port" listen
// string. Returns 0 when the input is empty or unparseable.
func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// oneShotListener wraps a single net.Conn so http.Serve can hand it to
// the dashboard mux. After the first Accept, subsequent calls block
// until Close — the netstack forwarder spawns one goroutine per conn
// so http.Serve cleanly exits when the connection ends.
type oneShotListener struct {
	c    net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.done
		return nil, net.ErrClosed
	}
	l.once = true
	if l.done == nil {
		l.done = make(chan struct{})
	}
	return l.c, nil
}

func (l *oneShotListener) Close() error {
	if l.done != nil {
		select {
		case <-l.done:
		default:
			close(l.done)
		}
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	if l.c == nil {
		return &net.TCPAddr{}
	}
	return l.c.LocalAddr()
}

// wgRelay is the catch-all path: WG peer wants to talk to a host we
// don't MITM (plain HTTP, ssh, anything not on :443 or the dash port).
// Dials the real dst from the host network and pipes bytes both ways.
// Emits a sink Event so transparently-relayed flows show up in the
// dashboard request history alongside MITM traffic — without this,
// ssh / git-over-ssh / arbitrary-port connections went silent.
//
// Analytics are gated on the peer being a known device. The tsnet
// fallback handler catches every TCP forwarded through the gateway's
// exit-node advertisement, which includes stray probes from every
// other tailnet peer on the network. Without the gate, each new
// probing tailnet IP mints a synthetic "agent" row in the dashboard
// and the actions table fills up with thousands of phantom devices
// that never appear in the device list. The dial still runs for
// unknown peers (relay behavior unchanged); only the sink event is
// suppressed.
func (g *Gateway) wgRelay(c net.Conn, dstIP string, dstPort int) {
	defer func() { _ = c.Close() }()
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)
	known := g.onboard == nil || g.onboard.HasDevice(pip) || g.onboard.HasDevice(agentPip)
	host := fmt.Sprintf("%s:%d", dstIP, dstPort)
	start := time.Now()
	up, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), 10*time.Second)
	if err != nil {
		if known {
			g.sink.Emit(Event{
				Mode: "relay", AgentIP: agentPip, Agent: profile,
				Host: host, Action: "deny", Reason: err.Error(),
				Ms: time.Since(start).Milliseconds(),
			})
		}
		return
	}
	defer func() { _ = up.Close() }()
	var tracker func(rx, tx int64)
	if known {
		tracker = g.streamTracker(agentPip, host)
	}
	rx, tx := pipeProgress(c, up, tracker)
	if known {
		g.sink.Emit(Event{
			Mode: "relay", AgentIP: agentPip, Agent: profile,
			Host: host, Action: "allow",
			In: rx, Out: tx,
			Ms: time.Since(start).Milliseconds(),
		})
	}
}

// streamTracker returns a pipeProgress onTick callback that feeds the
// per-agent activity sparkline with per-second byte deltas. Long-lived
// flows (ssh clone, websocket) need DURING-flight updates — sampleLoop
// reads BytesIn/Out at 1Hz and computes a delta, so a 10-minute flow
// without streaming track calls paints flat zeros until close. Returns
// nil when no agent IP / no registry — pipeProgress treats nil as
// "skip the ticker goroutine entirely".
func (g *Gateway) streamTracker(agentIP, host string) func(rx, tx int64) {
	if g.agents == nil || agentIP == "" {
		return nil
	}
	var lastRx, lastTx int64
	return func(rx, tx int64) {
		dRx := rx - lastRx
		dTx := tx - lastTx
		lastRx, lastTx = rx, tx
		if dRx == 0 && dTx == 0 {
			return
		}
		g.agents.track(agentIP, host, dRx, dTx)
	}
}
