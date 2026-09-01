// Package main implements clawpatrol main support.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"tailscale.com/client/local"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/config/plugins/tailscaleproto"
)

type Agent struct {
	IP           string     `json:"ip"`
	ExternalIPv4 string     `json:"external_ipv4,omitempty"`
	ExternalIPv6 string     `json:"external_ipv6,omitempty"`
	Hostname     string     `json:"hostname"`
	User         string     `json:"user"`
	Profile      string     `json:"profile,omitempty"`
	OS           string     `json:"os"`
	UA           string     `json:"ua"`
	FirstAt      time.Time  `json:"first_at"`
	LastAt       time.Time  `json:"last_at"`
	Reqs         int64      `json:"reqs"`
	BytesIn      int64      `json:"bytes_in"`
	BytesOut     int64      `json:"bytes_out"`
	LastHost     string     `json:"last_host"`
	Activity     []int      `json:"activity"`
	Integrations []string   `json:"integrations"`
	Sessions     []*Session `json:"sessions,omitempty"`
	prevTotal    int64
}

// Session = one coding-agent conversation on a device. Identified by
// (type, hash-of-first-user-message). New session = new first-message.
type Session struct {
	ID        string    `json:"id"` // sha256(first user message), short
	Title     string    `json:"title,omitempty"`
	Type      string    `json:"type"`
	Model     string    `json:"model,omitempty"`
	TokensIn  int64     `json:"tokens_in,omitempty"`
	TokensOut int64     `json:"tokens_out,omitempty"`
	CtxUsed   int64     `json:"ctx_used,omitempty"`
	CtxMax    int64     `json:"ctx_max,omitempty"`
	FirstAt   time.Time `json:"first_at"`
	LastAt    time.Time `json:"last_at"`
	Reqs      int64     `json:"reqs"`
	Activity  []int     `json:"activity"`
	prevReqs  int64
}

// findOrAddSession returns an existing session by (type, id) or creates one.
// id may be empty → caller has no first-message hash, falls back to
// most-recent same-type session if any. Caller holds r.mu.
func (a *Agent) findOrAddSession(t, id, title string) *Session {
	if id != "" {
		for _, s := range a.Sessions {
			if s.Type == t && s.ID == id {
				s.LastAt = time.Now().UTC()
				s.Reqs++
				return s
			}
		}
	} else {
		// no id: extend most-recent same-type session
		for i := len(a.Sessions) - 1; i >= 0; i-- {
			if a.Sessions[i].Type == t {
				s := a.Sessions[i]
				s.LastAt = time.Now().UTC()
				s.Reqs++
				return s
			}
		}
	}
	now := time.Now().UTC()
	s := &Session{ID: id, Title: title, Type: t, FirstAt: now, LastAt: now, Reqs: 1}
	a.Sessions = append(a.Sessions, s)
	return s
}

// detectAgentTypeFromHost infers type from destination host (used for
// splice path where we don't see UA).
func detectAgentTypeFromHost(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, "anthropic.com") || strings.HasSuffix(h, "claude.ai") || strings.HasSuffix(h, "claude.com"):
		return "claude"
	case strings.HasSuffix(h, "openai.com") || strings.HasSuffix(h, "chatgpt.com") || strings.HasSuffix(h, "oaiusercontent.com"):
		return "codex"
	}
	return ""
}

type AgentRegistry struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
	lc      *local.Client
	onboard *onboardRegistry // set by Gateway ctor; supplies hostname/owner overrides in WG mode
	db      *sql.DB          // optional; persists Session rows. nil → in-memory only.

	// persistState debounces per-session DB writes (see persistSession).
	// Separate mutex from r.mu so a slow SQLite write doesn't block
	// snapshot()/track() readers.
	persistMu    sync.Mutex
	persistState map[string]persistMark
}

const activityBuckets = 30 // ~30s history at 1s sampling

func NewAgentRegistry() *AgentRegistry {
	r := &AgentRegistry{
		agents: map[string]*Agent{},
		lc:     &local.Client{},
	}
	go r.sampleLoop()
	return r
}

// SetLocalClient replaces the default system-tailscaled LocalClient with
// the one from an embedded tsnet.Server. Call after tsnet is up so that
// whois lookups resolve against the tsnet peer table, not the host daemon.
func (r *AgentRegistry) SetLocalClient(lc *local.Client) {
	r.mu.Lock()
	r.lc = lc
	r.mu.Unlock()
}

// sampleLoop runs once per second, computes bytes/sec delta per agent,
// appends to Activity ring buffer.
func (r *AgentRegistry) sampleLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		r.mu.Lock()
		for _, a := range r.agents {
			total := a.BytesIn + a.BytesOut
			delta := total - a.prevTotal
			if delta < 0 {
				delta = 0
			}
			a.prevTotal = total
			a.Activity = append(a.Activity, int(delta))
			if len(a.Activity) > activityBuckets {
				a.Activity = a.Activity[len(a.Activity)-activityBuckets:]
			}
			for _, s := range a.Sessions {
				rd := s.Reqs - s.prevReqs
				if rd < 0 {
					rd = 0
				}
				s.prevReqs = s.Reqs
				s.Activity = append(s.Activity, int(rd))
				if len(s.Activity) > activityBuckets {
					s.Activity = s.Activity[len(s.Activity)-activityBuckets:]
				}
			}
		}
		r.mu.Unlock()
	}
}

// Seed creates an empty agent entry for ip if missing. Called at
// onboard-approve time so the device appears in the dashboard before
// it sends any traffic. Hostname / owner are pulled from
// onboardRegistry overrides.
func (r *AgentRegistry) Seed(ip string) {
	if ip == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[ip]; ok {
		return
	}
	now := time.Now().UTC()
	a := &Agent{IP: ip, FirstAt: now, LastAt: now}
	if r.onboard != nil {
		if hn := r.onboard.HostnameForIP(ip); hn != "" {
			a.Hostname = hn
		}
		if owner := r.onboard.OwnerForIP(ip); owner != "" {
			a.User = owner
		}
	}
	r.agents[ip] = a
	// Kick off the whois fill the same way trackUA does on first sight.
	// Without this, pre-seeding the entry here means the agent-miss
	// branch in trackUA never fires for this IP, so OS / tailnet login
	// would never populate. Skip placeholder IDs (tsnet-<host>) — they
	// aren't real addresses; promotion re-seeds under the tailnet IP.
	if !strings.HasPrefix(ip, tsnetPlaceholderPrefix) {
		go r.fillIdentity(ip)
	}
}

func (r *AgentRegistry) track(remoteAddr, host string, in, out int64) {
	r.trackUA(remoteAddr, host, "", in, out)
}

func (r *AgentRegistry) trackUA(remoteAddr, host, ua string, in, out int64) {
	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = remoteAddr
	}
	now := time.Now().UTC()

	r.mu.Lock()
	a, ok := r.agents[ip]
	if !ok {
		a = &Agent{IP: ip, FirstAt: now}
		// WG-mode override: hostname captured at `clawpatrol join` time.
		// Tailscale whois fills more (User, OS) — see fillIdentity.
		if r.onboard != nil {
			if hn := r.onboard.HostnameForIP(ip); hn != "" {
				a.Hostname = hn
			}
			if owner := r.onboard.OwnerForIP(ip); owner != "" {
				a.User = owner
			}
		}
		r.agents[ip] = a
		go r.fillIdentity(ip)
	}
	a.LastAt = now
	a.Reqs++
	a.BytesIn += in
	a.BytesOut += out
	a.LastHost = host
	if ua != "" {
		a.UA = ua
	}
	// best-effort session creation for codex via splice (chatgpt.com etc.)
	// — claude sessions are created in trackLLMUsage when /v1/messages
	// fires. We only auto-create here for hosts we *can't* MITM.
	if t := detectAgentTypeFromHost(host); t == "codex" {
		a.findOrAddSession(t, "", "")
	}
	r.mu.Unlock()
}

// lookupWhois does a synchronous whois (short timeout). Used for
// credential-owner derivation per-request. Returns nil on failure.
func (r *AgentRegistry) lookupWhois(ip string) *whoisResult {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	who, err := r.lc.WhoIs(ctx, netip.AddrPortFrom(addr, 0).String())
	if err != nil || who == nil {
		return nil
	}
	res := &whoisResult{}
	if who.Node != nil {
		res.Node = whoisNode{StableID: string(who.Node.StableID), HostName: who.Node.Hostinfo.Hostname()}
	}
	if who.UserProfile != nil {
		res.UserProfile = whoisProfile{LoginName: who.UserProfile.LoginName}
	}
	return res
}

type whoisResult struct {
	Node        whoisNode
	UserProfile whoisProfile
}
type whoisNode struct{ StableID, HostName string }
type whoisProfile struct{ LoginName string }

func (r *AgentRegistry) fillIdentity(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addrPort := netip.AddrPortFrom(addr, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Snapshot the LocalClient under the lock — SetLocalClient swaps it
	// in once tsnet is up, and Seed now spawns fillIdentity at boot
	// (via seedAgentsFromDevices) which can race that write.
	r.mu.Lock()
	lc := r.lc
	r.mu.Unlock()
	if lc == nil {
		return
	}
	who, err := lc.WhoIs(ctx, addrPort.String())
	if err != nil || who == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[ip]
	if !ok {
		return
	}
	if who.Node != nil {
		// An ephemeral `--login` join-bootstrap node is not a managed
		// device — its API calls during onboarding get tracked like
		// any tailnet peer, but it's discarded the instant join
		// completes. Drop it once whois reveals what it is.
		if strings.HasPrefix(who.Node.Hostinfo.Hostname(), bootstrapHostnamePrefix) {
			delete(r.agents, ip)
			return
		}
		// Onboard-supplied hostname (via /api/onboard/claim or
		// /api/peer/tsnet/register) takes priority. The whois response
		// reflects whatever the tsnet node registered with (the daemon's
		// configured hostname) — letting it overwrite would clobber the
		// operator-chosen name with whatever Hostinfo.Hostname() returns.
		if a.Hostname == "" {
			a.Hostname = who.Node.Hostinfo.Hostname()
		}
		a.OS = who.Node.Hostinfo.OS()
	}
	if who.UserProfile != nil {
		a.User = who.UserProfile.LoginName
	}
}

func (r *AgentRegistry) snapshot() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		cp := *a
		if r.onboard != nil {
			cp.Profile = r.onboard.ProfileForIP(a.IP)
		}
		if a.Activity != nil {
			cp.Activity = append([]int(nil), a.Activity...)
		}
		if a.Integrations != nil {
			cp.Integrations = append([]string(nil), a.Integrations...)
		}
		if a.Sessions != nil {
			cp.Sessions = make([]*Session, len(a.Sessions))
			for i, s := range a.Sessions {
				sc := *s
				if s.Activity != nil {
					sc.Activity = append([]int(nil), s.Activity...)
				}
				cp.Sessions[i] = &sc
			}
		}
		out = append(out, &cp)
	}
	return out
}

// Delete drops an agent from the registry. Idempotent — silent on
// unknown IP. Caller is expected to also clear any side-tables
// (onboard ownerByIP override, OAuth credentials, etc.).
func (r *AgentRegistry) Delete(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, ip)
}

func (r *AgentRegistry) recordLLMUsage(ip, sessionType, sessionID, sessionTitle, model string, in, out int64) {
	r.mu.Lock()
	a := r.agents[ip]
	if a == nil {
		r.mu.Unlock()
		return
	}
	s := a.findOrAddSession(sessionType, sessionID, sessionTitle)
	if model != "" {
		s.Model = model
	}
	// Title tracks the LATEST user message, not the first. Sessions
	// can stretch across days and revive on new activity — pinning the
	// title to the first prompt buries what the agent is actually
	// working on right now. parseClaudeRequest / codex parsers send
	// the latest user-message text on every recordLLMUsage call, so
	// just overwrite. Empty sessionTitle (e.g. tool-result-only turns)
	// preserves the previous value.
	if sessionTitle != "" {
		s.Title = sessionTitle
	}
	s.TokensIn += in
	s.TokensOut += out
	s.CtxUsed = in + out
	s.CtxMax = ctxMaxFor(model)
	persistAgent := ip
	persistSession := *s
	r.mu.Unlock()
	r.persistSession(persistAgent, &persistSession)
}

// persistSession writes/updates the session row. Debounced — a
// session that's already been persisted within persistDebounce gets
// skipped unless the title changed (which is what dashboard users
// most want to see live). The skipped writes are coalesced into the
// next call after the debounce expires; in-memory state is always
// authoritative, the DB lags by ≤ persistDebounce.
//
// Why this matters: codex WS frames hit recordLLMUsage every output
// token (tens per second on a streaming response). Without debounce
// each one triggered an UPDATE — bursty SQLite writes serialize on
// the writer thread and the per-event sink drain backs up. With
// debounce the DB sees ~1 write/sec/session even under streaming.
//
// Called outside the registry lock so a slow disk write doesn't block
// other request handlers.
const persistDebounce = 2 * time.Second

func (r *AgentRegistry) persistSession(ip string, s *Session) {
	if r == nil || r.db == nil || s == nil {
		return
	}
	key := ip + "|" + s.Type + "|" + s.ID
	now := time.Now()

	r.persistMu.Lock()
	prev, hadPrev := r.persistState[key]
	titleChanged := prev.title != s.Title
	stale := !hadPrev || now.Sub(prev.at) >= persistDebounce
	if !titleChanged && !stale {
		r.persistMu.Unlock()
		return
	}
	if r.persistState == nil {
		r.persistState = map[string]persistMark{}
	}
	r.persistState[key] = persistMark{at: now, title: s.Title}
	r.persistMu.Unlock()

	_, _ = r.db.Exec(`
		INSERT INTO sessions
		  (agent_ip, type, id, title, model, tokens_in, tokens_out, ctx_used, ctx_max, reqs, first_at, last_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_ip, type, id) DO UPDATE SET
		  title      = COALESCE(NULLIF(excluded.title,''), sessions.title),
		  model      = COALESCE(NULLIF(excluded.model,''), sessions.model),
		  tokens_in  = excluded.tokens_in,
		  tokens_out = excluded.tokens_out,
		  ctx_used   = excluded.ctx_used,
		  ctx_max    = excluded.ctx_max,
		  reqs       = excluded.reqs,
		  last_at    = excluded.last_at
	`, ip, s.Type, s.ID, s.Title, s.Model,
		s.TokensIn, s.TokensOut, s.CtxUsed, s.CtxMax, s.Reqs,
		s.FirstAt.UnixNano(), s.LastAt.UnixNano())
}

type persistMark struct {
	at    time.Time
	title string
}

// LoadSessions rehydrates persisted sessions from the DB into the
// in-memory agent map. Called once at boot, after Seed has populated
// agents from the devices table. Skips closed sessions older than the
// keep window — those are sweeper-deletable, no point rendering them.
func (r *AgentRegistry) LoadSessions(db *sql.DB) {
	if db == nil {
		return
	}
	r.mu.Lock()
	r.db = db
	r.mu.Unlock()
	rows, err := db.Query(`
		SELECT agent_ip, type, id, COALESCE(title,''), COALESCE(model,''),
		       tokens_in, tokens_out, ctx_used, ctx_max, reqs,
		       first_at, last_at
		  FROM sessions
		 ORDER BY last_at ASC`)
	if err != nil {
		log.Printf("sessions: load: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	r.mu.Lock()
	defer r.mu.Unlock()
	for rows.Next() {
		var (
			ip, t, id, title, model      string
			ti, to, cu, cm, reqs, fa, la int64
		)
		if err := rows.Scan(&ip, &t, &id, &title, &model, &ti, &to, &cu, &cm, &reqs, &fa, &la); err != nil {
			log.Printf("sessions: scan row: %v", err)
			continue
		}
		if r.onboard != nil && !r.onboard.HasDevice(ip) {
			continue // device row gone (e.g. reaped at startup) — skip orphaned sessions
		}
		a := r.agents[ip]
		if a == nil {
			now := time.Now().UTC()
			a = &Agent{IP: ip, FirstAt: now, LastAt: now}
			if r.onboard != nil {
				if hn := r.onboard.HostnameForIP(ip); hn != "" {
					a.Hostname = hn
				}
				if owner := r.onboard.OwnerForIP(ip); owner != "" {
					a.User = owner
				}
			}
			r.agents[ip] = a
		}
		s := &Session{
			ID: id, Title: title, Type: t, Model: model,
			TokensIn: ti, TokensOut: to, CtxUsed: cu, CtxMax: cm,
			Reqs: reqs, FirstAt: time.Unix(0, fa), LastAt: time.Unix(0, la),
		}
		a.Sessions = append(a.Sessions, s)
	}
	if err := rows.Err(); err != nil {
		log.Printf("sessions: load rows: %v", err)
	}
}

// startSessionSweeper deletes sessions whose last_at is older than
// keep. There's no "closed" intermediate state — sessions can revive
// on new activity at any time, marking them closed mid-life would
// either drop legitimate rows or freeze the dashboard's history.
// Sweep just enforces a hard retention floor.
//
// keep=0 disables the sweeper entirely; otherwise the goroutine ticks
// every minute (first run 30s after boot to avoid log noise on
// restart) and runs an indexed DELETE.
func (r *AgentRegistry) startSessionSweeper(keep time.Duration) {
	if r.db == nil || keep <= 0 {
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			r.sweepSessions(keep)
			<-t.C
		}
	}()
}

func (r *AgentRegistry) sweepSessions(keep time.Duration) {
	cutoffT := time.Now().Add(-keep)
	cutoff := cutoffT.UnixNano()
	// Surface the delete error so a silently-failing sweep (e.g. WAL
	// checkpoint contention dragging on past busy_timeout, or a
	// schema-incompatible row blocking the index walk) doesn't accrete
	// unbounded session history without anyone noticing. The in-memory
	// trim below still runs on error so the dashboard's view at least
	// rolls forward — the next tick will retry the delete.
	if _, err := r.db.Exec(`DELETE FROM sessions WHERE last_at < ?`, cutoff); err != nil {
		log.Printf("sessions: sweep delete: %v", err)
	}
	// Trim in-memory slices too. Without this the dashboard keeps
	// showing rows the DB no longer has — apiAgents reads from
	// snapshot(), not from the DB. Single pass under the registry
	// write lock; sessions are already grouped per-agent.
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.agents {
		if len(a.Sessions) == 0 {
			continue
		}
		kept := a.Sessions[:0]
		for _, s := range a.Sessions {
			if s.LastAt.After(cutoffT) {
				kept = append(kept, s)
			}
		}
		a.Sessions = kept
	}
}

func ctxMaxFor(model string) int64 {
	return models.ctxMax(model)
}

func shortHash(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

type IntegrationRow struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Type             string                 `json:"type"` // credential plugin type
	HasOAuth         bool                   `json:"has_oauth"`
	OAuth            *OAuthIntegrationUI    `json:"oauth,omitempty"`
	Slots            []config.SecretSlot    `json:"slots,omitempty"`
	Connected        bool                   `json:"connected"`
	ExpiresAt        int64                  `json:"expires_at,omitempty"`
	DisplayName      string                 `json:"display_name,omitempty"`
	AvatarURL        string                 `json:"avatar_url,omitempty"`
	HasTailscaleAuth bool                   `json:"has_tailscale_auth,omitempty"`
	TailscaleAuth    *TailscaleAuthStatusUI `json:"tailscale_auth,omitempty"`

	// Passthrough is true for credentials whose type injects nothing at
	// request time (the `passthrough` type). They exist only as a
	// claimable handle for credential-less endpoints; the dashboard
	// renders a "no injection" indicator and offers no connect flow.
	Passthrough bool `json:"passthrough,omitempty"`

	// Profiles is the sorted list of profile names that route any
	// endpoint or tunnel binding this credential. Empty when the
	// credential is declared but no profile references it.
	Profiles []string `json:"profiles,omitempty"`
	// Endpoints is the sorted list of endpoint names this credential
	// binds — directly via its `endpoint` / `endpoints` field, or
	// transitively via the credential attached to an endpoint's
	// `tunnel = ...`.
	Endpoints []string `json:"endpoints,omitempty"`
	// Config exposes the operator-set HCL block attributes for the
	// credential (e.g. `user = "postgres"`) keyed by attribute name.
	// Values are the raw HCL token text (quoted strings included).
	// Never contains secret material — secret bytes live in the
	// secrets store, not in the HCL block.
	Config map[string]string `json:"config,omitempty"`
	// UpdatedAt is the Unix-seconds timestamp of the most recent
	// persistence event for this credential — the max of
	// credential_secrets.updated_ns and the OAuth row's updated_ns.
	// Zero when neither store has a row (declared-only credential).
	// The dashboard sorts the per-type details table by this so the
	// most recently connected credential surfaces at the top of the
	// non-pending rows.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// TailscaleAuthStatusUI is the dashboard-facing slice of a
// tailscale-node-auth credential's live state. Connected reflects
// tailnet-auth validity, not tunnel liveness: a credential whose
// OAuth-issued node identity is persisted and has not been observed
// to fail (NeedsLogin / NeedsMachAuth / InUseOtherUser) reads as
// connected even when the tunnel is idle and tsnet is torn down.
// State carries the underlying live BackendState label (or a
// hasPersistedSlots-aware fallback) so the card can distinguish
// "awaiting authentication" from "starting" from "stopped" from
// "running" — that's the tunnel signal, separate from the credential
// signal. PendingURL is the live Tailscale login URL emitted by
// tsnet during NeedsLogin — the dashboard's "Connect" button
// redirects to it. Endpoint paths are surfaced so the dashboard
// renders the connect flow without hard-coding the route layout.
type TailscaleAuthStatusUI struct {
	Connected bool                          `json:"connected"`
	State     tailscaleproto.NodeStateLabel `json:"state"`
	// HasState is true when credential_secrets carries any rows for
	// this credential — i.e. there's a persisted tsnet identity (or a
	// fragment of one) that could be cleared by Disconnect. The
	// dashboard renders the disconnect ✕ off this field rather than
	// gating it on Connected, so an operator can reset a stuck
	// identity even when tsnet has dropped out of Running.
	HasState      bool   `json:"has_state,omitempty"`
	PendingURL    string `json:"pending_url,omitempty"`
	ConnectURL    string `json:"connect_url"`
	StatusURL     string `json:"status_url"`
	DisconnectURL string `json:"disconnect_url"`
}

// OAuthIntegrationUI is the dashboard-facing slice of an
// OAuthIntegration: just enough for the connect modal to render the
// always-included base scopes and the optional pickable catalog.
type OAuthIntegrationUI struct {
	BaseScopes     []string                    `json:"base_scopes"`
	OptionalScopes []config.OptionalScopeGroup `json:"optional_scopes,omitempty"`
}

func (w *webMux) apiStatus(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, w.statusList(r))
}

// statusList exposes the apiStatus payload as a Go slice so /api/state
// can bundle it without going through writeJSON. Same data shape; no
// behavior change.
func (w *webMux) statusList(r *http.Request) []IntegrationRow {
	out := []IntegrationRow{}
	policy := w.g.policy.Load()
	if policy == nil {
		return out
	}
	profile := r.URL.Query().Get("profile")
	allowed := credentialsInProfile(policy, profile)

	names := make([]string, 0, len(policy.Credentials))
	for name := range policy.Credentials {
		if allowed != nil && !allowed[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ent := policy.Credentials[name]
		row := IntegrationRow{ID: name, Name: name, Type: ent.Plugin.Type}
		if op, ok := ent.Body.(config.OAuthFlowProvider); ok {
			row.HasOAuth = true
			if flow := op.OAuthFlow(); flow != nil {
				row.OAuth = &OAuthIntegrationUI{
					BaseScopes:     flow.OAuth.Scopes,
					OptionalScopes: flow.OptionalScopes,
				}
			}
			if connected, exp := w.g.oauth.Status(name); connected {
				row.Connected = true
				if !exp.IsZero() {
					row.ExpiresAt = exp.Unix()
				}
				row.DisplayName, row.AvatarURL = w.g.oauth.Profile(name)
			}
		}
		if sp, ok := ent.Body.(config.SecretSlotsProvider); ok {
			row.Slots = sp.SecretSlots()
			present, _ := credentialSlotPresence(w.g.db, name)
			if len(present) > 0 {
				row.Connected = true
			}
		}
		if _, ok := ent.Body.(tailscaleproto.TailscaleAuthProvider); ok {
			row.HasTailscaleAuth = true
			present, _ := credentialSlotPresence(w.g.db, name)
			label := tailscaleproto.DefaultStates.Get(name)
			hasSlots := len(present) > 0
			row.TailscaleAuth = &TailscaleAuthStatusUI{
				Connected:     tailscaleCredentialAuthValid(label, hasSlots),
				State:         dashboardTailscaleState(label, hasSlots),
				HasState:      hasSlots,
				PendingURL:    tailscaleproto.Default.Get(name),
				ConnectURL:    "/api/tailscale/connect?id=" + name,
				StatusURL:     "/api/tailscale/status?id=" + name,
				DisconnectURL: "/api/tailscale/disconnect?id=" + name,
			}
		}
		if _, ok := ent.Body.(config.NonInjectingCredential); ok {
			row.Passthrough = true
		}
		row.Profiles, row.Endpoints = credentialBindings(policy, name)
		row.Config = credentialConfig(ent, name)
		row.UpdatedAt = credentialUpdatedAt(w.g.db, name)
		out = append(out, row)
	}
	return out
}

// credentialBindings reports every profile + endpoint that references
// the named credential. The dashboard's details table renders one
// column for profiles and one for endpoints so an operator can see
// at a glance where a credential is in play.
//
// Both columns read in the canonical "credentials bind endpoints"
// direction:
//
//   - Endpoints: the credential's own `endpoint` / `endpoints`
//     framework attr (via config.CredentialEndpointTargets), plus any
//     endpoint whose tunnel chain attaches this credential.
//   - Profiles: each CompiledProfile's own HCL-declared `credentials`
//     list, plus the tunnel chain on the profile's endpoints for
//     tunnel-attached auth.
//
// Walking the inverted CompiledEndpoint.Credentials list would leak
// sibling profiles onto the Profiles column whenever two profiles
// share an endpoint — e.g. the postgres `pg` endpoint carries both
// `pg-readonly` and `pg-writer`, and profile "data" (declares only
// `pg-readonly`) must not appear in `pg-writer`'s Profiles cell.
// Mirror of the device-page fix in cl-lgwg / commit b0a3813.
func credentialBindings(policy *config.CompiledPolicy, credName string) (profiles, endpoints []string) {
	if policy == nil {
		return nil, nil
	}
	epSet := map[string]bool{}
	for _, n := range config.CredentialEndpointTargets(policy.Credentials[credName]) {
		epSet[n] = true
	}
	for epName, ep := range policy.Endpoints {
		for tun := ep.Tunnel; tun != nil; tun = tun.Via {
			if tun.Credential != nil && tun.Credential.Symbol != nil && tun.Credential.Symbol.Name == credName {
				epSet[epName] = true
				break
			}
		}
	}
	if len(epSet) > 0 {
		endpoints = make([]string, 0, len(epSet))
		for n := range epSet {
			endpoints = append(endpoints, n)
		}
		sort.Strings(endpoints)
	}
	profSet := map[string]bool{}
	for pname, prof := range policy.Profiles {
		if profileBindsCredential(prof, credName) {
			profSet[pname] = true
		}
	}
	if len(profSet) > 0 {
		profiles = make([]string, 0, len(profSet))
		for n := range profSet {
			profiles = append(profiles, n)
		}
		sort.Strings(profiles)
	}
	return profiles, endpoints
}

// profileBindsCredential reports whether the profile's own HCL list
// declares the credential, or reaches it via a tunnel attached to one
// of its endpoints. Mirrors credentialsInProfile's data sources so
// the inverse rendering stays consistent with the per-device view.
func profileBindsCredential(prof *config.CompiledProfile, credName string) bool {
	if prof == nil {
		return false
	}
	for _, ent := range prof.Credentials {
		if ent != nil && ent.Symbol != nil && ent.Symbol.Name == credName {
			return true
		}
	}
	for _, ep := range prof.Endpoints {
		for tun := ep.Tunnel; tun != nil; tun = tun.Via {
			if tun.Credential != nil && tun.Credential.Symbol != nil && tun.Credential.Symbol.Name == credName {
				return true
			}
		}
	}
	return false
}

// credentialConfig surfaces the operator-set HCL attributes on a
// credential block (`user = "x"`, `region = "us-east-1"`, …). Built
// by replaying the plugin's Emit hook into a throwaway hclwrite Body
// and harvesting the attributes back out — secret bytes never live
// in the HCL block (they're in the secrets store), so this is safe
// to render as-is. Returns nil when the plugin emits no attributes.
func credentialConfig(ent *config.Entity, name string) map[string]string {
	if ent == nil || ent.Plugin == nil || ent.Plugin.Emit == nil {
		return nil
	}
	file := hclwrite.NewEmptyFile()
	ent.Plugin.Emit(ent.Body, name, file.Body())
	attrs := file.Body().Attributes()
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for n, a := range attrs {
		raw := string(a.Expr().BuildTokens(nil).Bytes())
		out[n] = strings.TrimSpace(raw)
	}
	return out
}

// tailscaleCredentialAuthValid reports whether a tailscale-node-auth
// credential should be rendered as "connected" in the dashboard. It
// is a function of credential auth state alone, not tunnel liveness:
// tunnels open lazily and close on idle, and the credential's OAuth
// grant remains valid across those cycles. A fresh auth attempt
// against the tailnet only fails if the operator (or a tailnet admin)
// has revoked the grant or invalidated the node — which surfaces as
// tsnet entering NeedsLogin / NeedsMachineAuth / InUseOtherUser. As
// long as the watcher hasn't observed one of those auth-trouble
// states, persisted credential_secrets stand as proof that the OAuth
// flow succeeded and the node identity is accepted.
//
// Two paths read as connected:
//   - tsnet is currently Running for this credential (live join, the
//     strongest possible signal);
//   - persisted node-identity slots exist and the live state is not
//     one of the explicit auth-trouble labels (cached last-known-good,
//     the spec for an idle tunnel).
//
// Everything else reads as not-connected, including no-persisted-
// slots-and-not-Running (operator has never completed the auth) and
// any of the auth-trouble labels (the tailnet itself reported the
// credential is no longer good, so cached slots are stale).
func tailscaleCredentialAuthValid(label tailscaleproto.NodeStateLabel, hasPersistedSlots bool) bool {
	if label == tailscaleproto.NodeStateRunning {
		return true
	}
	switch label {
	case tailscaleproto.NodeStateNeedsLogin,
		tailscaleproto.NodeStateNeedsMachAuth,
		tailscaleproto.NodeStateInUseOtherUser:
		return false
	}
	return hasPersistedSlots
}

// dashboardTailscaleState narrows the live BackendState for the
// card's display. When the watcher has never observed a transition
// (the tunnel may still be lazy and tsnet hasn't been brought up
// yet), persisted slots flip the fallback from "unknown" to
// "stopped" — the identity is on disk but nothing is running.
// Without persisted slots and no observed state, "unknown" is
// honest: the operator hasn't connected yet either.
func dashboardTailscaleState(label tailscaleproto.NodeStateLabel, hasPersistedSlots bool) tailscaleproto.NodeStateLabel {
	if label != tailscaleproto.NodeStateUnknown {
		return label
	}
	if hasPersistedSlots {
		return tailscaleproto.NodeStateStopped
	}
	return tailscaleproto.NodeStateUnknown
}

// credentialsInProfile returns the set of credential bare names the
// given profile uses — directly via its `credentials = [...]` list,
// and transitively via the credential attached to an endpoint's
// `tunnel = ...`. nil means "no filter — return everything." Used by
// apiStatus and the device-page card render so per-device views only
// show credentials the device's profile actually uses.
//
// Reads strictly from CompiledProfile.Credentials (the profile's own
// HCL-declared list). Walking ep.Credentials would leak credentials
// from *other* profiles that share the same endpoint — e.g. the
// postgres `pg` endpoint carries both `pg-readonly` and `pg-writer`,
// but profile "data" declares only `pg-readonly` and must not see
// `pg-writer` on its card.
//
// Walking tunnel-attached credentials in addition to the profile's
// own list lets the dashboard surface tunnel-bound auth (e.g. the
// tailscale node-auth credential) on profiles whose endpoints reach
// upstream through that tunnel — the operator clicks Connect on the
// same integration card whether the credential is bound directly to
// the profile or to the tunnel underneath one of its endpoints.
func credentialsInProfile(policy *config.CompiledPolicy, profile string) map[string]bool {
	if profile == "" || policy == nil {
		return nil
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return map[string]bool{} // unknown profile → empty set, not nil
	}
	out := map[string]bool{}
	for _, ent := range prof.Credentials {
		if ent != nil && ent.Symbol != nil {
			out[ent.Symbol.Name] = true
		}
	}
	for _, ep := range prof.Endpoints {
		for tun := ep.Tunnel; tun != nil; tun = tun.Via {
			if tun.Credential != nil && tun.Credential.Symbol != nil {
				out[tun.Credential.Symbol.Name] = true
			}
		}
	}
	return out
}

// agentsList backs the agents slice of /api/state. No HTTP handler —
// the route was removed once App.tsx switched to bundled state.
func (w *webMux) agentsList() []*Agent {
	var snap []*Agent
	if w.g.agents != nil {
		snap = w.g.agents.snapshot()
	}
	// Hide ephemeral `--login` join-bootstrap nodes — fillIdentity drops
	// them once whois resolves, but filter here too so they never flash
	// into the list in the window before that lands.
	snap = slices.DeleteFunc(snap, func(a *Agent) bool {
		return strings.HasPrefix(a.Hostname, bootstrapHostnamePrefix)
	})
	// External IPs: the underlay v4/v6 each WG peer is dialing in from.
	// Show these in place of the server-side /32 (routing artefact).
	// Live endpoint observed via wg-go IpcGet — persist into the devices
	// row so the dashboard keeps a stable last-known address even when
	// the peer goes idle and wg-go drops its endpoint state.
	if globalWG != nil {
		for ip, ep := range globalWG.EndpointsByIP() {
			if ep == "" {
				continue
			}
			parsed := net.ParseIP(ep)
			var v4, v6 string
			if p4 := parsed.To4(); p4 != nil {
				v4 = p4.String()
			} else if parsed != nil {
				v6 = parsed.String()
			}
			w.onboard.SetExternalIPs(ip, v4, v6)
		}
	}
	for _, a := range snap {
		v4, v6 := w.onboard.ExternalIPs(a.IP)
		a.ExternalIPv4, a.ExternalIPv6 = v4, v6
	}
	// Surface the legacy display owner on agents whose User column is
	// still the tailnet "tagged-devices" stub, so the dashboard can
	// render something more meaningful.
	for _, a := range snap {
		if a.User == "" || a.User == "tagged-devices" {
			if owner := w.onboard.OwnerForIP(a.IP); owner != "" {
				a.User = owner
			}
		}
	}
	// Every credential the agent's profile references — connected or
	// not. The dashboard renders the unconfigured ones with a red ring
	// so operators can see at a glance which credentials still need
	// attention. Connection state is joined client-side from the
	// top-level Integration[] list (which already carries per-credential
	// connected / expires_at / display_name / avatar_url).
	policy := w.g.Policy()
	if policy == nil {
		return snap
	}
	for _, a := range snap {
		profile := w.onboard.ProfileForIP(a.IP)
		if profile == "" {
			continue
		}
		allowed := credentialsInProfile(policy, profile)
		if allowed == nil {
			// No profile filter — surface every declared credential.
			allowed = map[string]bool{}
			for name := range policy.Credentials {
				allowed[name] = true
			}
		}
		ids := make([]string, 0, len(allowed))
		for name := range allowed {
			ids = append(ids, name)
		}
		sort.Strings(ids)
		a.Integrations = ids
	}
	return snap
}

// apiAgentDelete drops a device from clawpatrol's view. Removes the
// in-memory agent record, the onboard owner / hostname / profile
// row, and (in WG mode) the WireGuard peer + allowed-IP entry — so
// traffic from the deleted device's tunnel can't keep flowing under
// the old owner. The Tailscale node itself isn't kicked; admins do
// that from the Tailscale admin console.
func (w *webMux) apiAgentDelete(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(rw, "missing ip", 400)
		return
	}
	if w.g.agents != nil {
		w.g.agents.Delete(ip)
	}
	if w.g.onboard != nil {
		w.g.onboard.ForgetIP(ip)
	}
	if globalWG != nil {
		globalWG.RevokePeerByIP(ip)
	}
	writeJSON(rw, map[string]bool{"ok": true})
}

// apiAgentProfile assigns a peer IP to a named profile. Profile must
// be declared in cfg.Profiles. The mapping is persisted in
// onboard.profileByIP and consulted by Gateway.profileFor at MITM
// time, so rule scoping switches over immediately.
func (w *webMux) apiAgentProfile(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	ip := r.URL.Query().Get("ip")
	profile := r.URL.Query().Get("profile")
	if ip == "" || profile == "" {
		http.Error(rw, "missing ip or profile", 400)
		return
	}
	names := orderedProfileNames(w.g.cfg.Load().Policy)
	known := false
	for _, n := range names {
		if n == profile {
			known = true
			break
		}
	}
	if !known {
		http.Error(rw, "unknown profile", 400)
		return
	}
	if bindings, _ := rolesFromContext(r.Context()); !canEditProfile(bindings, profile) {
		http.Error(rw, "editing profile "+profile+" requires editor on that profile", http.StatusForbidden)
		return
	}
	w.g.onboard.AssignProfile(ip, profile)
	writeJSON(rw, map[string]any{"ok": true, "ip": ip, "profile": profile})
}

// apiProfiles lists declared profile names so the dashboard can
// render a profile picker per device.
func (w *webMux) apiProfiles(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, orderedProfileNames(w.g.cfg.Load().Policy))
}

// apiPlugins lists the loaded external plugins with their approved
// permissions and sandbox state for the dashboard's Plugins page.
func (w *webMux) apiPlugins(rw http.ResponseWriter, _ *http.Request) {
	if w.g.pluginMgr == nil {
		writeJSON(rw, []extplugin.PluginInfo{})
		return
	}
	writeJSON(rw, w.g.pluginMgr.PluginInfos())
}

// apiPluginApprove re-records the named plugin's current permissions
// in the lockfile (the dashboard equivalent of `clawpatrol plugins
// approve`), then reloads so a previously-blocked plugin loads. This
// writes clawpatrol.lock.hcl, so committing that file still surfaces
// the approval as a reviewable diff.
func (w *webMux) apiPluginApprove(rw http.ResponseWriter, r *http.Request) {
	if w.g.pluginMgr == nil {
		http.Error(rw, "plugins are not enabled", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(rw, "a plugin name is required", http.StatusBadRequest)
		return
	}
	// Hold configMu across both the approve and the reload: Approve and
	// LoadPlugins (run from the reload path and the file watcher) both
	// touch the shared lock store and the manager's stateDir, so they
	// must not run concurrently. configMu is the gateway-wide serializer
	// for plugin (re)load.
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	specs := w.g.cfg.Load().Plugins
	if _, err := w.g.pluginMgr.Approve(r.Context(), specs, []string{req.Name}); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	// Reload so the now-approved plugin starts immediately instead of
	// waiting for the next file-watch tick.
	if err := w.g.reloadConfigFromFileLocked(w.g.cfgPath); err != nil {
		http.Error(rw, "approved, but reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// RuleSummary is the JSON shape the dashboard renders for each rule.
// It flattens a CompiledRule plus its enclosing endpoint and profile
// context so the table view doesn't need to walk the policy graph
// itself.
type RuleSummary struct {
	Name       string                `json:"name"`
	Family     string                `json:"family"` // "http" | "sql" | "k8s"
	Endpoint   string                `json:"endpoint"`
	Profile    string                `json:"profile,omitempty"`
	Priority   int                   `json:"priority,omitempty"`
	Disabled   bool                  `json:"disabled,omitempty"`
	Condition  string                `json:"condition,omitempty"`
	Credential string                `json:"credential,omitempty"`
	Verdict    string                `json:"verdict,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	Approve    []config.ApproveStage `json:"approve,omitempty"`
}

// apiRules returns every compiled rule across every profile, flattened
// for the dashboard table view. Rules attached to multiple endpoints
// emit one row per endpoint so the operator sees each attachment
// site individually.
//
// Read-only. Dashboard edits go through the whole-file gateway.hcl
// preview/save flow so operators review the formatted diff before the
// typed-block validator persists changes.
func (w *webMux) apiRules(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(rw, w.collectRuleSummaries(""))
	default:
		http.Error(rw, "edit rules through the gateway.hcl preview/save flow", http.StatusNotImplemented)
	}
}

// collectRuleSummaries walks the compiled policy and emits one
// RuleSummary per (rule × endpoint × profile) triple. When profile is
// empty, every profile contributes; otherwise only that profile.
//
// Sort: by profile, then endpoint, then descending priority (so the
// dashboard mirrors first-match-wins order within each endpoint).
func (w *webMux) collectRuleSummaries(profileFilter string) []RuleSummary {
	policy := w.g.Policy()
	if policy == nil {
		return []RuleSummary{}
	}
	var out []RuleSummary
	for profileName, prof := range policy.Profiles {
		if profileFilter != "" && profileName != profileFilter {
			continue
		}
		for epName, ep := range prof.Endpoints {
			for _, r := range ep.Rules {
				out = append(out, RuleSummary{
					Name:       r.Name,
					Family:     ep.Family,
					Endpoint:   epName,
					Profile:    profileName,
					Priority:   r.Priority,
					Disabled:   r.Disabled,
					Condition:  r.Condition,
					Credential: r.Credential,
					Verdict:    r.Outcome.Verdict,
					Reason:     r.Outcome.Reason,
					Approve:    r.Outcome.Approve,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Priority > out[j].Priority
	})
	return out
}
