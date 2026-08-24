package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/denoland/clawpatrol/dashboard"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

var loginTpl = template.Must(template.New("login").Parse(dashboard.LoginHTML))

type webMux struct {
	g         *Gateway
	ts        JoinConfig // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry
	routeAuth map[string]authRequirement

	// stateCache: per-caller TTL'd memo for /api/state. RWMutex
	// because reads vastly outnumber writes — every dashboard tab
	// polls every 5s, but the cached entry only refreshes once per
	// stateCacheTTL (1s). 99% of polls are RLock-only.
	stateCacheMu sync.RWMutex
	stateCache   map[string]stateCacheEntry
}

type dashboardBranding struct {
	Name    string `json:"name"`
	LogoURL string `json:"logo_url"`
	IconURL string `json:"icon_url"`
}

type authRequirement int

const (
	// authDashboard routes require the configured dashboard secret before
	// they can reach the handler. In Tailscale control mode, the existing
	// tailnet gate still runs after dashboard auth.
	authDashboard authRequirement = iota
	// authPublic routes are intentionally reachable before any dashboard
	// or tailnet identity exists.
	authPublic
	// authTailnetOperator routes skip dashboard-secret auth but are still
	// protected by tailnet identity when Tailscale control mode is active.
	authTailnetOperator
	// authDashboardOrTailnetOperator accepts dashboard auth everywhere and
	// may defer to tailnet identity in Tailscale control mode. In WireGuard
	// / proxy mode there is no tailnet identity, so dashboard auth remains
	// mandatory.
	authDashboardOrTailnetOperator
	// authSelfAuthenticating routes carry their own request-level proof
	// (for example a bearer token or webhook signature), so they do not
	// require the dashboard secret. Existing tailnet-gate behavior is kept.
	authSelfAuthenticating
)

type webRoute struct {
	Method  string
	Path    string
	Auth    authRequirement
	Handler http.HandlerFunc
}

type principalKind string

const (
	principalDashboardPassword principalKind = "dashboard_password"
	principalTailnet           principalKind = "tailnet"
)

type principal struct {
	Kind   principalKind
	Owner  string
	User   string
	Device string
	Host   string
}

type principalContextKey struct{}

func contextWithPrincipal(ctx context.Context, p principal) context.Context {
	if p.Owner == "" {
		p.Owner = p.User
	}
	return context.WithValue(ctx, principalContextKey{}, p)
}

func principalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(principal)
	if !ok || p.Owner == "" {
		return principal{}, false
	}
	return p, true
}

func (w *webMux) dashboardPasswordPrincipal() principal {
	return principal{Kind: principalDashboardPassword, Owner: dashboardRootUsername}
}

func routeAuthIndex(routes []webRoute) map[string]authRequirement {
	out := make(map[string]authRequirement, len(routes))
	for _, route := range routes {
		out[route.Path] = route.Auth
	}
	return out
}

func (w *webMux) authRequirementForPath(path string) authRequirement {
	if strings.HasPrefix(path, credentialWebhookPrefix) || strings.HasPrefix(path, hitlOperationStatusPrefix) {
		return authSelfAuthenticating
	}
	if w.routeAuth != nil {
		if req, ok := w.routeAuth[path]; ok {
			return req
		}
	}
	// The login page is authPublic — its assets must be too, or the
	// browser would chase /claw-patrol-logo.svg through dashboardAuthGate,
	// land on an HTML redirect, and render a broken-image icon on every
	// logged-out visit.
	if isLoginPageAsset(path) {
		return authPublic
	}
	return authDashboard
}

// isLoginPageAsset matches the exact set of static assets the login
// page (www/login.html) loads while the user is unauthenticated:
// favicon, logo, and the woff2 font subset. Anything else under /
// stays gated.
func isLoginPageAsset(path string) bool {
	switch path {
	case "/claw-patrol-icon.svg", "/claw-patrol-logo.svg":
		return true
	}
	return strings.HasPrefix(path, "/fonts/")
}

// skipsDashboardPassword returns true for routes whose handlers
// provide their own authentication (credential webhook signatures,
// peer API tokens) or are intentionally open (/info, /ca.crt,
// onboarding handshakes). For these, the dashboard gate does not
// require the cookie.
func (w *webMux) skipsDashboardPassword(path string) bool {
	switch w.authRequirementForPath(path) {
	case authPublic, authTailnetOperator, authSelfAuthenticating:
		return true
	default:
		return false
	}
}

func (w *webMux) mayUseTailnetInsteadOfDashboard(path string) bool {
	return w.authRequirementForPath(path) == authDashboardOrTailnetOperator &&
		w.g.cfg.Load().IsTailscaleEnabled()
}

func (w *webMux) skipsTailnetGate(path string) bool {
	req := w.authRequirementForPath(path)
	// authPublic needs no gate. authSelfAuthenticating routes carry their
	// own proof (Bearer token, webhook signature) — the tailnet gate would
	// block tag:client devices that have no Tailscale user identity.
	return req == authPublic || req == authSelfAuthenticating
}

func newWebMux(g *Gateway, ts JoinConfig, publicURL string) http.Handler {
	w := &webMux{g: g, ts: ts, publicURL: publicURL, sessions: map[string]*oauthSession{}, onboard: g.onboard}
	return w.handler()
}

func (w *webMux) handler() http.Handler {
	mux := http.NewServeMux()
	routes := w.routes()
	w.routeAuth = routeAuthIndex(routes)
	for _, route := range routes {
		if route.Method == "" {
			panic("web route missing method: " + route.Path)
		}
		mux.HandleFunc(route.Path, route.Handler)
	}
	w.mountCredentialWebhooks(mux)
	mux.Handle("/", w.staticHandler())
	return w.dashboardAuthGate(w.tailnetGate(mux))
}

func (w *webMux) routes() []webRoute {
	return []webRoute{
		{Method: http.MethodGet, Path: "/info", Auth: authPublic, Handler: w.serveInfo},
		{Method: http.MethodGet, Path: "/ca.crt", Auth: authPublic, Handler: w.serveCA},
		// /api/whoami + /api/agents are gone — superseded by /api/state.
		// /api/status stays because DevicePage scopes it with ?profile=.
		{Method: http.MethodGet, Path: "/api/status", Auth: authDashboard, Handler: w.apiStatus},
		// /api/state is the dashboard's single-call refresh endpoint —
		// bundles whoami+status+agents in one round-trip and returns 304
		// when the JSON hash matches If-None-Match. Replaces the three
		// parallel per-3s fetches App.refresh used to fire.
		{Method: http.MethodGet, Path: "/api/state", Auth: authDashboard, Handler: w.apiState},
		{Method: http.MethodPost, Path: "/api/agents/delete", Auth: authDashboard, Handler: w.apiAgentDelete},
		{Method: http.MethodPost, Path: "/api/agents/profile", Auth: authDashboard, Handler: w.apiAgentProfile},
		{Method: http.MethodGet, Path: "/api/profiles", Auth: authDashboard, Handler: w.apiProfiles},
		{Method: http.MethodGet, Path: "/api/plugins", Auth: authDashboard, Handler: w.apiPlugins},
		{Method: http.MethodPost, Path: "/api/plugins/approve", Auth: authDashboard, Handler: w.apiPluginApprove},
		{Method: http.MethodGet, Path: "/api/rules", Auth: authDashboard, Handler: w.apiRules},
		{Method: http.MethodGet, Path: "/api/config", Auth: authDashboard, Handler: w.apiConfig},
		{Method: http.MethodPost, Path: "/api/config/apply", Auth: authDashboard, Handler: w.apiConfigApply},
		{Method: http.MethodGet, Path: "/api/hitl/pending", Auth: authDashboard, Handler: w.apiHITLPending},
		{Method: http.MethodPost, Path: "/api/hitl/decide", Auth: authDashboard, Handler: w.apiHITLDecide},
		{Method: http.MethodGet, Path: hitlOperationStatusPrefix, Auth: authSelfAuthenticating, Handler: w.apiHITLOperationStatus},
		{Method: http.MethodPost, Path: "/api/oauth/start", Auth: authDashboard, Handler: w.apiOAuthStart},
		{Method: http.MethodPost, Path: "/api/oauth/exchange", Auth: authDashboard, Handler: w.apiOAuthExchange},
		{Method: http.MethodPost, Path: "/api/oauth/device-poll", Auth: authDashboard, Handler: w.apiOAuthDevicePoll},
		{Method: http.MethodPost, Path: "/api/oauth/revoke", Auth: authDashboard, Handler: w.apiOAuthRevoke},
		{Method: http.MethodGet, Path: "/oauth/callback", Auth: authDashboard, Handler: w.serveOAuthCallback},
		{Method: http.MethodPost, Path: "/api/tailscale/connect", Auth: authDashboard, Handler: w.apiTailscaleConnect},
		{Method: http.MethodGet, Path: "/api/tailscale/status", Auth: authDashboard, Handler: w.apiTailscaleStatus},
		{Method: http.MethodPost, Path: "/api/tailscale/disconnect", Auth: authDashboard, Handler: w.apiTailscaleDisconnect},
		{Method: http.MethodPost, Path: "/api/credentials/set", Auth: authDashboard, Handler: w.apiCredentialsSet},
		{Method: http.MethodPost, Path: "/api/credentials/clear", Auth: authDashboard, Handler: w.apiCredentialsClear},
		{Method: http.MethodGet, Path: "/api/events", Auth: authDashboard, Handler: w.apiEventsSSE},
		{Method: http.MethodPost, Path: "/api/actions/rule-preview", Auth: authDashboard, Handler: w.apiActionRulePreview},
		{Method: http.MethodPost, Path: "/api/actions/", Auth: authDashboard, Handler: w.apiActionByID},
		{Method: http.MethodGet, Path: "/api/analytics", Auth: authDashboard, Handler: w.apiAnalytics},
		{Method: http.MethodGet, Path: "/api/facets", Auth: authDashboard, Handler: w.apiFacets},
		{Method: http.MethodPost, Path: "/api/onboard/start", Auth: authPublic, Handler: w.apiOnboardStart},
		{Method: http.MethodPost, Path: "/api/onboard/poll", Auth: authPublic, Handler: w.apiOnboardPoll},
		{Method: http.MethodPost, Path: "/api/onboard/approve", Auth: authDashboardOrTailnetOperator, Handler: w.apiOnboardApprove},
		{Method: http.MethodGet, Path: "/api/onboard/lookup", Auth: authTailnetOperator, Handler: w.apiOnboardLookup},
		{Method: http.MethodPost, Path: "/api/onboard/claim", Auth: authPublic, Handler: w.apiOnboardClaim},
		{Method: http.MethodGet, Path: "/api/env-pushdown", Auth: authSelfAuthenticating, Handler: w.apiEnvPushdown},
		{Method: http.MethodPost, Path: "/api/peer/tsnet/register", Auth: authSelfAuthenticating, Handler: w.apiPeerTsnetRegister},
		// /__login is the auth point itself — it MUST be reachable
		// without a credential. The handler dispatches on r.Method
		// (GET renders the form, POST validates + mints a session
		// cookie), and dashboardAuthGate further restricts it to
		// first-run mode when no root row exists. SameSite=Lax on
		// the cp_session cookie blocks cross-site CSRF on the POST.
		{Method: http.MethodGet, Path: "/__login", Auth: authPublic, Handler: w.apiDashboardLogin},
		// /__logout revokes the session row + clears the cookie. The
		// gate still applies — only an authenticated caller can log
		// out (tailnet-allowlisted callers get 401 because there's no
		// session to clear; the dashboard SPA disables the button for
		// them rather than calling this endpoint).
		{Method: http.MethodPost, Path: "/__logout", Auth: authDashboard, Handler: w.apiDashboardLogout},
	}
}

// dashboardAuthGate requires every non-public request to carry a
// valid dashboard credential. Two methods are accepted:
//
//   - cookie `cp_dash` (or header `X-Clawpatrol-Secret`) holding the
//     password, bcrypt-checked against the root row in dashboard_users;
//   - in tailscale-control mode, a tsnet whois login that matches an
//     entry in cfg.DashboardOperators. The actual whois resolution
//     happens downstream in tailnetGate; this gate only decides that
//     the request is allowed to reach the tailnet check.
//
// When no root row exists (fresh install), every protected request is
// redirected to /__login, which renders the first-run "set password"
// form. The dashboard cannot serve any management endpoint until a
// password is set, so credentials / profile state can never be
// created before there is an operator to protect them. See
// doc/security-model.md for the full trust statement.
//
// credentialWebhookPrefix is the path prefix every plugin webhook
// route mounts under. Public — credential plugins authenticate
// callbacks via their own signature header (Slack signing secret,
// etc.) so this gate skips the prefix entirely.
const credentialWebhookPrefix = "/api/cred/"

const (
	hitlOperationStatusPrefix       = "/api/hitl/operations/"
	hitlOperationStatusSuffix       = "/status"
	hitlRetryOperationHeader        = "Clawpatrol-HITL-Operation"
	hitlDefaultRetryAfterSeconds    = 5
	hitlOperationNotFoundErrorValue = "hitl_operation_not_found"
)

// cpSessionCookieName holds an opaque, server-issued session token —
// random 256 bits, never derived from the password. The cookie is
// HttpOnly + SameSite=Lax. The DB only stores its SHA-256, so a DB
// leak doesn't grant access. Replaces the older cp_dash cookie that
// stored the raw password.
const cpSessionCookieName = "cp_session"

// dashboardSessionTTL resolves the configured session TTL or falls
// back to the default. Validator catches bad strings at load time;
// the duplicate parse here is so a hot-reloaded config can change
// the TTL without restarting.
func (w *webMux) dashboardSessionTTL() time.Duration {
	d, err := config.DashboardSessionTTLFromString(w.g.cfg.Load().DashboardSessionTTL())
	if err != nil {
		// Validator at config load would have caught this; defensive
		// fallback to the default keeps a hot-reload typo from
		// breaking the login flow.
		return config.DefaultDashboardSessionTTL
	}
	return d
}

func (w *webMux) dashboardBranding() dashboardBranding {
	cfg := w.g.cfg.Load()
	if cfg == nil {
		return dashboardBranding{
			Name:    config.DefaultDashboardName,
			LogoURL: config.DefaultDashboardLogoURL,
			IconURL: config.DefaultDashboardIconURL,
		}
	}
	return dashboardBranding{
		Name:    cfg.DashboardName(),
		LogoURL: cfg.DashboardLogoURL(),
		IconURL: cfg.DashboardIconURL(),
	}
}

func (w *webMux) dashboardAuthGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// /info, /ca.crt, /api/onboard/{start,poll,claim} stay open
		// for brand-new clients that don't have any credential yet.
		if w.skipsDashboardPassword(path) {
			next.ServeHTTP(rw, r)
			return
		}

		// First-run gate: until a root row exists, every protected
		// request redirects to /__login (which renders the "set
		// password" form). API callers see 401 with a hint.
		_, rootExists, err := lookupDashboardUser(w.g.db, dashboardRootUsername)
		if err != nil {
			http.Error(rw, "dashboard auth lookup failed", http.StatusServiceUnavailable)
			return
		}
		if !rootExists {
			if path == dashboardLoginPath {
				next.ServeHTTP(rw, r)
				return
			}
			if strings.HasPrefix(path, "/api/") {
				http.Error(rw, "dashboard not initialized — open the dashboard and set a password, or run `clawpatrol gateway --set-dashboard-password <pw>`", http.StatusUnauthorized)
				return
			}
			http.Redirect(rw, r, dashboardLoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}

		// Session-cookie path: look up the cookie's token-hash in
		// the dashboard_sessions table. Hit → inject the password
		// principal so tailnetGate downstream short-circuits.
		if username := w.lookupSessionFromRequest(r); username != "" {
			next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), w.dashboardPasswordPrincipal())))
			return
		}

		// Tailnet allowlist path: defer to tailnetGate so it can
		// resolve the whois identity and compare against the
		// configured operators allowlist. Only relevant when the
		// `tailscale {}` block is enabled — without it there's no
		// whois identity to resolve.
		if w.g.cfg.Load().IsTailscaleEnabled() && len(w.g.cfg.Load().Operators()) > 0 {
			next.ServeHTTP(rw, r)
			return
		}

		// /api/onboard/approve in tailscale-control mode is a
		// dual-path route (any tailnet operator can approve), so
		// pass it through to tailnetGate even without a configured
		// allowlist.
		if w.mayUseTailnetInsteadOfDashboard(path) {
			next.ServeHTTP(rw, r)
			return
		}

		// API callers see 401; browsers get redirected to the login form.
		if strings.HasPrefix(path, "/api/") {
			http.Error(rw, "dashboard session required", http.StatusUnauthorized)
			return
		}
		http.Redirect(rw, r, dashboardLoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// dashboardLoginPath is the unauthenticated login + first-run setup
// endpoint. Single route to keep the auth surface small.
const dashboardLoginPath = "/__login"

// lookupSessionFromRequest reads the cp_session cookie, looks up the
// matching row, and returns the username on a live hit. Empty string
// when missing/expired/error (the gate treats all three as "no
// session, redirect to login").
func (w *webMux) lookupSessionFromRequest(r *http.Request) string {
	c, err := r.Cookie(cpSessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	username, ok, err := lookupDashboardSession(w.g.db, c.Value)
	if err != nil || !ok {
		return ""
	}
	return username
}

func safeDashboardLoginNext(next string) string {
	if next == "" || strings.Contains(next, "\\") || strings.HasPrefix(next, "//") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return next
}

// apiDashboardLogin serves /__login. Two modes, switched on whether
// the root row exists:
//
//   - first-run (GET): render the "set password" form (two fields).
//     POST: validate password == confirm, length >= 12, upsert root,
//     mint a session, set cookie, redirect.
//   - steady-state (GET): render the "enter password" form.
//     POST: bcrypt-verify, mint a session, set cookie, redirect.
func (w *webMux) apiDashboardLogin(rw http.ResponseWriter, r *http.Request) {
	next := safeDashboardLoginNext(r.URL.Query().Get("next"))
	_, rootExists, err := lookupDashboardUser(w.g.db, dashboardRootUsername)
	if err != nil {
		http.Error(rw, "dashboard auth lookup failed", http.StatusServiceUnavailable)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(rw, "bad form", http.StatusBadRequest)
			return
		}
		password := r.PostFormValue("password")
		if !rootExists {
			confirm := r.PostFormValue("confirm")
			if len(password) < dashboardMinPasswordLen {
				w.renderLogin(rw, next, fmt.Sprintf("password must be at least %d characters", dashboardMinPasswordLen), true, http.StatusBadRequest)
				return
			}
			if password != confirm {
				w.renderLogin(rw, next, "passwords do not match", true, http.StatusBadRequest)
				return
			}
			if err := setDashboardUser(w.g.db, dashboardRootUsername, password); err != nil {
				log.Printf("set dashboard root password: %v", err)
				http.Error(rw, "could not store password", http.StatusInternalServerError)
				return
			}
			log.Printf("dashboard auth: root password initialized via /__login first-run flow")
			if err := w.mintAndSetSessionCookie(rw, dashboardRootUsername); err != nil {
				http.Error(rw, "could not mint session", http.StatusInternalServerError)
				return
			}
			http.Redirect(rw, r, next, http.StatusFound)
			return
		}
		ok, _, err := checkDashboardPassword(w.g.db, dashboardRootUsername, password)
		if err != nil {
			http.Error(rw, "dashboard auth check failed", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			w.renderLogin(rw, next, "wrong password", false, http.StatusUnauthorized)
			return
		}
		if err := w.mintAndSetSessionCookie(rw, dashboardRootUsername); err != nil {
			http.Error(rw, "could not mint session", http.StatusInternalServerError)
			return
		}
		http.Redirect(rw, r, next, http.StatusFound)
		return
	}
	w.renderLogin(rw, next, "", !rootExists, http.StatusOK)
}

// apiDashboardLogout revokes the cp_session cookie (server- and
// client-side) and redirects to /__login. Idempotent — POSTing
// without a cookie clears nothing and still 200s. GET / non-tailnet
// callers without a session land here too via the gate; the cookie
// clear is harmless in those cases.
func (w *webMux) apiDashboardLogout(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(cpSessionCookieName); err == nil && c.Value != "" {
		if err := revokeDashboardSession(w.g.db, c.Value); err != nil {
			log.Printf("revoke dashboard session: %v", err)
		}
	}
	// Clear the cookie regardless of whether the row existed — the
	// browser may have a stale value and we want it gone.
	http.SetCookie(rw, &http.Cookie{
		Name:     cpSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	rw.WriteHeader(http.StatusOK)
}

// dashboardMinPasswordLen is the minimum length enforced at password
// set time. 12 chars is the OWASP-recommended floor for human-chosen
// passwords; the CLI flag enforces the same limit.
const dashboardMinPasswordLen = 12

// mintAndSetSessionCookie creates a row in dashboard_sessions for
// username, then writes the raw token to the cp_session cookie. The
// cookie's Max-Age matches the configured TTL — same window the
// server-side row enforces — so the browser stops sending it the
// moment the server stops accepting it.
func (w *webMux) mintAndSetSessionCookie(rw http.ResponseWriter, username string) error {
	ttl := w.dashboardSessionTTL()
	token, err := createDashboardSession(w.g.db, username, ttl)
	if err != nil {
		log.Printf("create dashboard session: %v", err)
		return err
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     cpSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	return nil
}

func (w *webMux) renderLogin(rw http.ResponseWriter, next, errMsg string, firstRun bool, status int) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	_ = loginTpl.Execute(rw, struct {
		Next     string
		Error    string
		FirstRun bool
		Branding dashboardBranding
	}{next, errMsg, firstRun, w.dashboardBranding()})
}

// tailnetGate runs downstream of dashboardAuthGate. Three jobs:
//
//   - For routes the upstream gate already authenticated (password
//     cookie verified), let the request pass with its injected
//     principal.
//   - For authTailnetOperator / authDashboardOrTailnetOperator
//     routes, attribute a principal from the tsnet whois identity
//     ("any tailnet member, just identify them").
//   - For authDashboard routes that fall through here (because the
//     password cookie was missing and DashboardOperators is
//     configured), require that the whois login matches the
//     operator allowlist. This is the path that lets a deployed
//     "alice@example.com" operator hit the dashboard with no
//     password while keeping every other tailnet peer — including
//     tagged agent devices — locked out.
//
// In wireguard / proxy mode there is no tsnet whois at all; the
// gate is skipped and dashboardAuthGate's password requirement is
// the only auth.
func (w *webMux) tailnetGate(next http.Handler) http.Handler {
	skipGate := !w.g.cfg.Load().IsTailscaleEnabled()

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.skipsTailnetGate(r.URL.Path) || skipGate {
			next.ServeHTTP(rw, r)
			return
		}
		// Upstream password gate already authenticated → keep the
		// dashboard principal it injected.
		if _, ok := principalFromContext(r.Context()); ok {
			next.ServeHTTP(rw, r)
			return
		}
		// Two ways to prove tailnet membership:
		//   1. peer IP whois (direct tailnet → gateway, no proxy).
		//   2. Tailscale-User-Login header from `tailscale serve` —
		//      ONLY trusted when the proxy hop is local (127.0.0.1 /
		//      ::1). Anyone hitting us via funnel can otherwise forge
		//      the header trivially.
		host := r.RemoteAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		var login, device, displayHost string
		if w.g.agents != nil {
			if who := w.g.agents.lookupWhois(host); who != nil {
				login = who.UserProfile.LoginName
				device = who.Node.StableID
				displayHost = who.Node.HostName
			}
		}
		if login == "" && isLoopback(host) {
			// `tailscale serve` proxy hop. The header is authoritative
			// here because nothing public can reach loopback.
			login = r.Header.Get("Tailscale-User-Login")
			displayHost = host
		}
		if login == "" {
			http.Error(rw, "tailnet access required — onboard via `clawpatrol join <gateway>`", http.StatusForbidden)
			return
		}
		// Operator-class routes — approving onboarding devices, looking
		// up pending user_codes, reading the dashboard via tailnet
		// identity — must require an explicit dashboard_operators
		// allowlist match for the tailnet identity path. Previously
		// authTailnetOperator and authDashboardOrTailnetOperator
		// accepted any non-empty whois, which let tag:client peers
		// (whois == "tagged-devices") call /api/onboard/approve and
		// mint fresh auth keys bound to arbitrary profiles — see
		// issue #509. MatchDashboardOperator only accepts "user@domain"
		// or "*@domain" entries, so "tagged-devices" and "tagged-*"
		// stubs fail closed by construction.
		//
		// The dashboard-password path is unaffected: requests carrying
		// a valid cp_session cookie have their principal injected by
		// dashboardAuthGate upstream and short-circuit this gate at
		// the principalFromContext check above.
		if needsOperatorGate(w.authRequirementForPath(r.URL.Path)) {
			if !config.MatchDashboardOperator(login, w.g.cfg.Load().Operators()) {
				http.Error(rw, "operator routes require a dashboard password session or a tailnet login matching the operators allowlist", http.StatusForbidden)
				return
			}
		}
		principal := principal{Kind: principalTailnet, Owner: login, User: login, Device: device, Host: displayHost}
		next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), principal)))
	})
}

// needsOperatorGate reports whether req requires the caller to be an
// operator — either a dashboard-password session or a tailnet login
// matching dashboard_operators. Every non-public, non-self-auth
// route is operator-class in the daemon-model gateway, because all
// of them either expose internal state or accept profile-affecting
// writes. The dashboard-password path is handled separately by
// dashboardAuthGate; this only applies on the tailnet-identity path.
func needsOperatorGate(req authRequirement) bool {
	switch req {
	case authDashboard, authTailnetOperator, authDashboardOrTailnetOperator:
		return true
	}
	return false
}

// mountCredentialWebhooks walks every credential whose body
// implements runtime.WebhookProvider and mounts each declared route
// under /api/cred/<credName>/<route.Path>. Future plugins (Discord,
// Telegram, generic webhook) plug in by implementing WebhookRoutes()
// — main needs no plugin-specific path table.
func (w *webMux) mountCredentialWebhooks(mux *http.ServeMux) {
	policy := w.g.Policy()
	if policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		provider, ok := ent.Body.(runtime.WebhookProvider)
		if !ok {
			continue
		}
		credName := name
		for _, route := range provider.WebhookRoutes() {
			path := credentialWebhookPrefix + credName + route.Path
			handler := route.Handler
			mux.HandleFunc(path, func(rw http.ResponseWriter, r *http.Request) {
				ctx := runtime.WebhookCtx{
					CredentialName: credName,
					Secrets:        w.g.secrets,
					HITL:           w.g.hitl,
					Policy:         w.g.Policy(),
				}
				handler(ctx, rw, r)
			})
		}
	}
}

// apiEnvPushdown returns the env-var push-down list assembled from
// the gateway's currently-loaded policy, scoped to the calling
// peer's profile. Clients (`clawpatrol env`, `clawpatrol run`)
// fetch this instead of iterating their own compiled-in plugin
// set, so the binary on the client doesn't have to track which
// endpoint plugins the operator has enabled on the gateway.
//
// Auth: requires `Authorization: Bearer <token>` where <token>
// matches a row in peer_api_tokens. The token was minted for the
// caller at onboard-approve time and persisted next to ca.crt by
// `clawpatrol join`. Only the (name, value, description,
// plugin_type) bytes for plugins reachable from the peer's
// profile are returned; CA-bundle vars stay client-side because
// they reference a path on the *client's* disk.
func (w *webMux) apiEnvPushdown(rw http.ResponseWriter, r *http.Request) {
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	peerIP := peerIPForAPIToken(w.g.db, token)
	if peerIP == "" {
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
		return
	}
	profileName := w.g.profileFor(peerIP)
	policy := w.g.Policy()
	if policy == nil {
		writeJSON(rw, map[string]any{"vars": []any{}})
		return
	}
	prof, ok := policy.Profiles[profileName]
	if !ok || prof == nil {
		writeJSON(rw, map[string]any{"vars": []any{}})
		return
	}

	out := []map[string]string{}
	seen := map[string]bool{}
	add := func(name, value, description, pluginType string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, map[string]string{
			"name":        name,
			"value":       value,
			"description": description,
			"plugin_type": pluginType,
		})
	}
	credSeen := map[string]bool{}
	// Endpoints in this profile, plus the credentials they bind.
	// Credentials are emitted first (so credential-shaped
	// placeholders win on duplicate names), endpoints second.
	for _, ep := range prof.Endpoints {
		for _, ent := range ep.Credentials {
			if ent == nil || ent.Symbol == nil || credSeen[ent.Symbol.Name] {
				continue
			}
			credSeen[ent.Symbol.Name] = true
			provider, ok := ent.Body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				add(ev.Name, ev.Value, ev.Description, ent.Plugin.Type)
			}
		}
	}
	for _, ep := range prof.Endpoints {
		provider, ok := ep.Body.(config.EnvPushdownProvider)
		if !ok {
			continue
		}
		for _, ev := range provider.EnvVars() {
			add(ev.Name, ev.Value, ev.Description, ep.Plugin.Type)
		}
	}
	writeJSON(rw, map[string]any{"vars": out})
}

func (w *webMux) apiHITLOperationStatus(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, http.MethodGet, http.StatusMethodNotAllowed)
		return
	}
	store := NewHITLOperationStore(w.g.db)
	var op HITLOperation
	var err error
	statusToken := r.URL.Query().Get("token")
	if statusToken != "" {
		operationID, ok := hitlOperationIDFromStatusPath(r.URL.Path)
		if !ok {
			writeHITLOperationNotFound(rw)
			return
		}
		op, err = store.GetForStatusToken(r.Context(), operationID, statusToken)
		if err == nil {
			op.StatusToken = statusToken
		} else if !errors.Is(err, ErrHITLOperationNotFound) {
			log.Printf("hitl operation status %s: %v", operationID, err)
			http.Error(rw, "failed to load HITL operation", http.StatusInternalServerError)
			return
		} else if bearerFromAuthHeader(r.Header.Get("Authorization")) == "" {
			writeHITLOperationNotFound(rw)
			return
		}
	}
	if op.ID == "" {
		if isFunnelPublicRequest(r.Context()) {
			writeHITLOperationNotFound(rw)
			return
		}
		token := bearerFromAuthHeader(r.Header.Get("Authorization"))
		peerIP := peerIPForAPIToken(w.g.db, token)
		if peerIP == "" {
			http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
			return
		}
		operationID, ok := hitlOperationIDFromStatusPath(r.URL.Path)
		if !ok {
			writeHITLOperationNotFound(rw)
			return
		}
		profileID := w.g.profileFor(peerIP)
		principalID := hitlPeerPrincipalID(peerIP)
		op, err = store.GetForPrincipal(r.Context(), operationID, profileID, principalID)
	}
	if errors.Is(err, ErrHITLOperationNotFound) {
		writeHITLOperationNotFound(rw)
		return
	}
	if err != nil {
		http.Error(rw, "load hitl operation", http.StatusInternalServerError)
		return
	}
	writeHITLOperationStatus(rw, op, w.hitlPublicURL())
}

func (w *webMux) hitlPublicURL() string {
	// Prefer the live config — public_url may be auto-derived from the
	// tsnet Funnel cert AFTER webMux is constructed.
	if w.g != nil {
		if cfg := w.g.cfg.Load(); cfg != nil && cfg.PublicURL() != "" {
			return cfg.PublicURL()
		}
	}
	return w.publicURL
}

func hitlOperationIDFromStatusPath(path string) (string, bool) {
	if !strings.HasPrefix(path, hitlOperationStatusPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(path, hitlOperationStatusPrefix)
	if !strings.HasSuffix(rest, hitlOperationStatusSuffix) {
		return "", false
	}
	rawID := strings.TrimSuffix(rest, hitlOperationStatusSuffix)
	if rawID == "" || strings.Contains(rawID, "/") {
		return "", false
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func hitlPeerPrincipalID(peerIP string) string {
	return "peer:" + peerIP
}

func writeHITLOperationAccepted(rw http.ResponseWriter, op HITLOperation, publicURL string) {
	statusURL := hitlOperationStatusURL(publicURL, op.ID, op.StatusToken)
	rw.Header().Set("Location", statusURL)
	rw.Header().Set("Retry-After", strconv.Itoa(hitlDefaultRetryAfterSeconds))
	writeHITLOperationResponse(rw, http.StatusAccepted, op, statusURL)
}

func writeHITLOperationStatus(rw http.ResponseWriter, op HITLOperation, publicURL string) {
	statusURL := hitlOperationStatusURL(publicURL, op.ID, op.StatusToken)
	writeHITLOperationResponse(rw, http.StatusOK, op, statusURL)
}

func writeHITLOperationResponse(rw http.ResponseWriter, status int, op HITLOperation, statusURL string) {
	upstreamCalled := hitlOperationUpstreamCalled(op)
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Clawpatrol-HITL-State", string(op.State))
	rw.Header().Set("Clawpatrol-Upstream-Called", strconv.FormatBool(upstreamCalled))
	if op.State == HITLOperationStatePendingApproval || op.State == HITLOperationStateSyncWaiting {
		rw.Header().Set("Retry-After", strconv.Itoa(hitlDefaultRetryAfterSeconds))
	}
	body := hitlOperationStatusBody(op, statusURL, upstreamCalled)
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}

func hitlOperationStatusBody(op HITLOperation, statusURL string, upstreamCalled bool) map[string]any {
	body := map[string]any{
		"operation_id":    op.ID,
		"state":           string(op.State),
		"status_url":      statusURL,
		"upstream_called": upstreamCalled,
		"terminal":        isTerminalHITLOperationState(op.State),
		"message":         hitlOperationStatusMessage(op.State),
	}

	switch op.State {
	case HITLOperationStateSyncWaiting, HITLOperationStatePendingApproval:
		body["poll_operation_status"] = true
		if !op.ApprovalExpiresAt.IsZero() {
			body["approval_expires_at"] = op.ApprovalExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	case HITLOperationStateApprovedWaitingForRetry:
		body["retry_original_request"] = true
		body["retry_header_name"] = hitlRetryOperationHeader
		body["retry_header_value"] = op.ID
		if op.RetryExpiresAt != nil {
			body["retry_expires_at"] = op.RetryExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	case HITLOperationStateExpired:
		if op.ExpiredReason != "" {
			body["expired_reason"] = op.ExpiredReason
		}
	case HITLOperationStateUpstreamSucceeded, HITLOperationStateUpstreamFailed:
		if op.TerminalAt != nil {
			body["completed_at"] = op.TerminalAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return body
}

func hitlOperationStatusMessage(state HITLOperationState) string {
	switch state {
	case HITLOperationStateSyncWaiting:
		return "This request is waiting for human approval. Claw Patrol has not called the upstream service yet."
	case HITLOperationStatePendingApproval:
		return "This request is waiting for human approval. Claw Patrol has not called the upstream service, so no upstream side effect has been executed. Poll status_url until the state changes. If the state becomes approved_waiting_for_retry, retry the same original request with Clawpatrol-HITL-Operation before retry_expires_at."
	case HITLOperationStateApprovedWaitingForRetry:
		return "Human approval has been granted. Claw Patrol has not called upstream yet. Retry the same original request with Clawpatrol-HITL-Operation before retry_expires_at to execute it."
	case HITLOperationStateDenied:
		return "Human approval was denied. Claw Patrol did not call upstream."
	case HITLOperationStateExpired:
		return "Human approval or retry time expired. Claw Patrol did not call upstream."
	case HITLOperationStateExecutingUpstream:
		return "The approved retry is being forwarded upstream now."
	case HITLOperationStateUpstreamSucceeded:
		return "The approved request completed upstream."
	case HITLOperationStateUpstreamFailed:
		return "The approved retry reached the forwarding attempt, but Claw Patrol could not confirm success."
	case HITLOperationStateClientDisconnected:
		return "The original client connection closed before Claw Patrol could return an async polling handle. Upstream was not called."
	default:
		return "HITL operation status is available."
	}
}

func hitlOperationUpstreamCalled(op HITLOperation) bool {
	if op.UpstreamCalled {
		return true
	}
	switch op.State {
	case HITLOperationStateExecutingUpstream, HITLOperationStateUpstreamSucceeded, HITLOperationStateUpstreamFailed:
		return true
	default:
		return false
	}
}

func hitlOperationStatusURL(publicURL, operationID, statusToken string) string {
	base := strings.TrimRight(publicURL, "/")
	path := hitlOperationStatusPrefix + url.PathEscape(operationID) + hitlOperationStatusSuffix
	if statusToken != "" {
		path += "?token=" + url.QueryEscape(statusToken)
	}
	if base == "" {
		return path
	}
	return base + path
}

func writeHITLOperationNotFound(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(rw).Encode(map[string]any{"error": hitlOperationNotFoundErrorValue})
}

func (w *webMux) staticHandler() http.Handler {
	sub, err := fs.Sub(dashboard.DistFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "dashboard not built (cd dashboard && npm run build)", 500)
		})
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.serveDashboardIndex(rw, r, sub)
			return
		}
		files.ServeHTTP(rw, r)
	})
}

func (w *webMux) serveDashboardIndex(rw http.ResponseWriter, r *http.Request, dist fs.FS) {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.Error(rw, "dashboard not built (missing index.html)", http.StatusInternalServerError)
		return
	}
	body := w.dashboardIndexWithBranding(index)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = rw.Write(body)
}

func (w *webMux) dashboardIndexWithBranding(index []byte) []byte {
	branding := w.dashboardBranding()
	body := bytes.Replace(index,
		[]byte("<title>Claw Patrol</title>"),
		[]byte("<title>"+template.HTMLEscapeString(branding.Name)+"</title>"),
		1,
	)
	body = bytes.Replace(body,
		[]byte(`href="/claw-patrol-icon.svg"`),
		[]byte(`href="`+template.HTMLEscapeString(branding.IconURL)+`"`),
		1,
	)
	brandJSON, err := json.Marshal(branding)
	if err != nil {
		return body
	}
	script := []byte("\n    <script>window.__CLAWPATROL_INITIAL_BRANDING__ = " + string(brandJSON) + ";</script>\n  </head>")
	return bytes.Replace(body, []byte("</head>"), script, 1)
}

func (w *webMux) serveCA(rw http.ResponseWriter, _ *http.Request) {
	pemBytes := w.g.certs.CertPEM()
	if len(pemBytes) == 0 {
		http.Error(rw, "ca not initialized", http.StatusServiceUnavailable)
		return
	}
	rw.Header().Set("Content-Type", "application/x-pem-file")
	rw.Header().Set("Content-Length", strconv.Itoa(len(pemBytes)))
	_, _ = rw.Write(pemBytes)
}

func (w *webMux) serveInfo(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	// Surface the CA fingerprint here so debug tools (and the
	// dashboard's approval page) have a single public-readable
	// liveness + identity endpoint. Same value the OnboardPage
	// renders next to the user_code.
	writeJSON(rw, map[string]any{
		"clawpatrol":     true,
		"version":        "0.1",
		"ca_fingerprint": w.caFingerprint(),
	})
}

// caFingerprint returns the SHA-256 fingerprint of the gateway's
// in-memory CA certificate. Empty when the CA hasn't been minted
// yet (test scaffolding or pre-init) so callers can fall through
// without surfacing a parse error to the operator.
func (w *webMux) caFingerprint() string {
	if w.g == nil || w.g.certs == nil {
		return ""
	}
	pemBytes := w.g.certs.CertPEM()
	if len(pemBytes) == 0 {
		return ""
	}
	fp, err := caFingerprintFromPEM(pemBytes)
	if err != nil {
		return ""
	}
	return fp
}

// callerIdentity resolves the (user, device) of the request peer via
// tailscale whois. May be empty if Tailscale is not available.
func (w *webMux) callerIdentity(r *http.Request) (user, device, displayHost string) {
	host := r.Header.Get("X-Forwarded-For")
	if host == "" {
		ipPort := r.RemoteAddr
		if i := strings.LastIndex(ipPort, ":"); i >= 0 {
			host = ipPort[:i]
		} else {
			host = ipPort
		}
	}
	if w.g.agents == nil {
		return "", "", host
	}
	who := w.g.agents.lookupWhois(host)
	if who == nil {
		return "", "", host
	}
	return who.UserProfile.LoginName, who.Node.StableID, who.Node.HostName
}

// selectedProfileForRequest returns the profile name a dashboard request
// targets. Prefer an explicit profile selector, then the configured
// default policy profile. The remaining fallbacks preserve legacy
// single-user/per-caller keys; they are not necessarily declared policy
// profiles and must not be used as evidence that the caller is
// authenticated.
func (w *webMux) selectedProfileForRequest(r *http.Request) (key, label string) {
	if p := r.URL.Query().Get("profile"); p != "" {
		return p, p
	}
	if p := r.Header.Get("X-Clawpatrol-Profile"); p != "" {
		return p, p
	}
	if def := defaultProfileName(w.g.cfg.Load().Policy); def != "" {
		return def, def
	}
	user, _, host := w.callerIdentity(r)
	if user != "" {
		return user, user
	}
	return host, host
}

// whoamiData backs the whoami slice of /api/state. No HTTP handler —
// the route was removed once App.tsx switched to the bundled
// /api/state response.
//
// Source of truth is the principal injected by dashboardAuthGate /
// tailnetGate. For password sessions the principal carries
// {Kind: dashboard_password, Owner: "root"}; for tailnet allowlist
// hits it carries {Kind: tailnet, Owner: <login>, Device, Host}. We
// fall back to the bare whois lookup only when no principal is on
// the context (e.g. on a route the gate let through without one,
// which shouldn't happen for authDashboard but stays defensive).
func (w *webMux) whoamiData(r *http.Request) map[string]string {
	pu := w.g.cfg.Load().PublicURL()
	if pu == "" {
		pu = w.publicURL
	}
	out := map[string]string{
		"user":        "",
		"device":      "",
		"host":        "",
		"auth_method": "",
		"public_url":  pu,
	}
	if p, ok := principalFromContext(r.Context()); ok {
		out["user"] = p.Owner
		out["device"] = p.Device
		out["host"] = p.Host
		switch p.Kind {
		case principalDashboardPassword:
			out["auth_method"] = "password"
		case principalTailnet:
			out["auth_method"] = "tailscale"
		}
		return out
	}
	// No principal on context — fall back to a bare whois so the
	// frontend at least gets a device/host display string. user
	// stays empty so the header renders "not authenticated".
	_, device, host := w.callerIdentity(r)
	out["device"] = device
	out["host"] = host
	return out
}

// apiState is the dashboard's combined refresh endpoint. Bundles
// whoami + status (integrations) + agents into one response with an
// ETag — when the JSON hash matches If-None-Match the gateway returns
// 304 with no body. Server-side caches the last (tag, body) under a
// short TTL so concurrent dashboards on the same tag answer 304
// without re-marshaling+hashing; only the first request per change-
// window pays the full cost. Whoami varies per-caller so the cache
// is keyed by (caller-user, profile).
//
// Cache TTL is conservatively short (1s) so changes propagate to
// idle dashboards within their 5s poll window without us needing a
// real invalidation hook off every credential mutation.
func (w *webMux) apiState(rw http.ResponseWriter, r *http.Request) {
	// Cache key includes the principal kind + owner so a request
	// authed by the root password and a request authed via tailnet
	// whois don't share an entry — the whoami slice they each render
	// is different.
	var keyKind, keyOwner string
	if p, ok := principalFromContext(r.Context()); ok {
		keyKind = string(p.Kind)
		keyOwner = p.Owner
	}
	cacheKey := keyKind + "|" + keyOwner + "|" + r.URL.Query().Get("profile")
	now := time.Now()

	w.stateCacheMu.RLock()
	if c, ok := w.stateCache[cacheKey]; ok && now.Sub(c.At) < stateCacheTTL {
		body, tag := c.Body, c.Tag
		w.stateCacheMu.RUnlock()
		serveState(rw, r, body, tag)
		return
	}
	w.stateCacheMu.RUnlock()

	state := map[string]any{
		"whoami":                  w.whoamiData(r),
		"integrations":            w.statusList(r),
		"agents":                  w.agentsList(),
		"update":                  currentUpdateBanner.Load(),
		"config_file":             filepath.Base(w.g.cfgPath),
		"dashboard_config_writes": w.g.cfg.Load().DashboardConfigWrites(),
		"branding":                w.dashboardBranding(),
	}
	body, err := json.Marshal(state)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:8]) + `"`

	w.stateCacheMu.Lock()
	if w.stateCache == nil {
		w.stateCache = map[string]stateCacheEntry{}
	}
	w.stateCache[cacheKey] = stateCacheEntry{Body: body, Tag: tag, At: now}
	w.stateCacheMu.Unlock()

	serveState(rw, r, body, tag)
}

const stateCacheTTL = 1 * time.Second

type stateCacheEntry struct {
	Body []byte
	Tag  string
	At   time.Time
}

func serveState(rw http.ResponseWriter, r *http.Request, body []byte, tag string) {
	if r.Header.Get("If-None-Match") == tag {
		rw.Header().Set("ETag", tag)
		rw.WriteHeader(http.StatusNotModified)
		return
	}
	rw.Header().Set("ETag", tag)
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-cache")
	_, _ = rw.Write(body)
}

// apiStatus returns the credentials list for the dashboard. Filters
// by profile when ?profile=NAME is set — only credentials referenced
// by an endpoint in that profile come back. Without the param, every
// declared credential ships (root view).

// apiCredentialsSet persists one or more slot values for a non-OAuth
// credential. Body shape:
//
//	{ "id": "stripe-live", "slots": { "": "sk_live_…" } }
//
// Multi-slot credentials (mtls, slack tokens) pass multiple keys.
// Empty values clear the slot.
func (w *webMux) apiCredentialsSet(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID    string            `json:"id"`
		Slots map[string]string `json:"slots"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	policy := w.g.policy.Load()
	ent, ok := policy.Credentials[body.ID]
	if !ok {
		http.Error(rw, "unknown credential: "+body.ID, 404)
		return
	}
	sp, ok := ent.Body.(config.SecretSlotsProvider)
	if !ok {
		http.Error(rw, "credential is OAuth-flow, use /api/oauth/start", 400)
		return
	}
	valid := map[string]bool{}
	for _, s := range sp.SecretSlots() {
		valid[s.Name] = true
	}
	for slot, v := range body.Slots {
		if !valid[slot] {
			http.Error(rw, "unknown slot: "+slot, 400)
			return
		}
		if v == "" {
			// Empty value = clear that slot specifically.
			if _, err := w.g.db.Exec(
				`DELETE FROM credential_secrets WHERE credential = ? AND slot = ?`,
				body.ID, slot,
			); err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			continue
		}
		if err := setCredentialSlot(w.g.db, body.ID, slot, v); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiCredentialsClear drops every slot for the credential. Disconnect
// button on the dashboard.
func (w *webMux) apiCredentialsClear(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	if err := clearCredentialSecrets(w.g.db, body.ID); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// lookupOAuthFlow finds the OAuth flow for a credential bare name in
// the loaded policy. Returns nil when the credential doesn't exist or
// the credential type isn't an OAuth-flow type.
func lookupOAuthFlow(policy *config.CompiledPolicy, name string) *config.OAuthIntegration {
	if policy == nil {
		return nil
	}
	ent, ok := policy.Credentials[name]
	if !ok {
		return nil
	}
	fp, ok := ent.Body.(config.OAuthFlowProvider)
	if !ok {
		return nil
	}
	return fp.OAuthFlow()
}

// apiConfig serves the entire gateway.hcl for the global settings
// editor. GET returns the file as-is (preserves operator comments).
// The gateway is read-only-config — writes happen out-of-band, via
// SSH push from the operator's config repo, not the dashboard.
func (w *webMux) apiConfig(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	b, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	rev := revisionForBytes(b)
	rw.Header().Set("ETag", `"`+rev+`"`)
	rw.Header().Set("X-Config-Revision", rev)
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = rw.Write(b)
}

func (w *webMux) apiConfigApply(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		BaseRevision string `json:"base_revision"`
		AppendHCL    string `json:"append_hcl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.AppendHCL) == "" {
		writeJSONError(rw, http.StatusBadRequest, map[string]any{
			"error": "append_hcl is required",
		})
		return
	}
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()

	// Re-check writes inside the lock: a concurrent reload could
	// have flipped the setting between the request arriving and us
	// acquiring the lock.
	if !w.g.cfg.Load().DashboardConfigWrites() {
		writeJSONError(rw, http.StatusForbidden, map[string]any{
			"error":                   "dashboard config writes are disabled",
			"dashboard_config_writes": false,
		})
		return
	}

	current, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	currentRevision := revisionForBytes(current)
	if body.BaseRevision != "" && body.BaseRevision != currentRevision {
		writeJSONError(rw, http.StatusConflict, map[string]any{
			"error":            "config changed",
			"current_revision": currentRevision,
		})
		return
	}
	candidate := appendConfigSnippet(current, body.AppendHCL)
	dir := filepath.Dir(w.g.cfgPath)
	tmp, err := os.CreateTemp(dir, ".clawpatrol-config-*.hcl")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(candidate); err != nil {
		_ = tmp.Close()
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmp.Close(); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, _, err := loadConfig(tmpPath); err != nil {
		writeJSONError(rw, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}
	// Preserve the original file's permissions across the atomic
	// rename — os.CreateTemp gives us 0600 by default, which would
	// silently downgrade a group-readable deploy file.
	if st, err := os.Stat(w.g.cfgPath); err == nil {
		_ = os.Chmod(tmpPath, st.Mode().Perm())
	}
	if err := os.Rename(tmpPath, w.g.cfgPath); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := w.g.reloadConfigFromFileLocked(w.g.cfgPath); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{
		"ok":       true,
		"revision": revisionForBytes(candidate),
	})
}

func revisionForBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func appendConfigSnippet(current []byte, snippet string) []byte {
	if mergedCurrent, remainingSnippet, ok := mergeGeneratedProfileCredentials(current, []byte(snippet)); ok {
		current = mergedCurrent
		snippet = string(remainingSnippet)
	}
	out := make([]byte, 0, len(current)+len(snippet)+4)
	out = append(out, current...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	if strings.TrimSpace(snippet) == "" {
		return out
	}
	out = append(out, '\n')
	out = append(out, strings.TrimRight(snippet, "\n")...)
	out = append(out, '\n')
	return out
}

// mergeGeneratedProfileCredentials folds any `profile "<name>" {
// credentials = [...] }` blocks in the snippet into the existing
// profile blocks in current, returning the updated current and the
// snippet stripped of those merged blocks. Returns ok=false when
// nothing was merged so the caller falls back to plain append.
func mergeGeneratedProfileCredentials(current, snippet []byte) ([]byte, []byte, bool) {
	currentText := string(current)
	snippetText := string(snippet)
	changed := false

	snippetText = generatedProfileCredentialsBlockRE.ReplaceAllStringFunc(snippetText, func(block string) string {
		m := generatedProfileCredentialsBlockRE.FindStringSubmatch(block)
		if len(m) != 3 {
			return block
		}
		profile := m[1]
		addRefs := credentialRefsFromListText(m[2])
		if len(addRefs) == 0 {
			return block
		}
		updated, ok := mergeProfileCredentialRefs(currentText, profile, addRefs)
		if !ok {
			return block
		}
		currentText = updated
		changed = true
		return ""
	})

	if !changed {
		return current, snippet, false
	}
	return []byte(currentText), []byte(strings.TrimSpace(snippetText)), true
}

var generatedProfileCredentialsBlockRE = regexp.MustCompile(`(?ms)\n*profile\s+"([^"]+)"\s*\{\s*credentials\s*=\s*\[([^\]]*)\]\s*\}\s*`)

func mergeProfileCredentialRefs(current, profile string, addRefs []string) (string, bool) {
	profileName := regexp.QuoteMeta(profile)
	oneLineRE := regexp.MustCompile(`(?m)^(\s*profile\s+"` + profileName + `"\s*\{\s*)([^{}\n]*?)(\s*\}\s*)$`)
	if loc := oneLineRE.FindStringSubmatchIndex(current); loc != nil {
		body := strings.TrimSpace(current[loc[4]:loc[5]])
		existing := credentialRefsFromProfileBody(body)
		refs := mergeRefLists(existing, addRefs)
		var replacement strings.Builder
		replacement.WriteString(`profile "` + profile + `" {` + "\n")
		if body != "" && !profileCredentialsLineRE.MatchString(body) {
			replacement.WriteString("  " + body + "\n")
		}
		replacement.WriteString("  credentials = [" + strings.Join(refs, ", ") + "]\n")
		replacement.WriteString("}")
		return current[:loc[0]] + replacement.String() + current[loc[1]:], true
	}

	blockRE := regexp.MustCompile(`(?ms)(profile\s+"` + profileName + `"\s*\{\n)(.*?)(\n\})`)
	loc := blockRE.FindStringSubmatchIndex(current)
	if loc == nil {
		return current, false
	}
	body := current[loc[4]:loc[5]]
	// Bail out if the body contains anything we can't reason about
	// with the simple credentials-list regex: nested braces (inline
	// disambiguator entries), multi-line credentials lists with `,`
	// on continuation lines, or any non-credentials attribute that
	// could swallow our edit. The caller falls back to a plain
	// append, which surfaces a clean "duplicate profile" diagnostic
	// from the loader.
	if strings.ContainsAny(body, "{}") || !profileBodyMergeSafe(body) {
		return current, false
	}
	existing := credentialRefsFromProfileBody(body)
	refs := mergeRefLists(existing, addRefs)
	if profileCredentialsLineRE.MatchString(body) {
		body = profileCredentialsLineRE.ReplaceAllString(body, "  credentials = ["+strings.Join(refs, ", ")+"]")
	} else {
		body = strings.TrimRight(body, "\n") + "\n  credentials = [" + strings.Join(refs, ", ") + "]"
	}
	return current[:loc[4]] + body + current[loc[5]:], true
}

// profileBodyMergeSafe returns true only when every non-blank line in
// the profile body is either the single `credentials = [...]` line we
// know how to edit or a comment / whitespace. Anything else (extra
// attributes, multi-line credentials lists, disambiguator literals
// the simple regex would mis-tokenise) makes the merge unsafe.
func profileBodyMergeSafe(body string) bool {
	credSeen := false
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}
		if !profileCredentialsLineRE.MatchString(line) {
			return false
		}
		if credSeen {
			return false
		}
		credSeen = true
	}
	return true
}

var profileCredentialsLineRE = regexp.MustCompile(`(?m)^\s*credentials\s*=\s*\[([^\]]*)\]`)

func credentialRefsFromProfileBody(body string) []string {
	m := profileCredentialsLineRE.FindStringSubmatch(body)
	if len(m) != 2 {
		return nil
	}
	return credentialRefsFromListText(m[1])
}

func credentialRefsFromListText(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		ref := strings.TrimSpace(part)
		if ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

func mergeRefLists(existing, added []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(added))
	for _, ref := range append(existing, added...) {
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

func writeJSONError(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func (w *webMux) apiHITLPending(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, w.g.hitl.List())
}

func (w *webMux) apiHITLDecide(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Allow bool   `json:"allow"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(rw, "decision requires an authenticated operator", http.StatusForbidden)
		return
	}
	result := runtime.HITLResolveResult{State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	decision := runtime.HITLDecision{Allow: body.Allow, By: principal.Owner}
	if decider, ok := interface{}(w.g.hitl).(runtime.HITLPoolDecider); ok {
		result = decider.DecideWithResult(body.ID, decision)
	} else {
		result.OK = w.g.hitl.Decide(body.ID, decision)
		if result.OK {
			if body.Allow {
				result.State = runtime.HITLStateApproved
			} else {
				result.State = runtime.HITLStateDenied
			}
		}
	}
	writeJSON(rw, result)
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.")
}

func (w *webMux) apiEventsSSE(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", 500)
		return
	}

	wantIP := r.URL.Query().Get("agent")

	if w.g.sink == nil {
		_, _ = fmt.Fprintf(rw, ": no sink\n\n")
		flusher.Flush()
		return
	}
	backlog, ch, cancel := w.g.sink.RecentAndSubscribe()
	defer cancel()

	_, _ = fmt.Fprint(rw, ": connected\n\n")
	// Backlog ships as a single `event: backlog` SSE message carrying
	// the whole array. Client renders that batch in one commit (no
	// per-event rAF flood), then switches to per-event live streaming.
	// Default event channel = live only.
	if len(backlog) > 0 {
		filtered := backlog
		if wantIP != "" {
			filtered = filtered[:0]
			for _, ev := range backlog {
				if ev.AgentIP == wantIP {
					filtered = append(filtered, ev)
				}
			}
		}
		if len(filtered) > 0 {
			b, err := json.Marshal(filtered)
			if err == nil {
				_, _ = fmt.Fprintf(rw, "event: backlog\ndata: %s\n\n", b)
			}
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprint(rw, ": ka\n\n")
			flusher.Flush()
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if wantIP != "" && pkt.ev.AgentIP != wantIP {
				continue
			}
			_, _ = fmt.Fprintf(rw, "data: %s\n\n", pkt.raw)
			flusher.Flush()
		}
	}
}

func (w *webMux) apiActionRulePreview(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ActionID string `json:"action_id"`
		Verdict  string `json:"verdict"`
		Scope    string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if body.ActionID == "" {
		http.Error(rw, "missing action_id", http.StatusBadRequest)
		return
	}
	policy := w.g.Policy()
	if policy == nil {
		http.Error(rw, "policy not loaded", http.StatusServiceUnavailable)
		return
	}
	ev, err := w.loadAction(body.ActionID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(rw, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rule, err := GenerateRuleFromEvent(policy, ev, RuleGenOptions{
		Verdict: body.Verdict,
		Scope:   body.Scope,
	})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if b, err := os.ReadFile(w.g.cfgPath); err == nil {
		rule.ConfigRevision = revisionForBytes(b)
	}
	rule.DashboardConfigWrites = w.g.cfg.Load().DashboardConfigWrites()
	writeJSON(rw, rule)
}

func (w *webMux) loadAction(actionID string) (*Event, error) {
	if actionID == "" {
		return nil, fmt.Errorf("missing id")
	}
	var (
		e            Event
		tsNs         int64
		mode         sql.NullString
		family       sql.NullString
		agentIP      sql.NullString
		method       sql.NullString
		path         sql.NullString
		status       sql.NullString
		in, ot       sql.NullInt64
		ms           sql.NullInt64
		action       sql.NullString
		reason       sql.NullString
		reqSha       sql.NullString
		respSha      sql.NullString
		reqBody      sql.NullString
		respBody     sql.NullString
		reqHeaders   sql.NullString
		respHeaders  sql.NullString
		extra        sql.NullString
		endpoint     sql.NullString
		rule         sql.NullString
		approver     sql.NullString
		approverType sql.NullString
		approverBy   sql.NullString
	)
	err := w.g.db.QueryRow(`
		SELECT ts_ns, mode, family, agent_ip, host, method, path,
		       status, bytes_in, bytes_out, ms, action,
		       reason, req_sha, resp_sha,
		       req_body, resp_body,
		       req_headers, resp_headers, extra,
		       endpoint, rule,
		       approver, approver_type, approver_by
		FROM actions WHERE action_id = ?`, actionID,
	).Scan(
		&tsNs, &mode, &family, &agentIP, &e.Host,
		&method, &path, &status, &in, &ot, &ms,
		&action, &reason, &reqSha, &respSha,
		&reqBody, &respBody,
		&reqHeaders, &respHeaders, &extra,
		&endpoint, &rule,
		&approver, &approverType, &approverBy,
	)
	if err != nil {
		return nil, err
	}
	e.ID = actionID
	e.Ts = time.Unix(0, tsNs).UTC()
	e.Mode = mode.String
	e.Family = family.String
	e.AgentIP = agentIP.String
	e.Method = method.String
	e.Path = path.String
	e.Status = status.String
	e.In = in.Int64
	e.Out = ot.Int64
	e.Ms = ms.Int64
	e.Action = action.String
	e.Reason = reason.String
	e.ReqSha = reqSha.String
	e.RespSha = respSha.String
	e.ReqBody = reqBody.String
	e.RespBody = respBody.String
	unmarshalHeaders(reqHeaders.String, &e.ReqHeaders)
	unmarshalHeaders(respHeaders.String, &e.RespHeaders)
	if extra.String != "" {
		_ = json.Unmarshal([]byte(extra.String), &e.Facets)
	}
	e.Endpoint = endpoint.String
	e.Rule = rule.String
	e.Approver = approver.String
	e.ApproverType = approverType.String
	e.ApproverBy = approverBy.String
	return &e, nil
}

func (w *webMux) apiActionByID(
	rw http.ResponseWriter, r *http.Request,
) {
	// Path: /api/actions/<uuid>
	actionID := strings.TrimPrefix(r.URL.Path, "/api/actions/")
	if actionID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	e, err := w.loadAction(actionID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(rw, "not found", 404)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("fmt") == "fixture" {
		w.writeActionFixture(rw, e)
		return
	}
	writeJSON(rw, e)
}

// writeActionFixture emits the Action JSON for `clawpatrol test`
// (site/doc/clawpatrol-test.md). 400s on events that pre-date
// endpoint tracking or can't be mapped to a terminal verdict.
func (w *webMux) writeActionFixture(rw http.ResponseWriter, ev *Event) {
	policy := w.g.Policy()
	if policy == nil {
		http.Error(rw, "policy not loaded", http.StatusServiceUnavailable)
		return
	}
	if ev.Endpoint == "" {
		http.Error(rw, "action predates endpoint tracking; cannot export as fixture", 400)
		return
	}
	ep := policy.Endpoints[ev.Endpoint]
	if ep == nil {
		http.Error(rw, fmt.Sprintf("endpoint %q no longer in policy", ev.Endpoint), 400)
		return
	}
	m, ok := matchFromEvent(ev)
	if !ok {
		http.Error(rw, fmt.Sprintf("event action %q is not exportable as a fixture", ev.Action), 400)
		return
	}
	// Stamp the typed reference (endpoint-type.endpoint-name) so the
	// runner can route the fixture without ambiguity. ev.Endpoint is
	// the bare DB-recorded name; the policy supplies the type.
	m.Endpoint = endpointRef(ep)

	fx := &Fixture{Match: m, Action: Action{PeerIP: ev.AgentIP}}
	switch ep.Family {
	case "http":
		fx.Action.Host = ev.Host
		fx.Action.HTTP = exportHTTP(ev)
	case "k8s":
		fx.Action.Host = ev.Host
		fx.Action.K8s = exportK8s(ev)
	case "sql":
		sql := exportSQL(ev)
		if sql == nil {
			http.Error(rw, "sql action has no statement recorded; cannot export", 400)
			return
		}
		// Host for SQL comes from the endpoint's HCL declaration —
		// the recorded Event.Host is the dst IP / tunnel listener,
		// not what the resolver scans against. For multi-host
		// endpoints pick the first; the runner short-circuits on
		// match.endpoint anyway, so host is informational here.
		if len(ep.Hosts) > 0 {
			fx.Action.Host = ep.Hosts[0]
		}
		fx.Action.SQL = sql
	case "ssh":
		ssh := exportSSH(ev)
		if ssh == nil {
			http.Error(rw, "ssh action has no gateable verb recorded; cannot export", 400)
			return
		}
		// Host for SSH, like SQL, comes from the endpoint's HCL
		// declaration — the recorded Event.Host is the dst IP / VIP,
		// not the hostname the resolver scans. The runner
		// short-circuits on match.endpoint anyway.
		if len(ep.Hosts) > 0 {
			fx.Action.Host = ep.Hosts[0]
		}
		fx.Action.SSH = ssh
	default:
		http.Error(rw, fmt.Sprintf("endpoint family %q is not yet exportable", ep.Family), http.StatusNotImplemented)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, ev.ID))
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")
	_ = enc.Encode(fx)
}

// matchFromEvent maps post-chain Event.Action onto the fixture's
// terminal verdict vocabulary. hitl_* collapses to "approve".
// Empty Event.Action maps to "allow" — that's the legacy default
// for rows written before per-action verdicts were tracked.
func matchFromEvent(ev *Event) (Match, bool) {
	m := Match{Rule: ev.Rule, Endpoint: ev.Endpoint, Reason: ev.Reason}
	switch ev.Action {
	case "deny":
		m.Verdict = "deny"
	case "approved", "denied", "hitl_allow", "hitl_deny":
		// `approved` / `denied` is the post-rename label for an
		// approve-chain verdict; `hitl_*` are kept for pre-migration
		// fixtures so the test corpus still loads.
		m.Verdict = "approve"
	case "allow", "":
		m.Verdict = "allow"
	case "passthrough":
		m.Verdict = "passthrough"
	default:
		return Match{}, false
	}
	return m, true
}

// exportHTTP populates the http.* CEL view from a recorded Event.
// Host lives on Action (not in the http block) since `http.host`
// isn't a CEL variable. Path comes straight from the recorded URL.
func exportHTTP(ev *Event) *HTTPAction {
	body, b64 := encodeBody([]byte(ev.ReqBody))
	path, query := splitPathQuery(ev.Path)
	return &HTTPAction{
		Method:  ev.Method,
		Path:    path,
		Query:   query,
		Headers: headersToMultiValue(ev.ReqHeaders),
		Body:    body,
		BodyB64: b64,
	}
}

// splitPathQuery separates a recorded Event.Path (which may carry
// `?query=...` already encoded) into path + parsed-query.
func splitPathQuery(raw string) (string, map[string][]string) {
	q := strings.IndexByte(raw, '?')
	if q < 0 {
		return raw, nil
	}
	vals, err := url.ParseQuery(raw[q+1:])
	if err != nil || len(vals) == 0 {
		return raw[:q], nil
	}
	return raw[:q], vals
}

// exportK8s recovers the parsed k8s tuple from Event.Facets, set
// by the k8s facet's Report at live-dispatch time. Only CEL-visible
// fields land in the k8s block.
func exportK8s(ev *Event) *K8sAction {
	a := &K8sAction{}
	if v, ok := ev.Facets["verb"].(string); ok {
		a.Verb = v
	}
	if v, ok := ev.Facets["resource"].(string); ok {
		a.Resource = v
	}
	if v, ok := ev.Facets["namespace"].(string); ok {
		a.Namespace = v
	}
	if v, ok := ev.Facets["name"].(string); ok {
		a.Name = v
	}
	if p, ok := ev.Facets["params"].(map[string]any); ok {
		a.Params = map[string]string{}
		for k, val := range p {
			if s, ok := val.(string); ok {
				a.Params[k] = s
			}
		}
	}
	return a
}

// exportSQL pulls the SQL facet fields out of Event.Facets (set by
// sqlfacet.Report). Statement is required; verb / tables / functions
// / database are emitted when the recorded facets supply them so the
// downloaded fixture mirrors what the dashboard renders and stays
// self-contained for `clawpatrol test` (the loader still tolerates
// missing facets — the SQLParser re-derives them at replay).
func exportSQL(ev *Event) *SQLAction {
	stmt, _ := ev.Facets["statement"].(string)
	if stmt == "" {
		return nil
	}
	a := &SQLAction{Statement: stmt}
	if v, ok := ev.Facets["verb"].(string); ok {
		a.Verb = v
	}
	a.Tables = stringSliceFromFacet(ev.Facets["tables"])
	a.Functions = stringSliceFromFacet(ev.Facets["functions"])
	if v, ok := ev.Facets["database"].(string); ok {
		a.Database = v
	}
	return a
}

// exportSSH recovers the ssh.* CEL view from Event.Facets (set by
// sshfacet.Report at live-dispatch time). Only the field the action's
// verb populates is non-empty. Returns nil for a non-gateable log
// line (connect / exit-status carry no verb facet), so the handler
// can refuse to export it as a fixture.
func exportSSH(ev *Event) *SSHAction {
	verb, _ := ev.Facets["verb"].(string)
	if verb == "" {
		return nil
	}
	a := &SSHAction{Verb: verb}
	if v, ok := ev.Facets["command"].(string); ok {
		a.Command = v
	}
	if v, ok := ev.Facets["subsystem"].(string); ok {
		a.Subsystem = v
	}
	if v, ok := ev.Facets["forward_host"].(string); ok {
		a.ForwardHost = v
	}
	a.ForwardPort = intFromFacet(ev.Facets["forward_port"])
	if v, ok := ev.Facets["user"].(string); ok {
		a.User = v
	}
	if v, ok := ev.Facets["stdin"].(string); ok {
		a.Stdin = v
	}
	return a
}

// intFromFacet narrows a JSON-unmarshalled numeric facet into int.
// Event.Facets is decoded as map[string]any, so integer facets land
// as float64 (json.Number when the decoder uses UseNumber).
func intFromFacet(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

// stringSliceFromFacet narrows a JSON-unmarshalled facet list into
// []string. Event.Facets is decoded as map[string]any, so list-typed
// facets land as []any.
func stringSliceFromFacet(v any) []string {
	raw, ok := v.([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// headersToMultiValue widens the Sink's single-value header map to
// http.Header's multi-value shape.
func headersToMultiValue(h map[string]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = []string{v}
	}
	return out
}

// apiAnalytics returns a randomly-sampled set of events for the
// analytics charts. Query params:
//
//	range  — duration string (1m, 5m, 15m, 30m, 1h, 6h, 24h)
//	agent  — optional agent IP filter
//	limit  — max rows (default 5000)
func (w *webMux) apiAnalytics(
	rw http.ResponseWriter, r *http.Request,
) {
	q := r.URL.Query()
	rangeStr := q.Get("range")
	if rangeStr == "" {
		rangeStr = "1h"
	}
	dur, err := time.ParseDuration(
		strings.TrimSuffix(rangeStr, "m") + "m0s",
	)
	// Parse shorthand: 1m, 5m, 30m, 1h, 6h, 24h
	switch rangeStr {
	case "1m":
		dur = time.Minute
	case "5m":
		dur = 5 * time.Minute
	case "15m":
		dur = 15 * time.Minute
	case "30m":
		dur = 30 * time.Minute
	case "1h":
		dur = time.Hour
	case "6h":
		dur = 6 * time.Hour
	case "24h":
		dur = 24 * time.Hour
	default:
		if err != nil {
			dur = time.Hour
		}
	}
	cutoff := time.Now().Add(-dur).UnixNano()
	limit := 5000
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 10000 {
				n = 10000
			}
			limit = n
		}
	}
	agent := q.Get("agent")

	where := "ts_ns >= ?"
	whereArgs := []any{cutoff}
	if agent != "" {
		where += " AND agent_ip = ?"
		whereArgs = append(whereArgs, agent)
	}

	// Sort by the random suffix of action_id (UUIDv7, so the last
	// chars are uniform random) instead of RANDOM(). Same range +
	// agent → same sample, so a polling dashboard doesn't reshuffle
	// the scatter every 10 s.
	query := `
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, extra
		FROM actions
		WHERE ` + where + `
		ORDER BY COALESCE(substr(action_id, -8), CAST(ts_ns AS TEXT))
		LIMIT ?`
	args := append(append([]any{}, whereArgs...), limit)
	rows, err := w.g.db.Query(query, args...)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, 256)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			family   sql.NullString
			agentIP  sql.NullString
			method   sql.NullString
			path     sql.NullString
			status   sql.NullString
			in, ot   sql.NullInt64
			ms       sql.NullInt64
			action   sql.NullString
			reason   sql.NullString
			extra    sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &extra,
		); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		e.ID = actionID.String
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.Family = family.String
		e.AgentIP = agentIP.String
		e.Method = method.String
		e.Path = path.String
		e.Status = status.String
		e.In = in.Int64
		e.Out = ot.Int64
		e.Ms = ms.Int64
		e.Action = action.String
		e.Reason = reason.String
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	// Real (non-sampled) totals so the top stats reflect the actual
	// request volume, not the chart's 5000-row sample. Filtered by
	// the same range + agent as the events query above.
	var totalCount int64
	var errorCount sql.NullInt64
	// Mirror statusClass: an error is a non-empty status that is either
	// non-numeric (a named plugin error like "AccessDenied") or a numeric
	// HTTP status >= 400. A bare `status >= 400` is wrong now that status is
	// TEXT — SQLite sorts every text value above all numbers, so it would
	// count "", "OK", and every named status as an error.
	_ = w.g.db.QueryRow(
		`SELECT COUNT(*),
		        SUM(CASE WHEN status IS NOT NULL AND status <> ''
		                  AND (NOT (status GLOB '[0-9]*') OR CAST(status AS INTEGER) >= 400)
		                 THEN 1 ELSE 0 END)
		 FROM actions WHERE `+where, whereArgs...,
	).Scan(&totalCount, &errorCount)

	// Real per-device / per-host counts so the bar lists aren't
	// capped at the sample size either. Same filter; bar charts only
	// render the top ~10 so 50 is a generous cap.
	byDevice := groupCount(w.g.db,
		`SELECT agent_ip, COUNT(*) FROM actions
		 WHERE `+where+` AND agent_ip IS NOT NULL AND agent_ip != ''
		 GROUP BY agent_ip ORDER BY 2 DESC LIMIT 50`,
		whereArgs)
	byHost := groupCount(w.g.db,
		`SELECT host, COUNT(*) FROM actions
		 WHERE `+where+` AND host IS NOT NULL AND host != ''
		 GROUP BY host ORDER BY 2 DESC LIMIT 50`,
		whereArgs)

	writeJSON(rw, map[string]any{
		"events":      out,
		"total":       len(out),
		"total_count": totalCount,
		"error_count": errorCount.Int64,
		"by_device":   byDevice,
		"by_host":     byHost,
	})
}

// apiFacets returns every registered facet's reporting schema.
// The dashboard fetches this once at boot and uses it to render
// per-family columns (HTTPS: method/path/status, SQL:
// verb/tables/..., k8s: verb/resource/...) directly from the JSON
// `facets` payload on each event, instead of carrying a hardcoded
// switch on family strings.
func (w *webMux) apiFacets(rw http.ResponseWriter, r *http.Request) {
	_ = r
	type reportFieldJSON struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Label       string `json:"label,omitempty"`
		Description string `json:"description,omitempty"`
		Title       bool   `json:"title,omitempty"`
		DetailOnly  bool   `json:"detail_only,omitempty"`
	}
	type facetJSON struct {
		Name             string            `json:"name"`
		EndpointFamilies []string          `json:"endpoint_families"`
		Transport        string            `json:"transport,omitempty"`
		HITLQueryLabel   string            `json:"hitl_query_label,omitempty"`
		HostIsResource   bool              `json:"host_is_resource"`
		ReportFields     []reportFieldJSON `json:"report_fields"`
		ResultFields     []reportFieldJSON `json:"result_fields,omitempty"`
	}
	all := facet.All()
	out := make([]facetJSON, 0, len(all))
	for _, f := range all {
		fks := f.ReportFields()
		entry := facetJSON{
			Name:             f.Name(),
			EndpointFamilies: f.EndpointFamilies(),
			Transport:        f.Transport(),
			HITLQueryLabel:   f.HITLQueryLabel(),
			HostIsResource:   f.HostIsResource(),
			ReportFields:     make([]reportFieldJSON, len(fks)),
		}
		for i, fk := range fks {
			entry.ReportFields[i] = reportFieldJSON{
				Name: fk.Name, Kind: reportKindName(fk.Kind), Label: fk.Label,
				Description: fk.Description, Title: fk.Title, DetailOnly: fk.DetailOnly,
			}
		}
		// result_fields is the after-the-fact result schema, exposed
		// only by facets that implement the optional accessor (plugin
		// facets). Don't widen the core facet.Runtime interface for it.
		if rf, ok := f.(interface {
			ResultFields() []facet.ReportFieldSpec
		}); ok {
			rfs := rf.ResultFields()
			entry.ResultFields = make([]reportFieldJSON, len(rfs))
			for i, fk := range rfs {
				entry.ResultFields[i] = reportFieldJSON{
					Name: fk.Name, Kind: reportKindName(fk.Kind), Label: fk.Label,
					Description: fk.Description, Title: fk.Title, DetailOnly: fk.DetailOnly,
				}
			}
		}
		out = append(out, entry)
	}
	writeJSON(rw, map[string]any{"facets": out})
}

func reportKindName(k facet.ReportValueKind) string {
	switch k {
	case facet.ReportString:
		return "string"
	case facet.ReportStringList:
		return "string_list"
	case facet.ReportStringMap:
		return "string_map"
	case facet.ReportInt:
		return "int"
	}
	return ""
}

func groupCount(db *sql.DB, q string, args []any) []map[string]any {
	out := []map[string]any{}
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k sql.NullString
		var c int64
		if err := rows.Scan(&k, &c); err != nil || !k.Valid {
			continue
		}
		out = append(out, map[string]any{
			"key": k.String, "count": c,
		})
	}
	if err := rows.Err(); err != nil {
		return []map[string]any{}
	}
	return out
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}

// Event sink + sampling helpers (fed by g.handle/mitm/splice; consumed
// by the dashboard SSE stream and the on-disk event log).

// statusClass buckets a status string for metrics + dashboard coloring: a
// numeric HTTP-style status by its leading digit (2xx..5xx), a non-empty
// non-numeric status (e.g. a plugin's "AccessDenied") as "error" — a named
// status is a failure; a successful plugin reports a 2xx — and an empty
// status as "".
func statusClass(status string) string {
	if status == "" {
		return ""
	}
	n, err := strconv.Atoi(status)
	if err != nil {
		return "error"
	}
	switch {
	case n >= 500:
		return "5xx"
	case n >= 400:
		return "4xx"
	case n >= 300:
		return "3xx"
	case n >= 200:
		return "2xx"
	default:
		return ""
	}
}

type Event struct {
	Ts      time.Time `json:"ts"`
	ID      string    `json:"id,omitempty"`    // UUIDv7; correlates start/end/frame + DB key
	Phase   string    `json:"phase,omitempty"` // "" (legacy/end), "start", "end", "frame"
	Mode    string    `json:"mode"`
	Agent   string    `json:"agent,omitempty"`
	AgentIP string    `json:"agent_ip,omitempty"`
	Host    string    `json:"host"`
	Method  string    `json:"method,omitempty"`
	Path    string    `json:"path,omitempty"`
	Status  string    `json:"status,omitempty"`
	In      int64     `json:"in,omitempty"`
	Out     int64     `json:"out,omitempty"`
	Ms      int64     `json:"ms"`
	Action  string    `json:"action,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	// Approver* are populated when Action is "approved" / "denied":
	// the approver entity's HCL block name, plugin type (human_approver
	// / llm_approver / dashboard), and the approver-specific "By"
	// string (Slack handle, llm:<model>, ...). All empty for rule-
	// driven verdicts.
	Approver     string            `json:"approver,omitempty"`
	ApproverType string            `json:"approver_type,omitempty"`
	ApproverBy   string            `json:"approver_by,omitempty"`
	ReqSha       string            `json:"req_sha,omitempty"`
	ReqBody      string            `json:"req_body,omitempty"`
	RespSha      string            `json:"resp_sha,omitempty"`
	RespBody     string            `json:"resp_body,omitempty"`
	ReqHeaders   map[string]string `json:"req_headers,omitempty"`
	RespHeaders  map[string]string `json:"resp_headers,omitempty"`
	// Frame is set for Phase="frame" only — a single WS frame's text
	// payload (truncated at sampleCap). Direction is "c→s" or "s→c"
	// to disambiguate masked client frames from unmasked server frames.
	Frame     string `json:"frame,omitempty"`
	Direction string `json:"direction,omitempty"`

	// Family identifies which protocol-family facet emitted this
	// event ("http", "sql", "k8s", or a future plugin's name).
	// Persisted as a dedicated column on actions so analytics can
	// filter by family; drives dashboard column selection via
	// /api/facets. Empty for splice events and pre-migration rows.
	Family string `json:"family,omitempty"`

	// Facets carries the per-family report payload — the result of
	// the family's facet.Runtime.Report hook against the matched
	// request. Keys correspond to the family's ReportFields().
	// Serialised as JSON into the actions table's `extra` column.
	Facets map[string]any `json:"facets,omitempty"`

	// Endpoint is the dispatching CompiledEndpoint.Name; Rule is the
	// matched CompiledRule.Name (empty when no rule fired). Populated
	// at the existing dispatch sites so the action-fixture exporter
	// can pin a downloaded action to a specific endpoint and assert
	// the rule that produced its verdict (site/doc/clawpatrol-test.md).
	Endpoint string `json:"endpoint,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// eventPacket carries an event plus its marshaled JSON bytes. drain()
// marshals once and ships the same bytes to every subscriber so a
// busy gateway doesn't pay N × json.Marshal per event when N
// dashboards are connected.
type eventPacket struct {
	ev  Event
	raw []byte
}

type Sink struct {
	ch    chan Event
	db    *sql.DB
	drops atomic.Uint64
	mu    sync.Mutex
	subs  []chan eventPacket
	// Recent ring backlog. recent is sized once at construction; we
	// write at recentNext (modulo cap) and rotate. Old behavior used
	// `append + slice` which reallocated on every overflow, churning
	// GC at ~10 alloc/sec on a busy gateway. Lazy fill: until we wrap,
	// recentLen tracks valid entries.
	recent     []Event
	recentNext int
	recentLen  int
	recentCap  int

	// closed flips once Close has run. Emit checks it as the cheap
	// pre-flight; the deferred recover handles the residual race where
	// Close intervenes between the closed-load and the channel send.
	closed    atomic.Bool
	closeOnce sync.Once
	// done closes when drain returns, signalling Close that every
	// buffered event has been persisted to actions / fanned out to
	// subscribers. Gateway shutdown waits on this before db.Close so
	// in-flight events aren't dropped at WAL teardown.
	done chan struct{}
}

func NewSink(db *sql.DB, buf int) (*Sink, error) {
	s := &Sink{ch: make(chan Event, buf), db: db, recentCap: 500, done: make(chan struct{})}
	s.recent = make([]Event, s.recentCap)
	if db != nil {
		if seed, err := readTailEvents(db, s.recentCap); err == nil && len(seed) > 0 {
			// Seed fills oldest→newest; place at indices 0..len(seed)-1
			// and set recentNext to the next slot, recentLen to length.
			n := len(seed)
			if n > s.recentCap {
				seed = seed[n-s.recentCap:]
				n = s.recentCap
			}
			copy(s.recent, seed)
			s.recentLen = n
			s.recentNext = n % s.recentCap
		}
	}
	go s.drain()
	return s, nil
}

func readTailEvents(db *sql.DB, n int) ([]Event, error) {
	rows, err := db.Query(`
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, req_sha, resp_sha, extra,
		       endpoint, rule,
		       approver, approver_type, approver_by
		FROM actions ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, n)
	for rows.Next() {
		var (
			e            Event
			actionID     sql.NullString
			tsNs         int64
			mode         sql.NullString
			family       sql.NullString
			agentIP      sql.NullString
			method       sql.NullString
			path         sql.NullString
			status       sql.NullString
			in, ot       sql.NullInt64
			ms           sql.NullInt64
			action       sql.NullString
			reason       sql.NullString
			reqSha       sql.NullString
			respSha      sql.NullString
			extra        sql.NullString
			endpoint     sql.NullString
			rule         sql.NullString
			approver     sql.NullString
			approverType sql.NullString
			approverBy   sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &reqSha, &respSha, &extra,
			&endpoint, &rule,
			&approver, &approverType, &approverBy,
		); err != nil {
			return nil, err
		}
		e.ID = actionID.String
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.Family = family.String
		e.Endpoint = endpoint.String
		e.Rule = rule.String
		e.AgentIP = agentIP.String
		e.Method = method.String
		e.Path = path.String
		e.Status = status.String
		e.In = in.Int64
		e.Out = ot.Int64
		e.Ms = ms.Int64
		e.Action = action.String
		e.Reason = reason.String
		e.ReqSha = reqSha.String
		e.RespSha = respSha.String
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
		e.Approver = approver.String
		e.ApproverType = approverType.String
		e.ApproverBy = approverBy.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// rows are newest-first; flip to oldest-first so SSE backlog
	// arrives in the order subscribers expect.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *Sink) Emit(e Event) {
	if s == nil || s.closed.Load() {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	defer func() {
		// Tiny race: closed.Load returned false but Close raced past
		// us before the select ran. Send-on-closed-channel panics —
		// swallow and count it as a drop instead of crashing the
		// goroutine that called Emit (e.g. a request handler) during
		// shutdown.
		if r := recover(); r != nil {
			s.drops.Add(1)
		}
	}()
	select {
	case s.ch <- e:
	default:
		s.drops.Add(1)
	}
}

func (s *Sink) Drops() uint64 { return s.drops.Load() }

// Close stops the sink from accepting new events and waits for the
// drain goroutine to persist anything already buffered, capped by
// ctx so a wedged DB write cannot block gateway shutdown. Idempotent
// — duplicate Close calls return the result of the first wait.
//
// Order matters at shutdown: call Close before db.Close so the
// final actions rows land in WAL before the file descriptor goes
// away. Without this step a SIGTERM in the middle of a busy batch
// silently loses every event still sitting in s.ch (4096-deep by
// default).
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.ch)
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sink) drain() {
	defer close(s.done)
	for e := range s.ch {
		// Persist only terminal events. start/frame are transient
		// signals for live SSE — duplicating them in `actions` would
		// double-count requests in the request-history view and bloat
		// the table for long-poll / WS sessions.
		persist := e.Phase == "" || e.Phase == "end"
		if persist && e.ID == "" {
			// Some connection-oriented endpoint runtimes emit a single terminal
			// event instead of the HTTP start/end pair. Give those events a
			// stable action_id before DB insert + SSE fan-out so every persisted
			// live-request row can navigate to /api/actions/<id>.
			e.ID = newReqID()
		}
		if s.db != nil && persist {
			var rqhJSON, rshJSON []byte
			if len(e.ReqHeaders) > 0 {
				rqhJSON, _ = json.Marshal(e.ReqHeaders)
			}
			if len(e.RespHeaders) > 0 {
				rshJSON, _ = json.Marshal(e.RespHeaders)
			}
			var extraJSON []byte
			if len(e.Facets) > 0 {
				extraJSON, _ = json.Marshal(e.Facets)
			}
			_, _ = s.db.Exec(`
				INSERT INTO actions
				 (action_id, ts_ns, mode, family, agent_ip, host,
				  method, path, status, bytes_in, bytes_out,
				  ms, action, reason, req_sha, resp_sha,
				  req_body, resp_body,
				  req_headers, resp_headers, extra,
				  endpoint, rule,
				  approver, approver_type, approver_by)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			`, e.ID, e.Ts.UnixNano(), e.Mode, e.Family, e.AgentIP,
				e.Host, e.Method, e.Path, e.Status,
				e.In, e.Out, e.Ms, e.Action, e.Reason,
				e.ReqSha, e.RespSha,
				e.ReqBody, e.RespBody,
				string(rqhJSON), string(rshJSON),
				string(extraJSON),
				e.Endpoint, e.Rule,
				e.Approver, e.ApproverType, e.ApproverBy)
		}

		// Marshal once per event regardless of subscriber count. Old
		// path marshaled inside each subscriber's SSE handler — N
		// dashboards = N json.Marshal calls per event. Now it's 1.
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		pkt := eventPacket{ev: e, raw: raw}

		s.mu.Lock()
		// Recent ring updated under lock since RecentAndSubscribe
		// snapshots it. Circular write: O(1) regardless of cap.
		// Strip bodies from the backlog copy — SSE consumers only
		// need metadata; the detail page fetches full data via
		// /api/actions/<id>.
		if persist {
			lite := e
			lite.ReqBody = ""
			lite.RespBody = ""
			lite.ReqHeaders = nil
			lite.RespHeaders = nil
			s.recent[s.recentNext] = lite
			s.recentNext = (s.recentNext + 1) % s.recentCap
			if s.recentLen < s.recentCap {
				s.recentLen++
			}
		}
		// Copy subs out of the lock, fan-out without holding mu so
		// a slow channel doesn't serialize the gateway. Cheap copy
		// (slice of channel pointers, len ~= dashboards open).
		subs := append([]chan eventPacket(nil), s.subs...)
		s.mu.Unlock()

		for _, sub := range subs {
			select {
			case sub <- pkt:
			default:
				// slow consumer; drop
				s.drops.Add(1)
			}
		}
	}
}

// recentSnapshot copies the ring into a flat oldest→newest slice.
// Caller must hold s.mu (or call from RecentAndSubscribe which does).
func (s *Sink) recentSnapshot() []Event {
	if s.recentLen == 0 {
		return nil
	}
	out := make([]Event, s.recentLen)
	if s.recentLen < s.recentCap {
		copy(out, s.recent[:s.recentLen])
		return out
	}
	// Wrapped: oldest entry sits at recentNext, walk forward modulo cap.
	for i := 0; i < s.recentCap; i++ {
		out[i] = s.recent[(s.recentNext+i)%s.recentCap]
	}
	return out
}

// RecentAndSubscribe atomically snapshots the backlog and registers a
// subscriber under the same lock so no event is missed or duplicated
// between the two. Channel ships eventPackets — drain marshaled the
// JSON once and shares those bytes across every subscriber.
func (s *Sink) RecentAndSubscribe() ([]Event, <-chan eventPacket, func()) {
	if s == nil {
		ch := make(chan eventPacket)
		close(ch)
		return nil, ch, func() {}
	}
	ch := make(chan eventPacket, 64)
	s.mu.Lock()
	snap := s.recentSnapshot()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return snap, ch, cancel
}

func (s *Sink) Subscribe() (<-chan eventPacket, func()) {
	_, ch, cancel := s.RecentAndSubscribe()
	return ch, cancel
}

type sampler struct {
	hash hash.Hash
	cap  int
	buf  bytes.Buffer
	n    int64
}

func unmarshalHeaders(s string, dst *map[string]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

var sensitiveHeader = regexp.MustCompile(
	`(?i)auth|token|secret|key|password|cookie`,
)

func flatHeaders(h http.Header) map[string]string {
	return flatHeadersRedacted(h, nil)
}

func flatHeadersRedacted(h http.Header, redactions []string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeader.MatchString(k) {
			out[k] = "***"
		} else {
			out[k] = redactCredentialSample(strings.Join(v, ", "), redactions)
		}
	}
	return out
}

func newSampler(capBytes int) *sampler {
	return &sampler{hash: sha256.New(), cap: capBytes}
}

func (s *sampler) Write(p []byte) (int, error) {
	s.hash.Write(p)
	s.n += int64(len(p))
	if remain := s.cap - s.buf.Len(); remain > 0 {
		take := len(p)
		if take > remain {
			take = remain
		}
		s.buf.Write(p[:take])
	}
	return len(p), nil
}

func (s *sampler) sha() string {
	if s.n == 0 {
		return ""
	}
	return hex.EncodeToString(s.hash.Sum(nil))
}

// bodyTruncatedMarker is appended to a persisted body sample when the
// full body exceeded the actions-table cap, so the dashboard can render
// a "truncated" badge instead of pretending the prefix is the whole
// body. The marker is a fixed ASCII sentinel the dashboard strips before
// parsing/rendering; see HttpBody in dashboard RequestDetailPage.tsx.
const bodyTruncatedMarker = "\n[clawpatrol:body-truncated]"

// truncated reports whether the sampler saw more bytes than it kept,
// i.e. the persisted sample is a prefix of the real body.
func (s *sampler) truncated() bool { return s.n > int64(s.cap) }

// sample returns the audit-log preview of the captured body. When
// encoding names a compression we know how to decode (gzip, br,
// deflate, zstd), the buffered prefix is decompressed first so a
// JSON response doesn't get rendered as "binary:<hex>" just because
// it's still on the wire compressed.
func (s *sampler) sample(encoding string) string {
	if s.buf.Len() == 0 {
		// An empty buffer with bytes counted means the cap was 0 (or the
		// body never reached the buffer); still flag truncation so the
		// dashboard doesn't render a capped body as the full thing.
		if s.truncated() {
			return bodyTruncatedMarker
		}
		return ""
	}
	raw := s.buf.Bytes()
	body := maybeDecode(raw, encoding)
	var out string
	if isPrintable(body) {
		out = string(body)
	} else {
		out = "binary:" + hex.EncodeToString(raw[:min(64, len(raw))])
	}
	if s.truncated() {
		out += bodyTruncatedMarker
	}
	return out
}

const (
	decodedSampleCap             = 4096
	decodedSampleTruncatedMarker = "\n[decoded response sample truncated]"
)

// maybeDecode returns the decompressed prefix of buf when encoding
// is a compression scheme we recognise, or buf unchanged otherwise.
// The sampler captures at most cap bytes, so the stream is almost
// always truncated mid-block — decoders return whatever they managed
// before hitting EOF, which is what we want for a preview. Decoded
// output is capped separately because tiny compressed inputs can expand
// far beyond the sampled wire bytes.
func maybeDecode(buf []byte, encoding string) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return buf
		}
		defer func() { _ = zr.Close() }()
		r = zr
	case "br":
		r = brotli.NewReader(bytes.NewReader(buf))
	case "deflate":
		// RFC 7230 says "deflate" is zlib-wrapped deflate, but some
		// servers send raw deflate. Try zlib first, fall back to raw.
		if zr, err := zlib.NewReader(bytes.NewReader(buf)); err == nil {
			defer func() { _ = zr.Close() }()
			r = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(buf))
			defer func() { _ = fr.Close() }()
			r = fr
		}
	case "zstd":
		zd, err := zstd.NewReader(bytes.NewReader(buf))
		if err != nil {
			return buf
		}
		defer zd.Close()
		r = zd
	default:
		return buf
	}
	out, _ := io.ReadAll(io.LimitReader(r, decodedSampleCap+1))
	if len(out) == 0 {
		return buf
	}
	if len(out) > decodedSampleCap {
		out = append(out[:decodedSampleCap:decodedSampleCap], decodedSampleTruncatedMarker...)
	}
	return out
}

func isPrintable(b []byte) bool {
	for _, x := range b {
		if x == 0 || (x < 0x20 && x != '\n' && x != '\r' && x != '\t') {
			return false
		}
	}
	return true
}

type teeReadCloser struct {
	r io.Reader
	c io.Closer
}

func (t teeReadCloser) Read(p []byte) (int, error) { return t.r.Read(p) }
func (t teeReadCloser) Close() error               { return t.c.Close() }

func wrapBodySampler(rc io.ReadCloser, s *sampler) io.ReadCloser {
	if rc == nil {
		return nil
	}
	return teeReadCloser{r: io.TeeReader(rc, s), c: rc}
}

// HITL — human-in-the-loop request approval. Rules with `approve = [...]`
// pause the upstream call until an operator approves on the dashboard,
// Slack, or another notifier. Decisions arrive over a per-request
// channel; the active request only remains resumable while the original
// client connection/context is alive.

// HITLPending and HITLDecision moved to config/runtime — declared
// there so approver plugins can produce them without importing main.

// HITLRegistry is the pool of pending approvals + per-pending decision
// channel. Approver runtimes (config/plugins/approvers) call Add to
// publish a pending entry and select on the returned channel.
// Dashboard's POST /api/hitl/decide calls DecideWithResult(id, decision)
// to resolve and receive operator-facing terminal-state details.
//
// Implements runtime.HITLPool via Add / Discard and preserves recent
// terminal states so stale Slack/dashboard prompts can explain whether
// a request was already decided, timed out, or lost its client.
const hitlTerminalTTL = 30 * time.Minute

type HITLRegistry struct {
	mu                    sync.Mutex
	pending               map[string]*pendingEntry
	terminal              map[string]terminalHITLEntry
	sink                  *Sink // SSE fan-out for the dashboard
	asyncGrantResolver    func(operationID string, d runtime.HITLDecision) runtime.HITLResolveResult
	pendingMessageUpdater func(ctx context.Context, pending runtime.HITLPending, ref string, result runtime.HITLResolveResult)
}

type pendingEntry struct {
	p           runtime.HITLPending
	decision    chan runtime.HITLDecision
	messageRefs []string
}

type terminalHITLEntry struct {
	result    runtime.HITLResolveResult
	pending   runtime.HITLPending
	refs      []string
	expiresAt time.Time
}

func newHITLRegistry(sink *Sink) *HITLRegistry {
	return &HITLRegistry{
		pending:  map[string]*pendingEntry{},
		terminal: map[string]terminalHITLEntry{},
		sink:     sink,
	}
}

// Add publishes a pending entry and returns its assigned id + a
// decision channel. Caller selects on the channel and calls Discard
// when ctx fires before the channel.
func (r *HITLRegistry) Add(p runtime.HITLPending) (string, <-chan runtime.HITLDecision) {
	p.ID = randomString(16)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	// Leave ExpiresAt zero when the caller set no real deadline. A
	// pure-sync park (builtin.dashboard) carries no enforced timeout — it
	// stays parked until a human decides or the agent disconnects — so we
	// must not fabricate one. Callers with a genuine deadline set ExpiresAt
	// themselves (human_approver does, via CreatedAt+timeout), and that is
	// actually enforced. pendingPoolView / the dashboard already guard on
	// ExpiresAt.IsZero(), so a zero value correctly renders as "no expiry"
	// instead of advertising a clock /pending never honors.
	ch := make(chan runtime.HITLDecision, 1)
	r.mu.Lock()
	r.pruneTerminalLocked(time.Now())
	r.pending[p.ID] = &pendingEntry{p: p, decision: ch}
	delete(r.terminal, p.ID)
	r.mu.Unlock()
	if r.sink != nil {
		r.sink.Emit(Event{
			Mode: "hitl_pending", Host: p.Host, Method: p.Method,
			Path: p.Path, AgentIP: p.AgentIP, Reason: p.Reason, Action: "pending",
		})
	}
	return p.ID, ch
}

func (r *HITLRegistry) Discard(id string) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (r *HITLRegistry) Update(id string, mutate func(*runtime.HITLPending)) bool {
	if mutate == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.pending[id]
	if e == nil {
		return false
	}
	mutate(&e.p)
	runtime.NormalizeHITLPendingApproval(&e.p)
	return true
}

// List returns pending entries sorted by CreatedAt ascending (oldest
// first), tiebroken on ID. The dashboard polls this endpoint once per
// second; Go's randomized map iteration would otherwise shuffle rows
// on every render and make the table flicker. Sort key is invariant
// across the sync_waiting → pending_approval Update transition (same
// ID, same CreatedAt), so a row keeps its position when its approval
// mode changes.
func (r *HITLRegistry) List() []runtime.HITLPending {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneTerminalLocked(time.Now())
	out := make([]runtime.HITLPending, 0, len(r.pending))
	for _, e := range r.pending {
		out = append(out, e.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Decide fires the pending entry's channel. Returns false when the
// id is unknown (already discarded / never existed).
func (r *HITLRegistry) Decide(id string, d runtime.HITLDecision) bool {
	return r.DecideWithResult(id, d).OK
}

// DecideWithResult resolves a pending entry and records the terminal
// state. Duplicate/stale clicks get the stored state back with OK=false.
func (r *HITLRegistry) DecideWithResult(id string, d runtime.HITLDecision) runtime.HITLResolveResult {
	state := runtime.HITLStateDenied
	if d.Allow {
		state = runtime.HITLStateApproved
	}
	reason := strings.TrimSpace(d.Reason)
	if reason == "" {
		verb := string(state)
		if d.By != "" {
			reason = fmt.Sprintf("%s by %s", verb, d.By)
		} else {
			reason = verb
		}
	}
	now := time.Now()
	r.mu.Lock()
	r.pruneTerminalLocked(now)
	e := r.pending[id]
	if e == nil {
		if terminal, ok := r.terminal[id]; ok {
			r.mu.Unlock()
			return terminal.result
		}
		r.mu.Unlock()
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	}
	if e.p.OperationID != "" && e.p.OperationState == runtime.HITLOperationStatePendingApproval && e.p.ApprovalEffect == runtime.HITLApprovalEffectCreateRetryGrant {
		resolver := r.asyncGrantResolver
		if resolver == nil {
			r.mu.Unlock()
			return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "async HITL retry-grant resolver is unavailable"}
		}
		delete(r.pending, id)
		r.mu.Unlock()

		result := resolver(e.p.OperationID, d)
		r.mu.Lock()
		r.terminal[id] = terminalHITLEntry{result: staleHITLResolveResult(result), expiresAt: now.Add(hitlTerminalTTL)}
		r.mu.Unlock()
		return result
	}
	refs := append([]string(nil), e.messageRefs...)
	pend := e.p
	e.decision <- d
	delete(r.pending, id)
	r.terminal[id] = terminalHITLEntry{
		result:    runtime.HITLResolveResult{OK: false, State: state, Reason: reason},
		expiresAt: now.Add(hitlTerminalTTL),
	}
	r.mu.Unlock()
	result := runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
	r.updateRecordedMessageRefs(context.Background(), pend, refs, result)
	return result
}

func staleHITLResolveResult(result runtime.HITLResolveResult) runtime.HITLResolveResult {
	result.OK = false
	return result
}

// Cancel resolves a pending entry without delivering a human decision.
// It is used when the original synchronous request times out or the
// client connection disappears before approval.
func (r *HITLRegistry) Cancel(id string, state runtime.HITLState, reason string) runtime.HITLResolveResult {
	if state == "" || state == runtime.HITLStatePending || state == runtime.HITLStateUnknown {
		state = runtime.HITLStateCanceled
	}
	if strings.TrimSpace(reason) == "" {
		reason = string(state)
	}
	e, result := r.resolve(id, state, reason)
	if e != nil && result.OK {
		r.updateRecordedMessageRefs(context.Background(), e.p, e.messageRefs, result)
	}
	return result
}

func (r *HITLRegistry) resolve(id string, state runtime.HITLState, reason string) (*pendingEntry, runtime.HITLResolveResult) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneTerminalLocked(now)
	e := r.pending[id]
	if e == nil {
		if terminal, ok := r.terminal[id]; ok {
			return nil, terminal.result
		}
		return nil, runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	}
	delete(r.pending, id)
	terminal := runtime.HITLResolveResult{OK: false, State: state, Reason: reason}
	r.terminal[id] = terminalHITLEntry{result: terminal, pending: e.p, refs: append([]string(nil), e.messageRefs...), expiresAt: now.Add(hitlTerminalTTL)}
	return e, runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
}

// RecordMessageRef records the channel-specific message id for a pending sync
// HITL prompt so terminal states (timeout/client disconnect) can proactively
// update the original Slack message. If the request already reached a terminal
// state before the notifier returned, use a fresh context to update immediately:
// the caller's request context is often canceled by then.
func (r *HITLRegistry) RecordMessageRef(_ context.Context, pendingID, ref string) error {
	if strings.TrimSpace(pendingID) == "" || strings.TrimSpace(ref) == "" {
		return nil
	}
	var pending runtime.HITLPending
	var result runtime.HITLResolveResult
	var shouldUpdate bool
	now := time.Now()
	r.mu.Lock()
	r.pruneTerminalLocked(now)
	if e := r.pending[pendingID]; e != nil {
		e.messageRefs = append(e.messageRefs, ref)
		r.mu.Unlock()
		return nil
	}
	if terminal, ok := r.terminal[pendingID]; ok {
		terminal.refs = append(terminal.refs, ref)
		r.terminal[pendingID] = terminal
		pending = terminal.pending
		result = terminal.result
		shouldUpdate = true
	}
	r.mu.Unlock()
	if shouldUpdate {
		r.updateRecordedMessageRefs(context.Background(), pending, []string{ref}, result)
	}
	return nil
}

func (r *HITLRegistry) updateRecordedMessageRefs(ctx context.Context, pending runtime.HITLPending, refs []string, result runtime.HITLResolveResult) {
	if r == nil || r.pendingMessageUpdater == nil {
		return
	}
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		r.pendingMessageUpdater(ctx, pending, ref, result)
	}
}

func (r *HITLRegistry) pruneTerminalLocked(now time.Time) {
	for id, entry := range r.terminal {
		if !entry.expiresAt.After(now) {
			delete(r.terminal, id)
		}
	}
}
