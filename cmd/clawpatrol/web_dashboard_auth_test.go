package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// newDashboardTestMux opens a fresh in-temp-dir DB, optionally seeds
// the root password row, and returns a webMux wired to it. Tests use
// this instead of building a partial Gateway by hand — the gate
// reads from the DB, so a real (if temporary) DB is required.
func newDashboardTestMux(t *testing.T, cfg *config.Gateway, rootPassword string) *webMux {
	t.Helper()
	if cfg == nil {
		cfg = &config.Gateway{}
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if rootPassword != "" {
		if err := setDashboardUser(db, dashboardRootUsername, rootPassword); err != nil {
			t.Fatalf("seed root password: %v", err)
		}
	}
	g := &Gateway{db: db}
	g.cfg.Store(cfg)
	return &webMux{g: g}
}

// mintTestSessionCookie creates a real session row + returns the
// matching cookie. Used by tests that need to send an authenticated
// request through the gate without typing a password.
func mintTestSessionCookie(t *testing.T, w *webMux) *http.Cookie {
	t.Helper()
	token, err := createDashboardSession(w.g.db, dashboardRootUsername, w.dashboardSessionTTL())
	if err != nil {
		t.Fatalf("createDashboardSession: %v", err)
	}
	return &http.Cookie{Name: cpSessionCookieName, Value: token}
}

func TestLookupSessionFromRequestAcceptsCookie(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
	c := mintTestSessionCookie(t, w)

	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(c)
	if got := w.lookupSessionFromRequest(r); got != dashboardRootUsername {
		t.Fatalf("lookupSessionFromRequest = %q, want %q", got, dashboardRootUsername)
	}
}

func TestLookupSessionFromRequestRejectsWrongCookie(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(&http.Cookie{Name: cpSessionCookieName, Value: "not-a-real-token"})
	if got := w.lookupSessionFromRequest(r); got != "" {
		t.Fatalf("lookupSessionFromRequest = %q, want empty", got)
	}
}

func TestLookupSessionFromRequestEmpty(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	if got := w.lookupSessionFromRequest(r); got != "" {
		t.Fatalf("lookupSessionFromRequest = %q, want empty (no cookie)", got)
	}
}

// TestDashboardLoginGetDoesNotMintSession: hitting the form via GET
// must never create a session row or set a cookie, even when query
// params look credential-ish. (Pre-#456 regression guard against
// query-string passwords sneaking through.)
func TestDashboardLoginGetDoesNotMintSession(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/__login?password=correct-horse-battery-staple&next=/api/state", nil)
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	if cookies := rw.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("GET /__login set cookies: %+v", cookies)
	}
}

func TestDashboardLoginUsesConfiguredBranding(t *testing.T) {
	cfg := &config.Gateway{Settings: &config.GatewaySettings{
		DashboardName:    "Acme Gateway",
		DashboardLogoURL: "https://assets.example.test/acme-logo.svg",
		DashboardIconURL: "https://assets.example.test/acme-icon.svg",
	}}
	w := newDashboardTestMux(t, cfg, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/__login", nil)
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	body := rw.Body.String()
	for _, want := range []string{
		"Log in — Acme Gateway",
		`href="https://assets.example.test/acme-icon.svg"`,
		`src="https://assets.example.test/acme-logo.svg"`,
		`<span class="brand-name">Acme Gateway</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q:\n%s", want, body)
		}
	}
}

func TestDashboardIndexInjectsInitialBranding(t *testing.T) {
	cfg := &config.Gateway{Settings: &config.GatewaySettings{
		DashboardName:    "Acme Gateway",
		DashboardLogoURL: "https://assets.example.test/acme-logo.svg",
		DashboardIconURL: "https://assets.example.test/acme-icon.svg",
	}}
	w := newDashboardTestMux(t, cfg, "correct-horse-battery-staple")

	body := string(w.dashboardIndexWithBranding([]byte(`<!doctype html><html><head><title>Claw Patrol</title><link rel="icon" type="image/svg+xml" href="/claw-patrol-icon.svg" /></head><body></body></html>`)))
	for _, want := range []string{
		"<title>Acme Gateway</title>",
		`href="https://assets.example.test/acme-icon.svg"`,
		"window.__CLAWPATROL_INITIAL_BRANDING__",
		`"name":"Acme Gateway"`,
		`"logo_url":"https://assets.example.test/acme-logo.svg"`,
		`"icon_url":"https://assets.example.test/acme-icon.svg"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("index missing %q:\n%s", want, body)
		}
	}
}

func TestDashboardLoginRejectsProtocolRelativeNext(t *testing.T) {
	tests := []struct {
		name      string
		queryNext string
		want      string
	}{
		{name: "valid dashboard path", queryNext: "/dashboard", want: "/dashboard"},
		{name: "protocol-relative URL", queryNext: "//evil.example/path", want: "/"},
		{name: "encoded protocol-relative URL", queryNext: "%2F%2Fevil.example%2Fpath", want: "/"},
		{name: "encoded backslash authority", queryNext: "%2F%5C%5Cevil.example%2Fpath", want: "/"},
		{name: "absolute URL", queryNext: "https%3A%2F%2Fevil.example%2Fpath", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
			r := httptest.NewRequest(http.MethodPost, "/__login?next="+tt.queryNext, strings.NewReader("password=correct-horse-battery-staple"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			w.apiDashboardLogin(rw, r)

			if rw.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rw.Code, http.StatusFound)
			}
			if got := rw.Result().Header.Get("Location"); got != tt.want {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDashboardLoginFirstRunMintsSession verifies the first-run flow:
// with no root row, POSTing matching password+confirm fields creates
// the row, mints a session, sets the cookie to the token (not the
// password!), and redirects.
func TestDashboardLoginFirstRunMintsSession(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	const pw = "first-run-passphrase-1234"
	body := strings.NewReader("password=" + pw + "&confirm=" + pw)
	r := httptest.NewRequest(http.MethodPost, "/__login?next=/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %s)", rw.Code, http.StatusFound, rw.Body.String())
	}
	var got *http.Cookie
	for _, c := range rw.Result().Cookies() {
		if c.Name == cpSessionCookieName {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("no cp_session cookie set after first-run setup")
	}
	if got.Value == "" {
		t.Fatal("cp_session cookie has empty value")
	}
	if got.Value == pw {
		t.Fatal("cp_session cookie holds the raw password — must be an opaque token")
	}
	if user, ok, _ := lookupDashboardSession(w.g.db, got.Value); !ok || user != dashboardRootUsername {
		t.Fatalf("session row missing for cookie value: ok=%v user=%q", ok, user)
	}
}

func TestDashboardLoginFirstRunMismatchRejected(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	body := strings.NewReader("password=first-run-passphrase-1234&confirm=different-passphrase-1234")
	r := httptest.NewRequest(http.MethodPost, "/__login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
	}
	if _, exists, _ := lookupDashboardUser(w.g.db, dashboardRootUsername); exists {
		t.Fatal("root row should not exist after mismatched first-run")
	}
}

func TestDashboardLoginFirstRunRejectsShortPassword(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	body := strings.NewReader("password=short&confirm=short")
	r := httptest.NewRequest(http.MethodPost, "/__login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
	}
}

// TestDashboardLogoutRevokesSessionAndClearsCookie covers the logout
// endpoint end-to-end: the row must be gone after POST and the
// browser must receive a Max-Age=-1 clearer for cp_session.
func TestDashboardLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
	c := mintTestSessionCookie(t, w)

	r := httptest.NewRequest(http.MethodPost, "/__logout", nil)
	r.AddCookie(c)
	rw := httptest.NewRecorder()
	w.apiDashboardLogout(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	if user, ok, _ := lookupDashboardSession(w.g.db, c.Value); ok || user != "" {
		t.Fatal("session row survived logout")
	}
	var clearCookie *http.Cookie
	for _, set := range rw.Result().Cookies() {
		if set.Name == cpSessionCookieName {
			clearCookie = set
		}
	}
	if clearCookie == nil || clearCookie.MaxAge >= 0 {
		t.Fatalf("expected clearing cookie with MaxAge<0, got %+v", clearCookie)
	}
}

func TestDashboardLogoutRejectsGET(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
	r := httptest.NewRequest(http.MethodGet, "/__logout", nil)
	rw := httptest.NewRecorder()
	w.apiDashboardLogout(rw, r)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusMethodNotAllowed)
	}
}
