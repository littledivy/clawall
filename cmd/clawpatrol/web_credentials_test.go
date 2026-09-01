package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

type testSecretSlots []config.SecretSlot

func (s testSecretSlots) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot(s)
}

func TestAPICredentialsSetPreservesUntouchedSlotsAndClearsExplicitEmpty(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for slot, value := range map[string]string{
		"cert": "old-cert",
		"key":  "old-key",
		"ca":   "old-ca",
	} {
		if err := setCredentialSlot(db, "client-tls", slot, value); err != nil {
			t.Fatalf("seed slot %q: %v", slot, err)
		}
	}

	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"client-tls": {
				Body: testSecretSlots{
					{Name: "cert", Label: "Client certificate"},
					{Name: "key", Label: "Client key"},
					{Name: "ca", Label: "CA certificate"},
				},
			},
		},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/set",
		strings.NewReader(`{"id":"client-tls","owner":"default","slots":{"cert":"new-cert","ca":""}}`),
	)
	req = req.WithContext(contextWithRoles(req.Context(), []roleBinding{{roleAdmin, scopeGlobal}}))
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	sec, ok, err := readCredentialSecrets(db, "client-tls")
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}
	if !ok {
		t.Fatalf("credential secrets not found")
	}
	if got := sec.Extras["cert"]; got != "new-cert" {
		t.Fatalf("cert slot = %q, want new-cert", got)
	}
	if got := sec.Extras["key"]; got != "old-key" {
		t.Fatalf("key slot = %q, want old-key", got)
	}
	if _, ok := sec.Extras["ca"]; ok {
		t.Fatalf("ca slot was preserved after explicit empty update")
	}
}
