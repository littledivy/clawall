package credentials

// Tests for the signal_cli HITL notifier. testSecretStore is defined in
// slack_notify_test.go (same package) and reused here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func signalTestReq(store testSecretStore) runtime.ApproveRequest {
	return runtime.ApproveRequest{
		Secrets: store,
		Method:  "POST",
		Host:    "gitlab.com",
		Path:    "/api/v4/projects/1/issues",
		Profile: "uninfo",
	}
}

// withSignalClient points the notifier at a test server and disables the
// retry backoff, restoring both on cleanup.
func withSignalClient(t *testing.T, c *http.Client) {
	t.Helper()
	oldClient, oldBackoff := signalHTTPClient, signalRetryBackoff
	signalHTTPClient, signalRetryBackoff = c, 0
	t.Cleanup(func() { signalHTTPClient, signalRetryBackoff = oldClient, oldBackoff })
}

func TestSignalNotifyHITLSendsToV2Send(t *testing.T) {
	var gotPath, gotAuth string
	var payload struct {
		Number     string   `json:"number"`
		Recipients []string `json:"recipients"`
		Message    string   `json:"message"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{
		CredentialName: "signal-ops",
		Channel:        "+15551112222",
		PendingID:      "pending-9",
		DashboardURL:   "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	if gotPath != "/v2/send" {
		t.Fatalf("path = %q, want /v2/send", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("unexpected Authorization header %q (no auth configured)", gotAuth)
	}
	if payload.Number != "+15550000000" {
		t.Fatalf("number = %q, want +15550000000", payload.Number)
	}
	if len(payload.Recipients) != 1 || payload.Recipients[0] != "+15551112222" {
		t.Fatalf("recipients = %v, want [+15551112222]", payload.Recipients)
	}
	for _, want := range []string{"clawpatrol:", "https://gateway.example/#hitl/pending-9"} {
		if !strings.Contains(payload.Message, want) {
			t.Fatalf("message = %q, want substring %q", payload.Message, want)
		}
	}
}

func TestSignalNotifyHITLBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000", "auth": "rest:secretpw"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1", DashboardURL: "https://gw"})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	if !ok || user != "rest" || pass != "secretpw" {
		t.Fatalf("basic auth = %q/%q ok=%v, want rest/secretpw", user, pass, ok)
	}
}

func TestSignalNotifyHITLRetriesTransient5xx(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, `{"error":"busy"}`, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1", DashboardURL: "https://gw"})
	if err != nil {
		t.Fatalf("NotifyHITL after retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSignalNotifyHITLNoRetryOn4xx(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		http.Error(w, `{"error":"invalid recipient"}`, http.StatusBadRequest)
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "bad", PendingID: "p1", DashboardURL: "https://gw"})
	if err == nil {
		t.Fatal("NotifyHITL error = nil, want 4xx error")
	}
	if !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("error = %v, want the signal error body surfaced", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx must not retry)", attempts)
	}
}

func TestSignalNotifyHITLRequiresConfig(t *testing.T) {
	cases := map[string]struct {
		extras  map[string]string
		channel string
	}{
		"missing api_url": {map[string]string{"number": "+15550000000"}, "+15551112222"},
		"missing number":  {map[string]string{"api_url": "http://signal.invalid"}, "+15551112222"},
		"missing channel": {map[string]string{"api_url": "http://signal.invalid", "number": "+15550000000"}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
				"signal-ops": {Extras: tc.extras},
			}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: tc.channel, PendingID: "p1", DashboardURL: "https://gw"})
			if err == nil {
				t.Fatalf("%s: expected an error, got nil", name)
			}
		})
	}
}

func TestSignalHITLMessageRendersSummaryAndLink(t *testing.T) {
	msg := signalHITLMessage(runtime.ApproveRequest{
		Method:  "POST",
		Host:    "gitlab.com",
		Path:    "/api/v4/projects/1/issues",
		Profile: "uninfo",
	}, runtime.HITLTarget{
		PendingID:    "abc",
		DashboardURL: "https://gateway.example/",
		Summary: &runtime.HITLSummary{
			Subject:    "POST /api/v4/projects/1/issues",
			Label:      "write",
			Confidence: 90,
			Summary:    "creates an issue",
		},
	})
	for _, want := range []string{
		"clawpatrol:",
		"POST /api/v4/projects/1/issues",
		"Label: write (90%)",
		"Summary: creates an issue",
		"agent: uninfo",
		"https://gateway.example/#hitl/abc",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}
