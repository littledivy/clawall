package credentials

// signal_cli: deliver HITL approval prompts to Signal via a
// signal-cli-rest-api instance (https://github.com/bbernhard/signal-cli-rest-api).
//
// Signal has no bot/HTTP API of its own and no interactive button UI,
// so this is a notification-only notifier: it POSTs a plain-text prompt
// ending with an "Open dashboard" link, and the human approves/denies
// there. It implements HITLNotifier only — there is no HTTP injection
// runtime and no WebhookProvider callback (contrast slack.go).
//
// Config is pasted via the dashboard secret slots:
//
//   - api_url: base URL of the signal-cli-rest-api (e.g. http://localhost:8080)
//   - number:  the registered Signal sender number, E.164 (+15551234567)
//   - auth:    optional "user:pass" if the REST API is behind HTTP basic auth
//
// The recipient is the human_approver block's `channel` — a recipient
// number (E.164) or a "group.<base64-id>" group identifier.
//
// Adding another notification channel is a new credential plugin with
// its own NotifyHITL — no human_approver / runtime.go changes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// SignalCLI is a notification-only HITL notifier that delivers approval
// prompts to Signal via a signal-cli-rest-api instance
// (https://github.com/bbernhard/signal-cli-rest-api). Signal has no
// interactive buttons, so the prompt is plain text ending in an
// "Open dashboard" link where the operator approves or denies.
//
// It has no HCL attributes; connection details live in the secret store as
// named slots, filled via the dashboard: api_url (base URL of the
// signal-cli-rest-api), number (the registered E.164 sender), and auth
// (optional "user:pass" for HTTP basic auth). The recipient is the
// human_approver's channel - an E.164 number or a "group.<base64-id>".
type SignalCLI struct{}

var (
	signalHTTPClient   = &http.Client{Timeout: 10 * time.Second}
	signalRetryBackoff = 500 * time.Millisecond
)

// signalSendPath is the signal-cli-rest-api v2 send endpoint.
const signalSendPath = "/v2/send"

// signalMessageMax bounds the prompt text. Signal messages can be long,
// but we keep individual sections trimmed so a giant body/path can't
// blow up the message; this is a soft overall guard.
const signalMessageMax = 4000

// SecretSlots is part of the clawpatrol plugin API.
func (*SignalCLI) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "api_url", Label: "signal-cli-rest-api URL", Description: "Base URL of the signal-cli-rest-api, e.g. http://localhost:8080"},
		{Name: "number", Label: "Sender number", Description: "Registered Signal number in E.164 form, e.g. +15551234567"},
		{Name: "auth", Label: "Basic auth (optional)", Description: "user:pass if the REST API is behind HTTP basic auth"},
	}
}

// NotifyHITL posts an approval prompt to the operator's Signal recipient
// via signal-cli-rest-api's POST /v2/send. api_url + number come from the
// credential's secret slots (fetched per-call via the request's
// SecretStore so dashboard rotations apply); the recipient is the
// approver block's channel.
func (s *SignalCLI) NotifyHITL(ctx context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
	if req.Secrets == nil {
		return fmt.Errorf("no secret store on request")
	}
	sec, err := req.Secrets.Get(target.CredentialName)
	if err != nil {
		return fmt.Errorf("fetch credential %s: %w", target.CredentialName, err)
	}
	apiURL := strings.TrimRight(sec.Extras["api_url"], "/")
	number := strings.TrimSpace(sec.Extras["number"])
	if apiURL == "" || number == "" {
		return fmt.Errorf("credential %s missing api_url or number (paste them via the dashboard)", target.CredentialName)
	}
	if strings.TrimSpace(target.Channel) == "" {
		return fmt.Errorf("human approver %s has no channel (set it to a Signal recipient number or group.<id>)", target.CredentialName)
	}

	body := map[string]any{
		"number":     number,
		"recipients": []string{target.Channel},
		"message":    signalHITLMessage(req, target),
	}
	buf, _ := json.Marshal(body)
	return signalPostSend(ctx, apiURL+signalSendPath, sec.Extras["auth"], buf)
}

// signalHITLMessage renders the plain-text prompt. Signal has no rich
// blocks or buttons, so it is a compact text card ending with the
// dashboard link where the operator approves or denies.
func signalHITLMessage(req runtime.ApproveRequest, target runtime.HITLTarget) string {
	endpoint := runtime.HITLEndpointLabel(req)
	title := runtime.HITLTitle(req.Method, endpoint)

	var b strings.Builder
	b.WriteString("clawpatrol: " + signalTrunc(title, 200) + "\n")

	switch {
	case strings.TrimSpace(target.Message) != "":
		b.WriteString("\n" + signalTrunc(target.Message, 1500) + "\n")
	case target.Summary != nil:
		sm := target.Summary
		if sm.Subject != "" {
			b.WriteString("\n" + signalTrunc(sm.Subject, 200) + "\n")
		}
		label := sm.Label
		if sm.Confidence > 0 {
			if label == "" {
				label = fmt.Sprintf("%d%% confidence", sm.Confidence)
			} else {
				label += fmt.Sprintf(" (%d%%)", sm.Confidence)
			}
		}
		if label != "" {
			b.WriteString("Label: " + label + "\n")
		}
		if sm.Summary != "" {
			b.WriteString("Summary: " + signalTrunc(sm.Summary, 500) + "\n")
		}
	default:
		if req.Path != "" {
			b.WriteString("\n" + runtime.HITLQueryLabel(req.Endpoint) + ": " + signalTrunc(req.Path, 800) + "\n")
		}
	}

	if req.Profile != "" {
		b.WriteString("agent: " + signalTrunc(req.Profile, 80) + "\n")
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		b.WriteString("reason: " + signalTrunc(r, 200) + "\n")
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		b.WriteString("\nBody:\n" + signalTrunc(bs, 800) + "\n")
	}
	if g := signalHITLApprovalGuidance(target); g != "" {
		b.WriteString("\n" + signalTrunc(g, 1000) + "\n")
	}

	// Bound the variable content, then append the dashboard link last and
	// unconditionally — so an overflowing body/summary can never truncate
	// away the approve/deny link, the actionable part of the prompt.
	content := strings.TrimRight(signalTrunc(b.String(), signalMessageMax), "\n")
	link := strings.TrimRight(target.DashboardURL, "/") + "/#hitl/" + target.PendingID
	return content + "\n\nApprove or deny: " + link
}

// signalHITLApprovalGuidance mirrors the Slack notifier's guidance line:
// it tells the operator whether approving executes the upstream call
// immediately or only authorizes a one-shot retry grant.
func signalHITLApprovalGuidance(target runtime.HITLTarget) string {
	if m := strings.TrimSpace(target.ApprovalMessage); m != "" {
		return m
	}
	if target.OperationState == "" && target.ApprovalEffect == "" && !target.UpstreamCalled {
		return ""
	}
	state := target.OperationState
	if state == "" {
		state = runtime.HITLOperationStateSyncWaiting
	}
	effect := target.ApprovalEffect
	if effect == "" {
		effect = runtime.HITLApprovalEffectForOperationState(state)
	}
	return runtime.HITLApprovalMessage(state, effect, target.UpstreamCalled)
}

// signalPostSend POSTs the send request with one retry on transient
// failure, mirroring the Slack notifier's backoff behavior.
func signalPostSend(ctx context.Context, endpoint, auth string, buf []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(buf))
		if err != nil {
			return err
		}
		hreq.Header.Set("Content-Type", "application/json")
		if auth != "" {
			if user, pass, ok := strings.Cut(auth, ":"); ok {
				hreq.SetBasicAuth(user, pass)
			}
		}

		resp, err := signalHTTPClient.Do(hreq)
		if err == nil {
			lastErr = signalDecodeResponse(resp)
			if closeErr := resp.Body.Close(); lastErr == nil && closeErr != nil {
				lastErr = closeErr
			}
		} else {
			lastErr = err
		}
		if lastErr == nil {
			return nil
		}
		if attempt == 2 || !signalShouldRetry(resp, err) {
			return lastErr
		}
		log.Printf("signal notify: %s failed on attempt %d, retrying once: %v", signalSendPath, attempt, lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(signalRetryBackoff):
		}
	}
	return lastErr
}

func signalDecodeResponse(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("signal %s: missing response", signalSendPath)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(respBody))
		// signal-cli-rest-api returns {"error":"..."} on failure.
		var parsed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &parsed) == nil && parsed.Error != "" {
			msg = parsed.Error
		}
		log.Printf("signal notify: %s failed: status=%d error=%q", signalSendPath, resp.StatusCode, signalTrunc(msg, 300))
		return fmt.Errorf("signal %s error: HTTP %d: %s", signalSendPath, resp.StatusCode, signalTrunc(msg, 300))
	}
	return nil
}

func signalShouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
}

func signalTrunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func init() {
	var _ runtime.HITLNotifier = (*SignalCLI)(nil)
	config.Register(&config.Plugin{
		Kind: config.KindCredential,
		Type: "signal_cli",
		// Notifier-only: no HTTP/SQL/TLS injection runtime, so Runtime is
		// nil (schema-only). The approver and dashboard read NotifyHITL /
		// SecretSlots off the built body (ent.Body), not off Runtime.
		New:   newer[SignalCLI](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
