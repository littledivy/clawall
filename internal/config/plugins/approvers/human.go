package approvers

// human_approver: targets one channel via a credential's HITLNotifier
// (Slack chat.postMessage, Discord webhook, Telegram sendMessage,
// etc.). The credential plugin owns the channel-specific wire shape;
// this approver just publishes to the dashboard pool and dispatches
// the prompt. First operator to act — pool decide via dashboard or
// channel-side action — wins.
//
// Empty Channel / Credential → falls through to dashboard-only.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// HumanApprover targets one channel. Timeout / require_approvers
// override the global defaults block on a per-approver basis.
//
// Credential references a credential whose body satisfies HITLNotifier
// (slack_tokens and signal_cli today; future Discord / Telegram / SMTP
// credentials).
// Leave empty for a dashboard-only approver (no channel notification;
// operator clicks approve/deny on the dashboard).
type HumanApprover struct {
	// Channel is the destination channel, chat id, or equivalent
	// notifier-specific target.
	Channel string `hcl:"channel"`
	// Credential references the notifier credential used to post
	// approval requests. Leave empty for dashboard-only approval.
	Credential string `hcl:"credential,optional"`
	// Timeout overrides the gateway's human_timeout for this approver,
	// in seconds.
	Timeout int `hcl:"timeout,optional"`
	// RequireApprovers is the number of separate human approvals
	// required before the request is allowed.
	RequireApprovers int `hcl:"require_approvers,optional"`
	// SyncWaitTimeout is the HTTP hold budget before an async-capable
	// HITL request returns 202 and moves to polling/retry-grant mode.
	// Optional, including when async_grant is enabled: when unset the
	// gateway parks the request synchronously for the full approval
	// window (it holds the connection until a human decides) and never
	// hands back a 202 — the async retry-grant path stays dormant.
	SyncWaitTimeout string `hcl:"sync_wait_timeout,optional" json:"sync_wait_timeout,omitempty"`
	// AsyncGrant configures v1 HITL async retry grants for this approver.
	// The nested block must set enabled = true, and the active profile must
	// also set hitl_async_grants = true, before async behavior is effective.
	AsyncGrant *config.HITLAsyncGrantConfig `hcl:"async_grant,block" json:"async_grant,omitempty"`
	// Interactive toggles in-channel approve/deny buttons. Requires the
	// referenced credential's signing_secret slot pasted via the
	// dashboard AND Slack's Interactivity URL pointed at the gateway.
	// Default false: message includes only an "Open dashboard" link.
	Interactive bool `hcl:"interactive,optional"`
	// Classifier optionally references an llm_approver by name. When set,
	// the approver calls the classifier's Summarize method before posting
	// the HITL notification, enriching the Slack card with request summary
	// metadata. Classifier failures are non-fatal — the generic card is used
	// as fallback.
	Classifier string `hcl:"classifier,optional"`
	// Message is an optional Go-template-style string with {{var}}
	// placeholders. When set, the expanded text replaces the default
	// section body in the Slack (or other notifier) card. Supported
	// vars mirror the CEL facet namespace: {{http.method}},
	// {{http.path}}, {{k8s.verb}}, {{sql.tables}}, {{http.body_json.resource_id}},
	// {{profile}}, {{endpoint}}, {{reason}}, etc.
	// Classifier (if also set) still runs; Message takes display precedence.
	Message string `hcl:"message,optional"`
}

// HumanApproverChannel + HumanApproverCredential expose the fields
// the gateway's HITL wiring needs without main importing this package
// — main does an anonymous-interface type-assert on ent.Body.
func (h *HumanApprover) HumanApproverChannel() string { return h.Channel }

// HumanApproverCredential is part of the clawpatrol plugin API.
func (h *HumanApprover) HumanApproverCredential() string { return h.Credential }

// HumanApproverInteractive is part of the clawpatrol plugin API.
func (h *HumanApprover) HumanApproverInteractive() bool { return h.Interactive }

// HITLAsyncGrantEnabled exposes the async opt-in to config-level cross validation.
func (h *HumanApprover) HITLAsyncGrantEnabled() bool {
	return h != nil && h.AsyncGrant != nil && h.AsyncGrant.Enabled
}

// HITLSyncWaitTimeout returns the parsed synchronous hold budget.
func (h *HumanApprover) HITLSyncWaitTimeout() time.Duration {
	if h == nil || h.SyncWaitTimeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(h.SyncWaitTimeout)
	return d
}

// HITLAsyncApprovalTTL returns the async pending approval lifetime,
// derived as the approver's overall timeout minus the synchronous wait
// window: once the sync wait elapses and the request falls back to a
// 202, the grant should stay pending only for whatever is left of the
// approval budget. When sync_wait_timeout >= the approver timeout the
// difference is non-positive; we clamp to zero so the grant is born
// already expired rather than carrying a negative lifetime.
func (h *HumanApprover) HITLAsyncApprovalTTL(policy *config.CompiledPolicy) time.Duration {
	ttl := h.approvalTimeout(policy) - h.HITLSyncWaitTimeout()
	if ttl < 0 {
		return 0
	}
	return ttl
}

// HITLAsyncApprovedRetryTTL returns the post-approval retry grant lifetime.
func (h *HumanApprover) HITLAsyncApprovedRetryTTL() time.Duration {
	d, _ := h.AsyncGrant.ApprovedRetryTTLDuration()
	return d
}

// HITLAsyncMaxBodyBytes returns the raw-body fingerprinting size limit.
func (h *HumanApprover) HITLAsyncMaxBodyBytes() int64 {
	return h.AsyncGrant.MaxBodyBytesValue()
}

// HITLAsyncFingerprintBody returns the v1 request fingerprint mode.
func (h *HumanApprover) HITLAsyncFingerprintBody() string {
	return h.AsyncGrant.FingerprintBodyValue()
}

// Approve is part of the clawpatrol plugin API.
func (h *HumanApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("human approver %q: no pool", req.ApproverName)
	}
	timeout := h.approvalTimeout(req.Policy)
	pending := buildPending(req)
	pending.ExpiresAt = pending.CreatedAt.Add(timeout)
	id, ch := req.Pool.Add(pending)
	discardOnReturn := true
	defer func() {
		if discardOnReturn {
			req.Pool.Discard(id)
		}
	}()

	var summary *runtime.HITLSummary
	if h.Classifier != "" && req.Policy != nil {
		if ent, ok := req.Policy.Approvers[h.Classifier]; ok {
			if clf, ok := ent.Body.(runtime.HITLClassifier); ok {
				if s, err := clf.Summarize(ctx, req); err == nil {
					summary = s
				} else {
					log.Printf("human approver %s: classifier %q: %v", req.ApproverName, h.Classifier, err)
				}
			}
		}
	}

	notifyChannel := h.Channel
	if req.NotifyChannel != "" {
		notifyChannel = req.NotifyChannel
	}
	if notifyChannel != "" && h.Credential != "" && req.Policy != nil {
		ent, ok := req.Policy.Credentials[h.Credential]
		if ok {
			if notifier, ok := ent.Body.(runtime.HITLNotifier); ok {
				var msg string
				if h.Message != "" {
					msg = expandMessage(h.Message, req)
				}
				target := runtime.HITLTarget{
					CredentialName:           h.Credential,
					Channel:                  notifyChannel,
					Interactive:              h.Interactive,
					PendingID:                id,
					DashboardURL:             req.DashboardURL,
					ThreadTS:                 req.ThreadTS,
					OperationState:           pending.OperationState,
					ApprovalEffect:           pending.ApprovalEffect,
					UpstreamCalled:           pending.UpstreamCalled,
					ApprovalMessage:          pending.ApprovalMessage,
					Summary:                  summary,
					Message:                  msg,
					MessageUpdateSink:        req.MessageUpdateSink,
					PendingMessageUpdateSink: req.PendingMessageUpdateSink,
				}
				go func() {
					if err := notifier.NotifyHITL(ctx, req, target); err != nil {
						log.Printf("human approver %s: notify: %v", req.ApproverName, err)
					}
				}()
			} else {
				log.Printf("human approver %s: credential %q does not implement HITLNotifier", req.ApproverName, h.Credential)
			}
		} else {
			log.Printf("human approver %s: credential %q not declared", req.ApproverName, h.Credential)
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case d := <-ch:
		return verdictFromDecision(d), nil
	case <-timer.C:
		reason := fmt.Sprintf("approver %q timed out after %s; upstream request was not sent", req.ApproverName, timeout)
		result := cancelPending(req.Pool, id, runtime.HITLStateTimedOut, reason)
		if verdict, ok := terminalDecisionVerdict(result, ch); ok {
			return verdict, nil
		}
		return runtime.ApproveVerdict{
			Reason: reason,
		}, nil
	case <-ctx.Done():
		if req.AsyncPendingOnSyncTimeout && errors.Is(ctx.Err(), context.DeadlineExceeded) && req.AsyncOperationID != "" {
			reason := fmt.Sprintf("approver %q sync wait timed out; upstream request was not sent and async approval remains pending", req.ApproverName)
			if updater, ok := req.Pool.(runtime.HITLPoolUpdater); ok {
				updated := updater.Update(id, func(p *runtime.HITLPending) {
					p.OperationID = req.AsyncOperationID
					p.OperationState = runtime.HITLOperationStatePendingApproval
					p.ApprovalEffect = runtime.HITLApprovalEffectCreateRetryGrant
					p.UpstreamCalled = false
					p.ApprovalMessage = ""
					runtime.NormalizeHITLPendingApproval(p)
				})
				if updated {
					discardOnReturn = false
					return runtime.ApproveVerdict{Decision: runtime.ApproveDecisionAsyncPending, Reason: reason}, nil
				}
			}
		}
		state, reason := hitlCancelStateForContext(ctx.Err())
		result := cancelPending(req.Pool, id, state, reason)
		if verdict, ok := terminalDecisionVerdict(result, ch); ok {
			return verdict, nil
		}
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}

func (h *HumanApprover) approvalTimeout(policy *config.CompiledPolicy) time.Duration {
	timeout := time.Duration(h.Timeout) * time.Second
	if timeout <= 0 && policy != nil {
		timeout = time.Duration(policy.HumanTimeout) * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return timeout
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "human_approver",
		New:     func() any { return &HumanApprover{} },
		Runtime: (*HumanApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
			{Path: "Classifier", Kind: config.KindApprover, Optional: true},
		},
		Validate: func(d any, name string, _ *config.BuildCtx) hcl.Diagnostics {
			a := d.(*HumanApprover)
			return config.ValidateHITLAsyncGrant(name, a.SyncWaitTimeout, a.AsyncGrant)
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*HumanApprover)
			ri := config.EmitRefIndex()
			b.SetAttributeValue("channel", cty.StringVal(a.Channel))
			if a.Credential != "" {
				config.SetIdent(b, "credential", ri.Ref(config.KindCredential, a.Credential))
			}
			if a.Timeout != 0 {
				b.SetAttributeValue("timeout", cty.NumberIntVal(int64(a.Timeout)))
			}
			if a.RequireApprovers != 0 {
				b.SetAttributeValue("require_approvers", cty.NumberIntVal(int64(a.RequireApprovers)))
			}
			if a.SyncWaitTimeout != "" {
				b.SetAttributeValue("sync_wait_timeout", cty.StringVal(a.SyncWaitTimeout))
			}
			if a.AsyncGrant != nil {
				ag := b.AppendNewBlock("async_grant", nil).Body()
				if a.AsyncGrant.Enabled {
					ag.SetAttributeValue("enabled", cty.True)
				}
				if a.AsyncGrant.ApprovedRetryTTL != "" {
					ag.SetAttributeValue("approved_retry_ttl", cty.StringVal(a.AsyncGrant.ApprovedRetryTTL))
				}
				if a.AsyncGrant.FingerprintBody != "" {
					ag.SetAttributeValue("fingerprint_body", cty.StringVal(a.AsyncGrant.FingerprintBody))
				}
				if a.AsyncGrant.MaxBodyBytes != nil {
					ag.SetAttributeValue("max_body_bytes", cty.NumberIntVal(int64(*a.AsyncGrant.MaxBodyBytes)))
				}
			}
			if a.Interactive {
				b.SetAttributeValue("interactive", cty.True)
			}
			if a.Classifier != "" {
				config.SetIdent(b, "classifier", ri.Ref(config.KindApprover, a.Classifier))
			}
			if a.Message != "" {
				b.SetAttributeValue("message", cty.StringVal(a.Message))
			}
		},
	})
}
