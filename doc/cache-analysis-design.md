# Cache-opportunity analysis (design)

Status: proposed (v1, advice-only). Implementation pending operator
sign-off — especially Phase 2.a (privacy).

## Goal

Dashboard-triggered, on-demand analysis that samples logged LLM
requests for a single endpoint, asks an analyzer LLM to identify
prompt-caching opportunities (repeated prefixes, large stable system
instructions, redundant context), and returns a structured report
to the operator. v1 is **advice-only** — the gateway does not
rewrite outgoing requests.

## Phase 1 findings (with file:line evidence)

### Request log content

- Storage: SQLite `actions` table. Columns added in
  `migrations/sqlite/0006_action_samples.sql:2-3` (`req_body`,
  `resp_body`) and `0001_initial.sql`.
- Insert site: `web.go:2056-2072` (`Sink.drain`).
- **Body cap = 4096 bytes.** `main.go:1908` (`newSampler(4096)` for
  request) and `main.go:1937` (response). Bodies longer than 4 KB
  are truncated at capture time. There is no flag to disable
  capture or raise the cap.
- This is the single most load-bearing constraint on the analyzer
  (see "Caveats" below).

### Single-action detail endpoint

- `GET /api/actions/<uuid>` → `apiActionByID` (`web.go:1346`,
  registered `web.go:242`). Returns the full `Event` JSON with
  truncated `req_body` / `resp_body`.
- TS type: `EventRecord` (`www/src/lib/api.ts:444-476`).
- "Download action" → `?fmt=fixture` (`writeActionFixture`,
  `web.go:1436`).

### Existing analytics

- `GET /api/analytics?range=...&agent=...&limit=...`
  (`web.go:1601-1753`). Returns sampled events (default 5 k,
  hard cap 10 k) + `total_count`, `error_count`, `by_device`,
  `by_host`.
- TS surface: `getAnalytics()` (`api.ts:507-523`).
- UI: `www/src/components/AnalyticsPage.tsx`.
- No existing "summary / report" endpoint. The cache analysis adds
  one as a sibling.

### Provider identification

- Endpoints in HCL are typed by **family** (`https`, `sql`, `k8s`)
  and a bare name, e.g.
  `endpoint "https" "anthropic" { hosts = ["api.anthropic.com"] }`.
  See `gateway.example.hcl:62-67`.
- Provider detection is host-keyed at request time:
  `main.go:678-687` (`trackKindFor`) maps
  `api.anthropic.com → claude_usage`, `api.openai.com → openai_usage`,
  `*.chatgpt.com → codex_ws_usage`. **No Gemini.**
- Action rows carry `endpoint` (`web.go:1885-1890`) — the cache
  analyzer can scope by endpoint name without reinventing provider
  detection.

### Existing client-side LLM call pattern

- The codebase already calls Anthropic and OpenAI as a client
  (rule-generation feature):
  - `callClaude` (`ai.go:316-360`) → `POST
    https://api.anthropic.com/v1/messages`, model `claude-haiku-4-5`,
    OAuth via `reg.Inject("claude", owner, req)`.
  - `callCodex` (`ai.go:365-411`) → `POST
    https://api.openai.com/v1/responses`, model `gpt-5-mini`.
- Raw `net/http`, no SDK dependency.

### Redaction surface

- `response_sanitize.go` only strips credential-bearing response
  **headers** (Set-Cookie, WWW-Authenticate, …). It does **not**
  redact request body content. Body redaction is a new build item
  for this feature.

## Phase 2 decisions

### (a) Privacy posture — operator opt-in per analysis, plus redaction

The analyzer sends *real* prompt content to an LLM. Three reasonable
shapes were proposed in the bead. Decision:

- **Per-run opt-in.** The "Run analysis" button opens a modal that
  names the analyzer provider/model and the endpoint being
  analyzed, and shows the estimated analyzer cost up-front. The
  request only fires after explicit confirm.
- **Programmatic redaction before send.** A new
  `redactForAnalyzer(body []byte) []byte` pass runs over each
  sampled body. v1 rules:
  - Header values matching `Authorization`, `X-Api-Key`,
    `OpenAI-API-Key`, `Anthropic-Api-Key` → `[REDACTED]`.
  - Body values matching configured `secret` block placeholders
    (already in HCL config — see `secrets.go`) → `[REDACTED]`.
  - High-entropy opaque runs (≥40 chars, alnum + `-`/`_`/`.`,
    Shannon entropy ≥ 4.5 bits/char) → `[REDACTED]`.
  Redaction is best-effort, not a security boundary. The opt-in
  modal explicitly says so.
- **Why not "operator-supplied analyzer endpoint"?** Adds new HCL
  surface for a v1 that we expect most operators to never use.
  Reuse the existing OAuth credential and revisit if the feature
  earns its keep.

Reasoning: the gateway already captures these bodies into local
SQLite (`web.go:2056-2072`). The new exposure surface is "this
content also reaches the analyzer provider once, per explicit
button click." Per-run opt-in keeps the activation threshold high;
redaction reduces accidental secret leakage.

### (b) Which LLM does the analysis — reuse existing Claude OAuth

- v1 hardcodes Claude as the analyzer, following the
  `callClaude` (`ai.go:316-360`) pattern.
- No new HCL block. No dedicated `analyzer_credential`. If usage
  pressure ever shows up, we can add the agent-selection logic
  from `generateRuleHCL` (`ai.go:178-196`) to also pick Codex.
- **Tradeoff vs. bead recommendation:** the bead suggested a
  dedicated `analyzer_credential` block "less foot-gunny." Counter:
  the existing OAuth is per-operator and per-device; cache analysis
  is a low-frequency operator action (estimated <10 runs/day per
  operator); the cost shows up in the same usage feed that already
  shows agent traffic, which is *more* discoverable, not less.

### (c) Sample selection

- **Time window:** operator-chosen, presets match the existing
  analytics page (`1m, 5m, 15m, 30m, 1h, 6h, 24h`). Default 24h.
- **Sampling rate:** reservoir sample of N=50 per run
  (configurable in the request body, hard cap 200). With the 4 KB
  body cap, 50 samples ≈ ≤200 KB of context — comfortably inside
  the analyzer model's window.
- **Per-endpoint scoping:** required, not optional. Operator picks
  exactly one endpoint from a dropdown listing endpoints with ≥1
  request in the window. Cross-endpoint analysis is meaningless
  (different providers, different cache mechanics).

### (d) Analyzer prompt & output shape — structured tool-use

The analyzer call uses Claude's tool-use feature with one tool
`report_cache_findings`, schema (JSON):

```
{
  "provider": "anthropic" | "openai" | "gemini" | "unknown",
  "findings": [
    {
      "prefix_excerpt": "<first ~200 chars of repeated prefix>",
      "estimated_repeat_count": <int>,
      "estimated_tokens_per_request": <int>,
      "estimated_monthly_savings_usd": <float>,
      "confidence": "low" | "medium" | "high",
      "suggested_change": "<one-paragraph fix>",
      "before_after": { "before": "...", "after": "..." } | null
    }
  ],
  "caveats": ["<short caveat string>"]
}
```

The meta-prompt:

- Names the provider (derived from the endpoint's host via the
  existing `trackKindFor` map).
- States the 4 KB body cap and the reservoir size explicitly, so
  the analyzer's savings estimates can be conservative.
- Encodes per-provider caching mechanics inline (see "Provider
  caching mechanics" below).

### (e) Dashboard surface

- New page `#/cache-analysis`, linked from the existing analytics
  navigation.
- Form: endpoint dropdown, range preset, sample-size input, "Run
  analysis" button.
- Confirmation modal (the privacy opt-in) before fire.
- Result panel: findings list (sortable by estimated savings),
  each finding rendered as prefix excerpt + repeat count +
  estimated tokens + estimated $/month + confidence chip +
  suggested change + optional before/after diff.
- v1 = one-shot. The latest run is cached server-side for the
  active session; navigating away loses it. **No history page.**
  If history earns its keep, add a `cache_analyses` table later.

### (f) Cost transparency — required

- The analyzer call returns `usage.input_tokens` and
  `usage.output_tokens`. Convert at the analyzer model's posted
  price (hardcoded constants for the chosen model; the rule-gen
  code uses `claude-haiku-4-5` so we reuse that).
- Display, at the top of the report:
  `This analysis cost $X.XXXX. Adopting all findings could save
   ≈ $Y/month if traffic stays similar.`

### (g) Action mode — out of scope for v1

The gateway does **not** rewrite outgoing requests in v1. The
report is advice-only. Auto-applied `cache_control` is a separate
feature.

## Caveats (operator-visible)

These appear verbatim on the report:

1. **4 KB body cap.** The gateway samples the first 4 KB of every
   request body (`main.go:1908`). The analyzer sees only that
   prefix. Token counts and savings estimates are *lower bounds*
   when real prompts exceed 4 KB.
2. **Reservoir sample.** N=50 by default; findings extrapolate
   from that sample. The confidence chip reflects this.
3. **Redaction is best-effort, not a security boundary.** Operators
   should treat the analyzer as a third party with access to the
   sampled prompts.

## Provider caching mechanics (analyzer reference)

The meta-prompt encodes the following so the analyzer's
recommendations are provider-correct.

- **Anthropic.** Explicit `cache_control: { type: "ephemeral" }`
  breakpoints on `messages[*]` / `system`. 5-min TTL default;
  1-hour TTL via beta header. Cache write 1.25× input price;
  cache read 0.1× input price. Minimum cacheable size as of 2026
  Q1: 1024 tokens for sonnet, 2048 for opus. Recommendation
  surface: where to place breakpoints; what to move to `system`.
- **OpenAI.** Server-side prompt caching is automatic for
  qualifying prompts; the operator action is *structural* —
  put stable content (system prompt, tool definitions, long
  reference material) at the start of the prompt, before
  user-varying content. No explicit cache directive.
- **Gemini.** Explicit context-caching API (`cachedContents`).
  v1 surfaces this provider only if the analyzer reports it; the
  gateway has no Gemini-specific code yet.

## Surfaces added by Phase 3 (sketch — not for sign-off here)

For visibility only. Phase 3 implementation will be a separate
review.

- Backend:
  - `POST /api/cache-analysis/run` — handler in a new
    `cache_analysis.go`. Body: `{ endpoint, range, sample_size }`.
    Pulls samples from `actions`, runs redaction, calls Claude
    with the tool-use prompt, returns the report.
  - `GET /api/cache-analysis/latest` — returns the most-recent
    run (in-memory only, per-operator).
  - Tests: redaction unit tests on synthetic inputs containing
    known secret placeholders; mock-analyzer test that asserts
    the response is parsed and returned to the dashboard; sample
    selection tests for various windows.
- Frontend:
  - `www/src/components/CacheAnalysisPage.tsx`.
  - New types + helpers in `lib/api.ts`.
- No schema migration in v1 (results live in process memory). Add
  one only if history earns its keep.

## Open questions for sign-off

1. **(a) privacy posture** — is per-run opt-in + best-effort
   redaction sufficient, or do you want operator-supplied
   analyzer endpoint as well?
2. **(b) analyzer credential** — OK to hardcode Claude OAuth, or
   do you want the dedicated `analyzer_credential` HCL block now?
3. **(c) sample defaults** — N=50, 24h, per-endpoint. Push back if
   the defaults look wrong.
4. **(d) tool-use vs. JSON-mode** — OK to depend on Anthropic's
   tool-use API for structured output, or prefer a stricter JSON
   schema in the user message?
5. **(e) history** — confirm v1 = one-shot (no persistence). If
   you want a history table, that's another migration plus a
   list endpoint and adds non-trivial surface.
