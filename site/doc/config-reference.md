# Config Reference

A clawpatrol gateway config mixes **operational** settings in the
required top-level `gateway { ... }` block with **policy** blocks.
Policy blocks (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
dispatch to a plugin chosen by the block's first label.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — the HCL value type. `string`, `bool`, `int` are scalar
  literals; `[]string` is a list of strings; `ref(<kind>)` is a
  typed reference to another block (`<type>.<name>` for
  two-label kinds like `credential = bearer_token.github`,
  `<kind>.<name>` for one-label kinds like `rule = rule.no-pii`);
  `[]ref(<kind>)` is a list of such references; nested blocks have
  their shape described inline.
- **Required** — `yes` if the loader rejects the block when the
  attribute is missing.

Plugin-dispatched kinds (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
list one subsection per registered type.

## Top-level blocks

Operational settings live under the required top-level `gateway { ... }` block. The optional `defaults { ... }` block carries policy fallbacks. Labeled policy blocks (`profile`, `approver`, `credential`, `endpoint`, `rule`, `tunnel`) are documented in their own sections.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `schema_version` | `int` | no | The config grammar this file targets. The gateway accepts a range of versions and rejects anything newer than it understands with an upgrade error. Omitting it loads as legacy grammar (version 0) with a deprecation warning. |
| `gateway` | `block` | yes | Carries every operational scalar and the two transport sub-blocks. Required: configs missing the block fail to load. |
| `defaults` | `block` | no | Holds the optional `defaults { ... }` block with the policy defaults (unknown_host, llm_*, human_*). nil when the block is absent — every field has a built-in default. |
| `plugin` | `block` | no | Lists every `plugin "<name>" { source = "..." }` block at the top of the file. The loader spawns each subprocess (and registers its declared types) before running pass-1 symbol building, so plugin-supplied (kind, type) pairs are available by the time policy blocks are dispatched. |

## `gateway { ... }`

The gateway block carries operational settings — listen addresses, the WireGuard / Tailscale transport sub-blocks, session and retention windows, telemetry, and the resolver.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `dashboard_listen` | `string` | no | The bind address for the dashboard + JSON API HTTP server. Default 127.0.0.1:8080. Set to a routable address to expose the dashboard off-host (the same mux is also served on the WG netstack / tsnet stack at this port). |
| `public_url` | `string` | no | The canonical externally-reachable gateway URL. Used in generated control-plane links such as join targets, OAuth redirect URIs, and (when public_url has a host but wireguard.endpoint doesn't) the host clients dial for WireGuard. |
| `state_dir` | `string` | no | The directory holding clawpatrol.db (and anything a plugin persists to disk under it). Defaults to ${HOME}/.clawpatrol. |
| `dashboard_session_ttl` | `string` | no | How long a dashboard login session stays valid after the operator types the password. time.ParseDuration format ("24h", "30m"). Default 24h. |
| `dashboard_config_writes` | `bool` | no | Allows authenticated dashboard users to append generated config snippets to the gateway HCL. Default false: config remains read-only and changes happen out-of-band. |
| `dashboard_name` | `string` | no | The display name shown in the dashboard UI and login page. Defaults to "Claw Patrol". |
| `dashboard_logo_url` | `string` | no | Logo image URL shown in the dashboard header and login page. Absolute URLs, data URLs, and same-origin paths are accepted. Defaults to the bundled Claw Patrol logo. |
| `dashboard_icon_url` | `string` | no | Compact logo / favicon URL. Defaults to `dashboard_logo_url` when set, otherwise the bundled Claw Patrol icon. |
| `resolver` | `string` | no | The DNS resolver address the gateway uses for upstream lookups when the runtime needs an explicit resolver. |
| `log_path` | `string` | no | An optional file path for gateway log output. |
| `telemetry` | `bool` | no | Opts in/out of the update-checker / anonymous usage ping (doc/telemetry.md). nil = default on; explicit `telemetry = false` silences the goroutine. Env vars CLAWPATROL_TELEMETRY=0 and DO_NOT_TRACK=1 also work. |
| `session_keep` | `string` | no | The hard retention floor for the sessions table. Sessions whose last_at is older than this get deleted by the background sweeper. Default 720h (30d), "0" / "off" disables. time.ParseDuration format. |
| `actions_keep` | `string` | no | The global default retention floor for the actions table (captured request/response logs — the gateway's largest table). Rows whose ts_ns is older than this are deleted by the background sweeper. Each endpoint may override this with its own `retention = "..."`. Default 720h (30d), "0" / "off" disables the default sweep (per-endpoint retention still applies). time.ParseDuration format. |
| `limits` | `block` | no | Limits, if present, overrides the two gateway-wide body-size limits (rules-engine body buffer and persisted action body storage). nil uses the DefaultBody*Limit constants, which match today's hardcoded behavior. |
| `genai_telemetry` | `block` | no | GenAITelemetry, if present, enables export of OpenTelemetry GenAI semantic-convention spans (gen_ai.*) for intercepted LLM requests. Requires the OTLP exporter to be configured (OTEL_EXPORTER_OTLP_ENDPOINT); without it there is nothing to export to. The block is opt-in: when absent, no gen_ai.* spans are emitted and there is no added per-request overhead. |
| `wireguard` | `block` | no | WireGuard, if present, enables the embedded userspace WireGuard server. Required block when running WG-mode deployments. |
| `tailscale` | `block` | no | Tailscale, if present, enables the embedded tsnet node and the Tailscale control plane (OAuth key minting, exit-node routing). Both transports may be enabled simultaneously. |

**Nested block `limits {}`:**

The optional `limits { ... }` sub-block inside
`gateway { ... }`. It exposes the two independent body-size limits as
human-readable size strings (e.g. "256KiB", "1MiB"):

  - BodyBuffer bounds the hot-path buffer the rules engine matches
    against. Trade-off: latency / memory vs. how much body rules see.
  - BodyStorage bounds the cold-storage sample persisted per action.
    Trade-off: disk / db size vs. how useful the action details page
    is for debugging.

Both are independent: a deployment may log more (or less) than it
rule-matches. Empty fields fall back to the DefaultBody*Limit
constants, which equal today's hardcoded behavior.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `body_buffer` | `string` | no |  |
| `body_storage` | `string` | no |  |

**Nested block `genai_telemetry {}`:**

The body of the `genai_telemetry { ... }`
sub-block inside `gateway { ... }`. Presence of the block enables
emission of OpenTelemetry GenAI semantic-convention spans for
intercepted LLM requests (gen_ai.* attributes — semconv v1.27.0).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `include_message_content` | `bool` | no | Additionally captures and exports the prompt/completion message content via the GenAI content convention (the gen_ai.input.messages, gen_ai.output.messages, and gen_ai.system_instructions span attributes), and enriches gen_ai.tool.definitions with each tool's description and JSON schema. Default false: message content can be large and sensitive, so it is only captured when an operator explicitly opts in. Independent of the base span export — the gen_ai.* attribute span emits regardless of this flag, including gen_ai.tool.definitions with each tool's name and type. |

**Nested block `wireguard {}`:**

The body of the `wireguard { ... }` sub-block
inside `gateway { ... }`. Presence of the block enables the WG
transport.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `subnet_cidr` | `string` | no | The private subnet assigned to onboarded clients. Required (e.g. "10.55.0.0/24"). |
| `listen_port` | `int` | no | The UDP port the gateway binds for WG peers. Default 51820. |
| `host_loopback_port` | `int` | no | The TCP port the gateway binds on 127.0.0.1 for host-local clients (single-host deployments where clawpatrol-run loops back to the gateway on the same box). Default 8443. Make it operator-controlled so two gateways can coexist on one host (dev/test, blue-green, multi-tenant) without colliding on the loopback landing pad. |
| `endpoint` | `string` | no | The host:port advertised in client wg.conf as `Endpoint = ...`. Host defaults to public_url's host; port defaults to listen_port. Set only for split-host deployments (gateway sits behind a different hostname/IP for WG than for the dashboard). |
| `interface` | `string` | no | The WireGuard interface name the gateway manages. Mostly irrelevant in userspace mode; leave unset. |
| `server_pub` | `string` | no | The WireGuard server public key advertised to clients. Normally derived from gateway state; only set when bootstrapping from an external key. |

**Nested block `tailscale {}`:**

The body of the `tailscale { ... }` sub-block
inside `gateway { ... }`. Presence of the block enables tsnet.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `authkey` | `string` | no | The Tailscale auth key for the embedded tsnet node. Required when the `tailscale` block is present. Falls back to $TS_AUTHKEY if empty. |
| `hostname` | `string` | no | The device name requested for the tsnet node. Default "clawpatrol-gateway". |
| `control_url` | `string` | no | The Tailscale control-plane URL. Empty → Tailscale's hosted control plane. |
| `tags` | `[]string` | no | The Tailscale device-tag list applied to keys the gateway mints for onboarded clients (`tag:client` etc.). The autoApprovers exit-node ACL must reference these tags. |
| `operators` | `[]string` | no | Allowlists tailnet logins permitted to use the dashboard without typing the root password. Each entry is either an exact login ("alice@example.com") or a domain wildcard ("*@example.com"). Tagged devices (whose whois login is the tag name, not a user email) never match a wildcard entry — agents on the tailnet can never bypass the gate through this path. Empty / unset → tailnet-allowlist auth is disabled. The stored root password is then the only way in. Lives under `tailscale {}` because matching requires the tsnet whois identity; there is no whois without an active tsnet node. |
| `funnel` | `bool` | no | Enables Tailscale Funnel on :443 so the join bootstrap and credential webhook paths are internet-reachable via the tsnet cert domain. Requires HTTPS enabled for the tailnet; if public_url is unset the gateway derives it from the tsnet cert domain at startup. |
| `oauth_client_id` | `string` | no | The OAuth client id used to mint per-device tailnet auth keys at approval time. |
| `oauth_client_secret` | `string` | no | The OAuth client secret paired with OAuthClientID. |

## `profile "<name>" { ... }`

Names a set of credentials. Profiles bind to dashboard owners; an owner's profile determines which credentials — and, transitively via each credential's `endpoint` / `endpoints` binding, which endpoints — their gateway requests can reach. Rules ride along automatically because they're attached to endpoints.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `credentials` | `[]credential` | yes | Bare-name credential references, or `{ credential = name, <disambiguator> = "..." }` object entries for multi-credential dispatch (e.g. `placeholder` for header-token credentials). |

```hcl
profile "default" {
  credentials = [bearer_token.github, postgres_credential.postgres-prod]
}
```

## `approver` blocks

Block syntax: `approver "<type>" "<name>" { ... }`

Registered types: [`human_approver`](#approver-humanapprover), [`llm_approver`](#approver-llmapprover).

### `approver "human_approver" "<name>"`

Targets one channel. Timeout / require_approvers
override the global defaults block on a per-approver basis.

Credential references a credential whose body satisfies HITLNotifier
(slack_tokens today; future Discord / Telegram / SMTP credentials).
Leave empty for a dashboard-only approver (no channel notification;
operator clicks approve/deny on the dashboard).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `channel` | `string` | yes | The destination channel, chat id, or equivalent notifier-specific target. |
| `credential` | `ref(credential)` | no | References the notifier credential used to post approval requests. Leave empty for dashboard-only approval. |
| `timeout` | `int` | no | Overrides the gateway's human_timeout for this approver, in seconds. |
| `require_approvers` | `int` | no | The number of separate human approvals required before the request is allowed. |
| `interactive` | `bool` | no | Toggles in-channel approve/deny buttons. Requires the referenced credential's signing_secret slot pasted via the dashboard AND Slack's Interactivity URL pointed at the gateway. Default false: message includes only an "Open dashboard" link. |
| `classifier` | `ref(approver)` | no | Optionally references an llm_approver by name. When set, the approver calls the classifier's Summarize method before posting the HITL notification, enriching the Slack card with request summary metadata. Classifier failures are non-fatal — the generic card is used as fallback. |
| `message` | `string` | no | An optional Go-template-style string with {{var}} placeholders. When set, the expanded text replaces the default section body in the Slack (or other notifier) card. Supported vars mirror the CEL facet namespace: {{http.method}}, {{http.path}}, {{k8s.verb}}, {{sql.tables}}, {{http.body_json.resource_id}}, {{profile}}, {{endpoint}}, {{reason}}, etc. Classifier (if also set) still runs; Message takes display precedence. |

```hcl
approver "human_approver" "example" {
  channel = "#approvals"
}
```

### `approver "llm_approver" "<name>"`

Carries the model + the credential used to authenticate
the call to the model API + the inline policy text the model judges
against. `policy` is a heredoc-friendly string attribute on the
approver block itself — no separate `policy "<name>" {}` block.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `model` | `string` | yes | The model id used for policy judgment, such as a claude-*, gpt-*, or o*-prefixed model. |
| `credential` | `ref(credential)` | yes | References the HTTP credential used to authenticate the model API call. |
| `policy` | `string` | no | The prose the model judges requests against. Typically a heredoc on the approver block. |

```hcl
approver "llm_approver" "example" {
  model = "claude-haiku-4-5-20251001"
  credential = bearer_token.example
}
```

## `credential` blocks

Block syntax: `credential "<type>" "<name>" { ... }`

Registered types: [`anthropic_manual_key`](#credential-anthropicmanualkey), [`anthropic_oauth_subscription`](#credential-anthropicoauthsubscription), [`aws_credential`](#credential-awscredential), [`basic_auth`](#credential-basicauth), [`bearer_token`](#credential-bearertoken), [`clickhouse_credential`](#credential-clickhousecredential), [`cookie_token`](#credential-cookietoken), [`discord_bot_token`](#credential-discordbottoken), [`gemini_api_key`](#credential-geminiapikey), [`github_oauth`](#credential-githuboauth), [`google_gke_credential`](#credential-googlegkecredential), [`header_token`](#credential-headertoken), [`mtls_credential`](#credential-mtlscredential), [`notion_mcp_oauth`](#credential-notionmcpoauth), [`notion_oauth`](#credential-notionoauth), [`openai_codex_oauth`](#credential-openaicodexoauth), [`passthrough`](#credential-passthrough), [`postgres_credential`](#credential-postgrescredential), [`slack_tokens`](#credential-slacktokens), [`ssh_key`](#credential-sshkey), [`tailscale_auth`](#credential-tailscaleauth), [`telegram_bot_token`](#credential-telegrambottoken).

### `credential "anthropic_manual_key" "<name>"`

_No configurable attributes._

```hcl
credential "anthropic_manual_key" "example" {}
```

### `credential "anthropic_oauth_subscription" "<name>"`

_No configurable attributes._

```hcl
credential "anthropic_oauth_subscription" "example" {}
```

### `credential "aws_credential" "<name>"`

Schema is intentionally empty: access key id and secret access key
(and optional session token) live in the secret store as named
slots, filled via the dashboard or CLAWPATROL_SECRET_<NAME>_<SLOT>
env vars. Cluster + region come from the kubernetes endpoint at
request time.

_No configurable attributes._

```hcl
credential "aws_credential" "example" {}
```

### `credential "basic_auth" "<name>"`

Injects `Authorization: Basic <base64(username:password)>`.

The credential secret is the raw password; `username` lives in
config. Common credential binding fields apply: use `endpoint` or
`endpoints` to bind the credential to upstreams.

When a profile has multiple Basic Auth credentials for the same HTTPS
endpoint, use the `placeholder` disambiguator on the profile entry or
credential block. The HTTPS placeholder detector matches that value
inside decoded `Authorization: Basic <base64(username:placeholder)>`
request headers.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | `string` | yes | The upstream HTTP Basic Auth username. |

```hcl
credential "basic_auth" "example" {
  endpoint = https.example
  username = "example"
}
```

### `credential "bearer_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `idempotency_key` | `bool` | no | Stamps a deterministic Idempotency-Key header on non-GET/HEAD HTTP requests when the agent did not provide one. |

```hcl
credential "bearer_token" "example" {}
```

### `credential "clickhouse_credential" "<name>"`

Database, when set, is the discriminator the dispatcher uses to
pick this credential when several clickhouse_credential blocks
bind the same endpoint(s). At request time the gateway reads the
agent-declared database off the wire and picks the credential
whose `database` matches; an unset `database` field is the
catchall (one allowed per (profile, endpoint)).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no | The upstream ClickHouse user the gateway injects. |
| `database` | `string` | no | Limits this credential to ClickHouse requests for that database. Empty acts as the catchall. |

```hcl
credential "clickhouse_credential" "example" {}
```

### `credential "cookie_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `cookie_name` | `string` | no | The HTTP cookie name that receives the secret value. |

```hcl
credential "cookie_token" "example" {}
```

### `credential "discord_bot_token" "<name>"`

Injects Discord bot tokens for REST and Gateway SDK traffic.

_No configurable attributes._

```hcl
credential "discord_bot_token" "example" {}
```

### `credential "gemini_api_key" "<name>"`

_No configurable attributes._

```hcl
credential "gemini_api_key" "example" {}
```

### `credential "github_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "github_oauth" "example" {}
```

### `credential "google_gke_credential" "<name>"`

_No configurable attributes._

```hcl
credential "google_gke_credential" "example" {}
```

### `credential "header_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `header` | `string` | yes | The HTTP header name to overwrite with the secret value. |
| `prefix` | `string` | no | Prepended to the secret before injection, for schemes such as "Bearer " or "Token ". |

```hcl
credential "header_token" "example" {
  header = "X-API-Key"
}
```

### `credential "mtls_credential" "<name>"`

_No configurable attributes._

```hcl
credential "mtls_credential" "example" {}
```

### `credential "notion_mcp_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "notion_mcp_oauth" "example" {}
```

### `credential "notion_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "notion_oauth" "example" {}
```

### `credential "openai_codex_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "openai_codex_oauth" "example" {}
```

### `credential "passthrough" "<name>"`

A credential that injects nothing. It exists only as
a handle the operator declares, binds to endpoints, and lists in a
profile's `credentials` — so the existing credential→endpoint→profile
claim path works for endpoints that simply don't need auth injection
(public APIs, services reached over an already-authenticated tunnel,
open-internal endpoints). Write one passthrough credential per group
of credential-less endpoints a profile should claim, or share one
across several. The gateway forwards matching requests verbatim — no
header, signature, or token rewrite — while the profile's rules
still apply.

_No configurable attributes._

```hcl
credential "passthrough" "example" {}
```

### `credential "postgres_credential" "<name>"`

Database, when set, is the discriminator the dispatcher uses to
pick this credential when several postgres_credential blocks bind
the same endpoint(s). At request time the gateway reads the
agent-declared database off the StartupMessage and picks the
credential whose `database` matches; an unset `database` field is
the catchall (one allowed per (profile, endpoint)).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no | The upstream Postgres role the gateway authenticates as. |
| `database` | `string` | no | Limits this credential to sessions whose StartupMessage declares the same database. Empty acts as the catchall. |

```hcl
credential "postgres_credential" "example" {}
```

### `credential "slack_tokens" "<name>"`

_No configurable attributes._

```hcl
credential "slack_tokens" "example" {}
```

### `credential "ssh_key" "<name>"`

_No configurable attributes._

```hcl
credential "ssh_key" "example" {}
```

### `credential "tailscale_auth" "<name>"`

Has no operator-facing fields — there is
nothing to paste. Per-tailnet selection (control_url, tags) lives
on the tunnel block instead.

_No configurable attributes._

```hcl
credential "tailscale_auth" "example" {}
```

### `credential "telegram_bot_token" "<name>"`

_No configurable attributes._

```hcl
credential "telegram_bot_token" "example" {}
```

## `endpoint` blocks

Block syntax: `endpoint "<type>" "<name>" { ... }`

Registered types: [`clickhouse_https`](#endpoint-clickhousehttps), [`clickhouse_native`](#endpoint-clickhousenative), [`https`](#endpoint-https), [`kubernetes`](#endpoint-kubernetes), [`openai_codex_https`](#endpoint-openaicodexhttps), [`postgres`](#endpoint-postgres), [`ssh`](#endpoint-ssh).

### `endpoint "clickhouse_https" "<name>"`

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of ClickHouse HTTPS hostnames or host:port pairs this endpoint intercepts. |

```hcl
endpoint "clickhouse_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "clickhouse_native" "<name>"`

Addresses one ClickHouse server reachable
via the binary native protocol. Operators bind a single
clickhouse_credential; the runtime parses the agent's Hello and
substitutes the credential's (user, password) where the agent
embedded a placeholder.

TLS toggles TLS on both hops: the gateway terminates the agent's
TLS using a leaf minted off the gateway CA, parses the Hello in
plaintext, then re-wraps to upstream. The wrapped client therefore
keeps speaking native-over-TLS exactly as it would against the
real cloud ClickHouse — `clawpatrol run` is transparent to its
TLS posture. Default false: WG-only deployments where the operator
wants plaintext on the inner hop (typical self-hosted ClickHouse
on 9000 behind a private network) leave it off.

AcceptInvalidCertificate mirrors clickhouse-client's flag of the
same name: when true and tls is on, the gateway skips upstream cert
validation. Use for self-hosted ClickHouse fronted by a private CA.
Default false keeps full validation against system roots.

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of ClickHouse native-protocol hostnames or host:port pairs this endpoint intercepts. |
| `port` | `int` | no | The default upstream port for hosts that omit one. Defaults to 9000 without TLS and 9440 with TLS. |
| `tls` | `bool` | no | Enables ClickHouse native-over-TLS on the upstream hop. |
| `accept_invalid_certificate` | `bool` | no | Skips upstream certificate validation when TLS is enabled. |

```hcl
endpoint "clickhouse_native" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of HTTPS hostnames or host:port pairs this endpoint intercepts. |

```hcl
endpoint "https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "kubernetes" "<name>"`

ClusterName + Region are EKS auth parameters: when the bound
credential is `aws_credential`, the gateway presigns an STS
GetCallerIdentity URL scoped to (region, cluster_name) and stamps
the result as a `k8s-aws-v1.<…>` bearer. Leave both unset for
self-hosted clusters with a non-EKS credential (bearer_token,
mtls_credential).

Family: `k8s`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | no | An optional list of Kubernetes API hostnames or host:port pairs to intercept. |
| `server` | `string` | no | The Kubernetes API server URL or host:port used when hosts is not set. |
| `ca_cert` | `string` | no | The PEM-encoded cluster CA, often loaded with `<<file:cluster-ca.pem>>`. |
| `cluster_name` | `string` | no | The EKS cluster name used by aws_credential. |
| `region` | `string` | no | The AWS region used by aws_credential for EKS auth. |

```hcl
endpoint "kubernetes" "example" {}
```

### `endpoint "openai_codex_https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The chatgpt.com host list intercepted for Codex subscription-auth traffic. |

```hcl
endpoint "openai_codex_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "postgres" "<name>"`

Addresses a single RDS-or-equivalent server.
Tunnel topologies (kubectl-portforward-ssh and friends) aren't
supported in this iteration — operators run the gateway with
network reachability already arranged.

SSLMode mirrors libpq's sslmode names — "disable" / "prefer" /
"require" / "verify-full". Default "prefer": try TLS, fall back
to plain when the upstream replies 'N'. "require" hard-fails on
'N'. "verify-full" additionally validates the upstream cert
against Host. "disable" skips the SSLRequest probe entirely —
fine for self-hosted pg on a private network where WG already
encrypts the path.

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | `string` | yes | The upstream Postgres host:port pair. |
| `sslmode` | `string` | no | Controls upstream TLS negotiation. Valid values mirror libpq: "disable", "prefer", "require", and "verify-full". |

```hcl
endpoint "postgres" "example" {
  host = "db.internal:5432"
}
```

### `endpoint "ssh" "<name>"`

Binds one or more host:port tuples. The credentials
that authenticate against it live on credential blocks via the
framework-level `endpoint = X` / `endpoints = [...]` binding. When
a profile wields more than one SSH credential at the endpoint,
each ambiguous credential carries a `user = "..."` disambiguator —
either on its profile-inline entry (`{ credential = X, user = "..." }`)
or on the credential block itself — and the agent's wire-protocol
username picks the matching entry. The agent's username is also
passed through verbatim as the upstream SSH user; credentials
carry only auth material (key / password / host_pubkey), never a
username override.

Family: `ssh`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of SSH host:port pairs this endpoint intercepts. |

```hcl
endpoint "ssh" "example" {
  hosts = ["api.example.com"]
}
```

## `rule` blocks

Block syntax: `rule "<name>" { ... }`

### `rule "<name>"`

The gohcl-tagged decode target. The match predicate is
family-agnostic at the HCL layer (just a CEL string); the facet's
*cel.Env decides which variables are valid once the family has
been inferred from the endpoint refs.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `endpoint` | `ref(endpoint)` | no | The single endpoint this rule attaches to. Use endpoint or endpoints, not both. |
| `endpoints` | `[]ref(endpoint)` | no | The list of endpoints this rule attaches to. All referenced endpoints must share one protocol family. |
| `priority` | `int` | no | Orders matching rules. Higher values run first; equal priorities preserve declaration order. |
| `disabled` | `bool` | no | Keeps the rule in config while excluding it from runtime evaluation. |
| `condition` | `string` | no | A CEL expression evaluated against the family-specific variable set. An absent / empty condition matches everything — the catch-all pattern (`rule "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `credential` | `ref(credential)` | no | Credential, if set, is a bare-name reference to a credential block. The runtime treats it as an extra match predicate (request must have been dispatched against this credential) evaluated before the CEL expression. |
| `verdict` | `string` | no | The outcome when the rule matches. Set exactly one of `verdict` (`"allow"` / `"deny"`) or `approve`. |
| `reason` | `string` | no | The operator-facing explanation recorded when the rule matches. |
| `approve` | `[]ref(approver)` | no | A list of bare-name approver references. The approvers run in order; the request is allowed only if every stage approves. Set this *or* `verdict`, not both. |

```hcl
rule {}
```

## `tunnel` blocks

Block syntax: `tunnel "<type>" "<name>" { ... }`

Registered types: [`kubernetes_port_forward`](#tunnel-kubernetesportforward), [`local_command`](#tunnel-localcommand), [`ssh_port_forward`](#tunnel-sshportforward), [`tailscale`](#tunnel-tailscale).

### `tunnel "kubernetes_port_forward" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `context` | `string` | no | Selects a kubeconfig context; empty uses the current context. Ignored when Server is set (the plugin builds its own per-tunnel kubeconfig). |
| `namespace` | `string` | no | Selects the Kubernetes namespace for kubectl commands. |
| `pod` | `string` | no | Names an existing pod to port-forward to. Exactly one of pod, service, selector, or template must be set. |
| `service` | `string` | no | Names a service to port-forward to. |
| `selector` | `map[string]string` | no | Matches a ready pod to port-forward to. |
| `template` | `string` | no | A pod manifest to apply and port-forward to. |
| `port` | `int` | yes | The pod-side port the forwarder targets. For service mode it's the *service* port; kubectl resolves the matching targetPort. |
| `cleanup` | `string` | no | Controls whether a template-created pod is deleted on tunnel teardown. "delete" (default) is right for the common create-on-demand case; "keep" disables deletion. Created pods are stamped with `clawpatrol.dev/managed-by=clawpatrol` and `clawpatrol.dev/tunnel=<name>` labels; unless cleanup is "keep", a startup sweep deletes any pod carrying those labels that a previous daemon lifetime left behind (e.g. after a crash skipped graceful teardown). |
| `server` | `string` | no | The Kubernetes apiserver URL. When set the plugin writes a per-tunnel kubeconfig (server + ca_cert + bearer minted from the bound credential) and invokes kubectl with --kubeconfig pointing at it; no external kubeconfig or KUBECONFIG env is needed. The Context field is then ignored. |
| `ca_cert` | `string` | no | The cluster CA PEM. Supports `<<file:path.pem>>` for out-of-line storage; the loader inlines the file contents. Required when Server is set against EKS (the apiserver presents a per-cluster CA that no system trust store carries). |
| `cluster_name` | `string` | no | The EKS cluster name, used by an aws_credential to scope the STS presign (sets the X-K8s-Aws-Id header). Only meaningful alongside Server + an aws_credential. |
| `region` | `string` | no | The AWS region the EKS cluster lives in; SigV4 needs it. Only meaningful alongside Server + an aws_credential. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains kubectl access through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for Kubernetes access. |

```hcl
tunnel "kubernetes_port_forward" "example" {
  port = 30
}
```

### `tunnel "local_command" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | `[]string` | yes | The argv vector to spawn for the tunnel process. |
| `listen` | `string` | yes | The local address the spawned command exposes. |
| `ready_probe` | `string` | no | An optional TCP address to poll before the tunnel is ready. |
| `ready_timeout` | `string` | no | Overrides the default readiness wait duration. |
| `env` | `map[string]string` | no | Adds environment variables to the spawned command. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains this tunnel through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for the tunnel runtime. |

```hcl
tunnel "local_command" "example" {
  command = ["example"]
  listen = "example"
}
```

### `tunnel "ssh_port_forward" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `bastion` | `string` | no | The SSH server host:port; required when via is unset. |
| `user` | `string` | yes | The SSH username for the bastion login. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains the SSH connection through another tunnel. |
| `credential` | `ref(credential)` | yes | References an ssh credential block used for bastion authentication. |

```hcl
tunnel "ssh_port_forward" "example" {
  bastion = "bastion.example:22"
  user = "example"
  credential = bearer_token.example
}
```

### `tunnel "tailscale" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `authkey` | `string` | no | The Tailscale auth key; env fallback is CLAWPATROL_TUNNEL_<NAME>_AUTHKEY. |
| `oauth_client_secret` | `string` | no | A Tailscale OAuth client secret (tskey-client-...). When set, tsnet mints a fresh, short-lived device key from the OAuth client on every join instead of relying on a static authkey — so there is no long-lived key that can expire out from under the tunnel. Requires `tags` (untagged OAuth keys are rejected by Tailscale). Env fallback is CLAWPATROL_TUNNEL_<NAME>_OAUTH_CLIENT_SECRET. |
| `control_url` | `string` | no | Overrides the Tailscale control-plane URL. |
| `hostname` | `string` | no | The tsnet node name; defaults to clawpatrol-tunnel-<name>. |
| `state_dir` | `string` | no | Stores tsnet node state; defaults under the gateway CA directory. |
| `tags` | `[]string` | no | Tailscale tags requested for the tsnet node. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains this tunnel through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for the tunnel runtime. |

```hcl
tunnel "tailscale" "example" {}
```
