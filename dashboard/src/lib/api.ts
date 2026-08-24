const api = fetch;

export type SecretSlot = {
  name: string;
  label: string;
  multiline?: boolean;
  description?: string;
};

export type OptionalScope = { id: string; label: string };
export type OptionalScopeGroup = { title: string; scopes: OptionalScope[] };
export type OAuthIntegrationUI = {
  base_scopes: string[];
  optional_scopes?: OptionalScopeGroup[];
};

// TailscaleNodeState mirrors the stable wire labels emitted by the
// backend's tailscaleproto.NodeStateLabel. `connected` is the boolean
// shortcut (true iff state === "running"); the raw label lets the
// card distinguish "awaiting authentication" from "starting" or
// "stopped" without re-encoding the bool back into a state machine.
export type TailscaleNodeState =
  | "unknown"
  | "needs_login"
  | "needs_machine_auth"
  | "starting"
  | "running"
  | "stopped"
  | "in_use_other_user";

// TailscaleAuthStatusUI matches IntegrationRow.TailscaleAuth on the
// server. The dashboard reads connect/disconnect endpoint paths off
// the row instead of hardcoding /api/tailscale/* so backend route
// changes don't need a coordinated frontend bump. pending_url, when
// non-empty, is tsnet's live login URL — opening it in a new tab
// completes the join.
export type TailscaleAuthStatusUI = {
  connected: boolean;
  state: TailscaleNodeState;
  // has_state is true when credential_secrets carries persisted
  // identity bytes — even when `connected` is false. The card uses
  // this to render the disconnect ✕ for stuck-but-not-running nodes
  // so the operator can reset without bouncing the gateway.
  has_state?: boolean;
  pending_url?: string;
  connect_url: string;
  status_url: string;
  disconnect_url: string;
};

// Each credential carries one secret. The connection state lives
// directly on the row; multi-tenant per-owner fan-out was removed.
export type Integration = {
  id: string;
  name: string;
  type: string; // credential plugin type (e.g. "postgres_credential")
  has_oauth: boolean;
  oauth?: OAuthIntegrationUI | null;
  slots?: SecretSlot[] | null;
  connected: boolean;
  expires_at?: number;
  display_name?: string;
  avatar_url?: string;
  has_tailscale_auth?: boolean;
  tailscale_auth?: TailscaleAuthStatusUI | null;
  // True for the `passthrough` credential type, which injects nothing
  // at request time. The card renders a "no injection" indicator and
  // offers no connect flow — there's nothing to connect.
  passthrough?: boolean;
  // Profiles routing requests through any endpoint that binds this
  // credential (directly or via a tunnel). Sorted by name.
  profiles?: string[];
  // Endpoints that bind this credential. Sorted by name.
  endpoints?: string[];
  // Operator-set HCL block attributes (`user`, `region`, …). Values
  // are the raw HCL token text (quoted strings included). Never
  // includes secret material.
  config?: Record<string, string>;
  // Unix seconds of the most recent connect/update on this
  // credential (max across the OAuth and per-slot secret stores).
  // Zero/undefined for declared-only credentials that have never
  // been touched.
  updated_at?: number;
};

// tailscaleConnect asks the gateway for the live tsnet login URL.
// Returns `{connected: true}` when the node is already joined.
// tsnet mints a fresh URL per attempt — call this on every click
// rather than caching.
export async function tailscaleConnect(connectURL: string): Promise<{
  id: string;
  connected: boolean;
  auth_url?: string;
  pending_url?: string;
  status: string;
}> {
  const r = await fetch(connectURL, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// tailscaleDisconnect drops the persisted node identity. The
// in-process tsnet node keeps running until gateway restart — the
// next boot reruns the interactive flow.
export async function tailscaleDisconnect(disconnectURL: string): Promise<void> {
  const r = await fetch(disconnectURL, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
}

export async function setCredentialSlots(id: string, slots: Record<string, string>): Promise<void> {
  const r = await fetch("/api/credentials/set", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, slots }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function clearCredential(id: string): Promise<void> {
  const r = await fetch("/api/credentials/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export type Session = {
  id: string;
  title?: string;
  type: string;
  model?: string;
  tokens_in?: number;
  tokens_out?: number;
  ctx_used?: number;
  ctx_max?: number;
  first_at: string;
  last_at: string;
  reqs: number;
  activity?: number[];
};

export type Agent = {
  ip: string;
  external_ipv4?: string;
  external_ipv6?: string;
  hostname: string;
  user: string;
  profile?: string;
  os: string;
  ua?: string;
  first_at: string;
  last_at: string;
  reqs: number;
  bytes_in: number;
  bytes_out: number;
  last_host: string;
  activity?: number[];
  integrations?: string[];
  sessions?: Session[];
};

export type RuleSummary = {
  // Rule's bare-name identifier (declared in HCL as
  // `rule "<name>"`). Unique across the file.
  name: string;
  // "https" | "sql" | "k8s" — protocol family inferred from the
  // rule's endpoint(s); pins the facet whose CEL variables are
  // bound when evaluating `condition`.
  family: string;
  // Endpoint this rule attaches to. Multi-endpoint rules emit one
  // RuleSummary per attachment site.
  endpoint: string;
  // Profile that includes the endpoint. Empty when the row came
  // back from a non-profile-scoped query.
  profile?: string;
  // Priority — higher wins. Negative values are catch-alls;
  // priority 0 is the default declaration-order tier.
  priority?: number;
  disabled?: boolean;
  // verdict: "allow" | "deny". Empty when approve = [...] is the
  // outcome instead.
  verdict?: string;
  reason?: string;
  // Approve chain stages. Each stage names an approver (LLM or
  // human); some stages additionally bind a policy + cache_ttl.
  approve?: Array<{
    name: string;
    policy?: string;
    cache_ttl?: number;
  }>;
  // CEL condition string. Empty for catch-all rules. Variables
  // exposed depend on the family: http.{method, path, query,
  // headers, body, body_json}, sql.{verb, tables, function,
  // statement}, k8s.{verb, resource, namespace, name, params}.
  condition?: string;
  // Bare-name credential ref the request must have been
  // dispatched against. Empty when the rule doesn't filter on
  // credential.
  credential?: string;
};

export async function getRules(): Promise<RuleSummary[]> {
  const r = await api("/api/rules");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// Plugin mirrors extplugin.PluginInfo: one loaded external plugin and
// the permissions it runs with. network is the approved grant ("none"
// | "outbound"); sandboxMode is the OS backend ("namespaces" |
// "landlock" | "seatbelt" | "off"). Plugins blocked by a permission
// escalation never load, so they don't appear here.
export type RequestedPrivileges = {
  version?: string;
  network: string;
  // egress is the set of upstream targets the plugin's manifest declares
  // it needs to reach via the gateway's brokered dial ("host:port" or
  // "*.suffix:port").
  egress?: string[];
  // privileged means the plugin's manifest declares it must run unsandboxed
  // (full host access). The operator must approve it explicitly.
  privileged?: boolean;
  credentials?: string[];
  endpoints?: string[];
  tunnels?: string[];
  facets?: string[];
};

export type Plugin = {
  name: string;
  source: string;
  // blocked plugins failed to load (chiefly a permission escalation);
  // they carry name, source, blocked, reason and nothing else.
  blocked?: boolean;
  reason?: string;
  version?: string;
  network?: string;
  // egress is the approved set of brokered-dial targets the plugin's
  // manifest declared, recorded in the lockfile.
  egress?: string[];
  // privileged means the plugin runs unsandboxed (full host access) — the
  // operator approved its declared privileged capability, or forced it with
  // `sandbox = "off"`.
  privileged?: boolean;
  sandboxMode?: string;
  sandboxWarning?: string;
  approvedHashes?: string[];
  // updateAvailable is the newest release tag (GitHub sources) that
  // satisfies the plugin's constraint and is newer than the locked
  // version; apply it with `clawpatrol plugins update`.
  updateAvailable?: string;
  // requested is what a blocked/unapproved plugin's resolvable version
  // declares it needs, read from its signed static manifest (no spawn) —
  // shown so an operator can review the privileges before approving.
  requested?: RequestedPrivileges;
  credentials?: string[];
  tunnels?: string[];
  endpoints?: string[];
  facets?: string[];
};

export async function getPlugins(): Promise<Plugin[]> {
  const r = await api("/api/plugins");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// approvePlugin records the named plugin's current permissions in the
// lockfile and reloads so a previously-blocked plugin loads. The
// dashboard equivalent of `clawpatrol plugins approve`.
export async function approvePlugin(name: string): Promise<void> {
  const r = await fetch("/api/plugins/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!r.ok) throw new Error(await r.text());
}

// Rules API speaks JSON on the wire. The editor pretty-prints the
// rules array so an operator can see/edit each rule's fields directly.
// (HCL is the on-disk format; JSON is just the dashboard transport.)

export async function getRulesJSON(): Promise<string> {
  const r = await api("/api/rules");
  if (!r.ok) throw new Error(await r.text());
  const data = await r.json();
  return JSON.stringify(data ?? [], null, 2);
}

export async function putRulesJSON(json: string): Promise<{ ok: boolean; count: number }> {
  const r = await api("/api/rules", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: json,
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// HCL editor. /api/config returns the full gateway.hcl as raw text.

export async function getConfigHCL(): Promise<string> {
  const r = await api("/api/config");
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

export async function getDeviceRulesHCL(ip: string): Promise<string> {
  const r = await api(`/api/rules/device?ip=${encodeURIComponent(ip)}&format=hcl`);
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

export async function listProfiles(): Promise<string[]> {
  const r = await api("/api/profiles");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function setDeviceProfile(ip: string, profile: string): Promise<void> {
  const r = await api(
    `/api/agents/profile?ip=${encodeURIComponent(ip)}&profile=${encodeURIComponent(profile)}`,
    {
      method: "POST",
    },
  );
  if (!r.ok) throw new Error(await r.text());
}

export type HITLPending = {
  id: string;
  agent_ip: string;
  host: string;
  method: string;
  path: string;
  operation_state?: HITLOperationState;
  approval_effect?: HITLApprovalEffect;
  upstream_called?: boolean;
  approval_message?: string;
  // Operator-readable endpoint identifier (hostname for HTTPS,
  // resource name for SQL/k8s where host is a virtual IP).
  // Computed server-side; falls back to host when unset.
  endpoint?: string;
  // Endpoint family — "https" | "sql" | "k8s". Used to label the
  // path column ("Path" vs "Query" vs "Resource") in the UI.
  family?: string;
  ua?: string;
  body_sample?: string;
  reason?: string;
  created_at: string;
  expires_at: string;
};

export type HITLOperationState =
  | "sync_waiting"
  | "pending_approval"
  | "approved_waiting_for_retry"
  | "denied"
  | "expired"
  | "executing_upstream"
  | "upstream_succeeded"
  | "upstream_failed"
  | "client_disconnected";

export type HITLApprovalEffect = "execute_upstream" | "create_retry_grant";

export async function getHITLPending(): Promise<HITLPending[]> {
  const r = await api("/api/hitl/pending");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export type HITLState =
  | "pending"
  | "approved"
  | "denied"
  | "timed_out"
  | "client_disconnected"
  | "canceled"
  | "unknown";

export type HITLResolveResult = {
  ok: boolean;
  state: HITLState;
  reason?: string;
};

export async function decideHITL(id: string, allow: boolean): Promise<HITLResolveResult> {
  const r = await api("/api/hitl/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, allow }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// AuthMethod describes which gate path attributed the request:
//   - "password": the cp_session cookie was valid; user = "root".
//   - "tailscale": the request landed via tsnet and the whois login
//     matched the dashboard_operators allowlist; user = that login.
//   - "" (empty): unauthenticated — only seen briefly between login
//     redirects, the SPA shouldn't render in this state.
export type AuthMethod = "password" | "tailscale" | "";

export type Whoami = {
  user: string;
  device: string;
  host: string;
  auth_method: AuthMethod;
  public_url?: string;
};

export async function logout(): Promise<void> {
  const r = await fetch("/__logout", { method: "POST", credentials: "same-origin" });
  if (!r.ok && r.status !== 401) throw new Error(await r.text());
}

export async function getStatus(profile?: string): Promise<Integration[]> {
  const url = profile ? `/api/status?profile=${encodeURIComponent(profile)}` : "/api/status";
  const r = await api(url);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function deleteAgent(ip: string): Promise<void> {
  const r = await api(`/api/agents/delete?ip=${encodeURIComponent(ip)}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
}

// /api/state bundles whoami + integrations + agents in one ETag'd
// response. Module-level lastTag persists across getState calls so
// the 304 fast path kicks in on every poll after the first; cached
// value returned on 304 means consumers always get a non-null shape.
//
// Browser fetch with default cache + ETag would also revalidate, but
// the cached body is still copied into JS land — going through If-
// None-Match explicitly skips JSON.parse on the no-change path too.
export type UpdateBanner = {
  latest: string;
  update_available: boolean;
  url: string;
  advisory?: string;
};

export type DashboardBranding = {
  name: string;
  logo_url: string;
  icon_url: string;
};

type StateResp = {
  whoami: Whoami;
  integrations: Integration[];
  agents: Agent[];
  update?: UpdateBanner | null;
  branding?: DashboardBranding;
  // Basename of the gateway config file (e.g. "gateway.hcl",
  // "dev.hcl"). Surfaced in UI hints so operators see the actual
  // running config name rather than a hardcoded string.
  config_file?: string;
  dashboard_config_writes?: boolean;
};
let lastStateTag = "";
let lastState: StateResp | null = null;
export async function getState(): Promise<StateResp> {
  const headers: Record<string, string> = {};
  if (lastStateTag) headers["If-None-Match"] = lastStateTag;
  const r = await fetch("/api/state", { headers, credentials: "same-origin" });
  if (r.status === 304 && lastState) return lastState;
  if (!r.ok) throw new Error(await r.text());
  const tag = r.headers.get("ETag");
  if (tag) lastStateTag = tag;
  const body = (await r.json()) as StateResp;
  lastState = body;
  return body;
}

export type OAuthStartResp =
  | { flow?: "auth_code"; auth_url: string; state: string }
  | {
      flow: "device";
      user_code: string;
      verification_uri: string;
      state: string;
      interval: number;
      expires_in: number;
    };

export async function oauthStart(id: string, extraScopes?: string[]): Promise<OAuthStartResp> {
  let qs = `id=${encodeURIComponent(id)}`;
  if (extraScopes && extraScopes.length > 0) {
    qs += `&extra_scopes=${encodeURIComponent(extraScopes.join(","))}`;
  }
  const r = await api(`/api/oauth/start?${qs}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function oauthDevicePoll(state: string): Promise<{
  connected?: boolean;
  error?: string;
  detail?: string;
  interval?: number;
}> {
  const r = await api(`/api/oauth/device-poll?state=${encodeURIComponent(state)}`, {
    method: "POST",
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function oauthRevoke(id: string): Promise<void> {
  const r = await api("/api/oauth/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function getAction(id: string): Promise<EventRecord> {
  const r = await api(`/api/actions/${id}`);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export type EventRecord = {
  ts: string;
  id?: string;
  phase?: "" | "start" | "end" | "frame";
  mode: string;
  agent_ip?: string;
  host: string;
  method?: string;
  path?: string;
  status?: string;
  in?: number;
  out?: number;
  ms: number;
  action?: string;
  reason?: string;
  frame?: string;
  direction?: string;
  req_sha?: string;
  resp_sha?: string;
  req_body?: string;
  resp_body?: string;
  req_headers?: Record<string, string>;
  resp_headers?: Record<string, string>;
  // family identifies which facet plugin emitted this event; facets
  // carries that plugin's per-request report payload (HTTPS:
  // method/path/status; SQL: verb/tables/...; k8s: verb/resource/...).
  family?: string;
  facets?: Record<string, unknown>;
  // endpoint/rule are populated at dispatch time; needed by the
  // Download action button (site/doc/clawpatrol-test.md).
  endpoint?: string;
  rule?: string;
  // approver/* are populated when action is "approved" or "denied":
  // the approver entity's HCL block name, plugin type
  // (human_approver / llm_approver / dashboard) and the per-approver
  // "by" string (slack handle, llm:<model>, ...).
  approver?: string;
  approver_type?: string;
  approver_by?: string;
};

// downloadActionFixture fetches the action reshaped as a
// `clawpatrol test` fixture. Returns a Blob so the caller can
// trigger a browser download.
export async function downloadActionFixture(id: string): Promise<Blob> {
  const r = await api(`/api/actions/${id}?fmt=fixture`);
  if (!r.ok) throw new Error(await r.text());
  return r.blob();
}

export type RulePreview = {
  rule_name: string;
  endpoint_name?: string;
  hcl: string;
  config_revision?: string;
  dashboard_config_writes: boolean;
  warnings?: string[];
};

export async function previewRuleFromAction(id: string): Promise<RulePreview> {
  const r = await api("/api/actions/rule-preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action_id: id,
      verdict: "deny",
      scope: "exact",
    }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function applyGeneratedRule(
  baseRevision: string,
  appendHCL: string,
): Promise<{ ok: boolean; revision: string }> {
  const r = await api("/api/config/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      base_revision: baseRevision,
      append_hcl: appendHCL,
    }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// FacetSchema mirrors the JSON returned by GET /api/facets — the
// dashboard fetches it once at boot and uses it to render
// per-family columns from the facets payload without hardcoding the
// list of protocol families.
export type FacetField = {
  name: string;
  kind: string;
  label?: string;
  // description: longer explanation for the per-action facet table.
  description?: string;
  // title: this field's value is the row's primary identifier (the "verb").
  title?: boolean;
  // detail_only: omit from the compact activity-log row (still in detail).
  detail_only?: boolean;
};

export type FacetSchema = {
  name: string;
  endpoint_families: string[];
  transport?: string;
  hitl_query_label?: string;
  host_is_resource: boolean;
  report_fields: Array<FacetField>;
  // result_fields declares the after-the-fact result schema (e.g. the
  // action's status). Only emitted by facets that have one.
  result_fields?: Array<FacetField>;
};

export async function getFacets(): Promise<FacetSchema[]> {
  const r = await api(`/api/facets`);
  if (!r.ok) throw new Error(await r.text());
  const body = (await r.json()) as { facets: FacetSchema[] };
  return body.facets ?? [];
}

export async function getAnalytics(params: {
  range: string;
  agent?: string;
  limit?: number;
}): Promise<{
  events: EventRecord[];
  total: number;
  total_count: number;
  error_count: number;
  by_device: Array<{ key: string; count: number }>;
  by_host: Array<{ key: string; count: number }>;
}> {
  const p = new URLSearchParams({ range: params.range });
  if (params.agent) p.set("agent", params.agent);
  if (params.limit) p.set("limit", String(params.limit));
  const r = await api(`/api/analytics?${p}`);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function oauthExchange(
  state: string,
  code: string,
): Promise<{ connected: boolean; expires: number }> {
  const r = await api("/api/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state, code }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
