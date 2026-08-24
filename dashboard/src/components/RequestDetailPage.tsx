import { useEffect, useState } from "react";
import {
  applyGeneratedRule,
  downloadActionFixture,
  getAction,
  previewRuleFromAction,
  type Agent,
  type EventRecord,
  type FacetSchema,
  type RulePreview,
} from "../lib/api";
import { copyText, headersToJSON } from "../lib/clipboard";
import { formatFacetValue, useFacets } from "../lib/facets";
import { fmtDateTime, statusColorClass } from "../lib/format";
import { Button } from "./Button";
import { CopyButton } from "./CopyButton";
import { ApprovalStatusIcon, LockGlyph, rowDescriptors } from "./LiveRequests";
import { Main } from "./Main";
import { Modal } from "./Modal";
import { PageTitle, type Crumb } from "./PageTitle";
import { Tag } from "./Tag";

// isDenyAction matches every action label the dispatcher emits for a
// "this request was blocked" outcome — legacy `deny` / `hitl_deny`
// (pre-migration rows) and the post-migration `denied`.
function isDenyAction(action: string): boolean {
  return action === "deny" || action === "denied" || action === "hitl_deny";
}

// approverKindLabel humanises the plugin type the dispatcher records
// on the event. Unknown values fall through verbatim so the dashboard
// stays useful as plugin types evolve.
function approverKindLabel(type?: string): string {
  switch (type) {
    case "llm_approver":
      return "LLM";
    case "human_approver":
      return "human";
    case "dashboard":
      return "dashboard";
    default:
      return type || "approver";
  }
}

export function RequestDetailPage({
  id,
  agents,
  productName,
}: {
  id: string;
  agents: Agent[];
  productName: string;
}) {
  const [ev, setEv] = useState<EventRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const { byFamily } = useFacets();

  useEffect(() => {
    getAction(id)
      .then(setEv)
      .catch((e) => setErr(e.message ?? "load failed"));
  }, [id]);

  if (err) {
    return (
      <Shell>
        <div className="text-sm text-danger-500">{err}</div>
      </Shell>
    );
  }
  if (!ev) {
    return (
      <Shell>
        <div className="text-xs text-text-subtle">Loading...</div>
      </Shell>
    );
  }

  const time = fmtDateTime(ev.ts);
  const status = ev.status ?? "";
  const statusColor = statusColorClass(status);
  const schema = ev.family ? byFamily[ev.family] : undefined;
  // SQL-family records come from the postgres / clickhouse_native
  // conn-family plugins. They populate Facets with verb / tables /
  // functions / statement. The HTTP-shaped fields (status, body,
  // headers) are unused for these rows; render the SQL-specific
  // section instead of the generic facets list so Statement gets a
  // dedicated code block. The header collapses to host only — the
  // full breakdown lives in SQLDetail below.
  const isSQL = ev.family === "sql" || ev.mode === "pg" || ev.mode === "clickhouse_native";
  const header = isSQL
    ? {
        verb: ((ev.facets?.verb as string | undefined) ?? ev.method ?? "").toUpperCase(),
        body: "",
      }
    : rowDescriptors(ev, schema);
  const { verb, body } = header;
  const fullUrl = ev.host + (body && !body.startsWith("/") ? " " : "") + body;
  const facetFields = facetDetailRows(ev, schema);
  const resultFields = resultDetailRows(ev, schema);
  const hasReq = !!ev.req_body;
  const hasResp = !!ev.resp_body;
  const hasReqH = ev.req_headers && Object.keys(ev.req_headers).length > 0;
  const hasRespH = ev.resp_headers && Object.keys(ev.resp_headers).length > 0;
  const hasFacets = !isSQL && facetFields.length > 0;
  const hasResult = !isSQL && resultFields.length > 0;
  const hasSections = hasFacets || hasResult || hasReq || hasResp || hasReqH || hasRespH;

  return (
    <Shell
      agentIP={ev.agent_ip}
      agentName={agents.find((a) => a.ip === ev.agent_ip)?.hostname}
      requestId={ev.id}
    >
      {/* header */}
      <div className="bg-canvas border-1.5 border-navy p-5 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <ApprovalStatusIcon ev={ev} inFlight={ev.phase === "start"} />
          {ev.mode === "splice" || ev.mode === "relay" ? (
            <LockGlyph />
          ) : (
            verb && (
              <span className="font-mono text-xs uppercase font-semibold text-text-muted">
                {verb}
              </span>
            )
          )}
          {!isSQL && (
            <span className={"text-sm font-semibold " + statusColor}>{status || "\u2014"}</span>
          )}
          <span className="text-sm text-text break-all font-mono" title={fullUrl}>
            {fullUrl}
          </span>
          <span className="ml-auto">
            <ActionButtons ev={ev} productName={productName} />
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs text-text-muted flex-wrap">
          <span>{time}</span>
          <span>{ev.ms}ms</span>
          {ev.agent_ip && <span>{ev.agent_ip}</span>}
          {ev.in != null && ev.in > 0 && <span>in: {fmtBytes(ev.in)}</span>}
          {ev.out != null && ev.out > 0 && <span>out: {fmtBytes(ev.out)}</span>}
        </div>
        {(ev.action || ev.reason || ev.approver) && (
          <div className="flex items-center gap-2 text-xs flex-wrap">
            {ev.action && (
              <Tag tone={isDenyAction(ev.action) ? "danger" : "success"}>{ev.action}</Tag>
            )}
            {ev.approver && (
              <span className="text-text-muted">
                by <span className="text-text">{approverKindLabel(ev.approver_type)}</span>{" "}
                <code>{ev.approver}</code>
                {ev.approver_by && <span className="text-text-muted"> · {ev.approver_by}</span>}
              </span>
            )}
            {ev.reason && <span className="text-text-muted">{ev.reason}</span>}
          </div>
        )}
      </div>

      {/* sections */}
      {isSQL ? (
        <SQLDetail ev={ev} />
      ) : hasSections ? (
        <div className="bg-canvas border-1.5 border-navy divide-y divide-canvas-dark">
          {hasFacets && (
            <Section title="Request">
              <Facets rows={facetFields} />
            </Section>
          )}
          {hasResult && (
            <Section title="Result">
              <Facets rows={resultFields} />
            </Section>
          )}
          {hasReqH && (
            <Section
              title="Request headers"
              action={
                <CopyButton label="request headers" text={() => headersToJSON(ev.req_headers!)} />
              }
            >
              <Headers obj={ev.req_headers!} />
            </Section>
          )}
          {hasReq && (
            <Section
              title="Request body"
              action={<CopyButton label="request body" text={() => ev.req_body!} />}
            >
              <HttpBody text={ev.req_body!} />
            </Section>
          )}
          {hasRespH && (
            <Section
              title="Response headers"
              action={
                <CopyButton label="response headers" text={() => headersToJSON(ev.resp_headers!)} />
              }
            >
              <Headers obj={ev.resp_headers!} />
            </Section>
          )}
          {hasResp && (
            <Section
              title={`Response body${status ? ` (${status})` : ""}`}
              action={<CopyButton label="response body" text={() => ev.resp_body!} />}
            >
              <HttpBody text={ev.resp_body!} />
            </Section>
          )}
        </div>
      ) : (
        <div className="bg-canvas border-1.5 border-navy px-5 py-4 text-xs text-text-subtle">
          No request/response body captured
          {ev.mode === "splice" && " (spliced connection)"}
        </div>
      )}
    </Shell>
  );
}

function ActionButtons({ ev, productName }: { ev: EventRecord; productName: string }) {
  const [ruleOpen, setRuleOpen] = useState(false);
  const canBlock = !!ev.id && ev.action !== "in_flight" && (!!ev.endpoint || ev.mode === "splice");
  return (
    <div className="flex items-center gap-2 flex-wrap justify-end">
      {canBlock && (
        <Button variant="outline" onClick={() => setRuleOpen(true)}>
          Block requests like this
        </Button>
      )}
      <DownloadActionButton ev={ev} productName={productName} />
      {ruleOpen && (
        <RulePreviewModal ev={ev} productName={productName} onClose={() => setRuleOpen(false)} />
      )}
    </div>
  );
}

// DownloadActionButton triggers a server-side reshape of this event
// into a `clawpatrol test` fixture and saves it as a .json file. The
// runner reads files in this exact format — drop the download into a
// fixtures/ directory and `clawpatrol test config.hcl fixtures/` will
// replay it against a candidate policy. See site/doc/clawpatrol-test.md.
function DownloadActionButton({ ev, productName }: { ev: EventRecord; productName: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!ev.id) return null;
  if (!ev.endpoint) return null;
  if (ev.action === "in_flight") return null;
  return (
    <Button
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        setErr(null);
        try {
          const blob = await downloadActionFixture(ev.id!);
          downloadBlob(blob, `${ev.id}.json`);
        } catch (e) {
          setErr((e as Error).message || "download failed");
        } finally {
          setBusy(false);
        }
      }}
      title={err ?? `Download as a ${productName} test fixture`}
    >
      {busy ? "Downloading…" : "Download action"}
    </Button>
  );
}

function RulePreviewModal({
  ev,
  productName,
  onClose,
}: {
  ev: EventRecord;
  productName: string;
  onClose: () => void;
}) {
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [hcl, setHCL] = useState("");
  const [busy, setBusy] = useState(true);
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!ev.id) return;
    setBusy(true);
    setErr(null);
    previewRuleFromAction(ev.id)
      .then((p) => {
        if (cancelled) return;
        setPreview(p);
        setHCL(p.hcl);
      })
      .catch((e) => {
        if (!cancelled) setErr((e as Error).message || "rule preview failed");
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ev.id]);

  async function copyHCL() {
    if (await copyText(hcl)) {
      setErr(null);
      setMsg("HCL copied.");
    } else {
      setMsg(null);
      setErr("Copy failed.");
    }
  }

  async function applyRule() {
    if (!preview?.config_revision) return;
    setApplying(true);
    setErr(null);
    setMsg(null);
    try {
      await applyGeneratedRule(preview.config_revision, hcl);
      setApplied(true);
    } catch (e) {
      const text = (e as Error).message || "apply failed";
      if (text.includes("config changed")) {
        setErr(
          "The config changed since this rule was generated. Regenerate the rule and try again.",
        );
      } else {
        setErr(text);
      }
    } finally {
      setApplying(false);
    }
  }

  const writesEnabled = !!preview?.dashboard_config_writes;
  const createsEndpoint = !!preview?.endpoint_name && preview.endpoint_name !== ev.endpoint;
  const passthrough = createsEndpoint || ev.mode === "splice";

  return (
    <Modal title="Block requests like this" size="lg" onClose={onClose}>
      <div className="p-4 space-y-3 overflow-auto">
        {applied ? (
          <div className="min-h-[300px] flex flex-col items-center justify-center text-center gap-4">
            <div className="flex items-center justify-center w-14 h-14 rounded-full border-2 border-success-600 text-success-600">
              <CheckLargeIcon />
            </div>
            <div className="space-y-2 max-w-[34rem]">
              <h3 className="text-lg font-semibold text-text">Rule applied</h3>
              <p className="text-sm text-text-muted">
                The generated HCL was validated, written to disk, and reloaded by the gateway. New
                matching requests will be denied.
              </p>
            </div>
          </div>
        ) : (
          <p className="text-sm text-text-muted">
            {passthrough
              ? `This request was passed through without MITM inspection because no endpoint matched it. ${productName} generated HCL that creates an endpoint for the observed host, claims it from existing profiles via a passthrough credential, and denies future matching requests before they pass through.`
              : `${productName} generated a narrow deny rule from this inspected action. Edit the condition if you want to broaden it.`}
          </p>
        )}
        {!applied && busy ? (
          <div className="text-xs text-text-subtle">Generating rule...</div>
        ) : !applied && err && !preview ? (
          <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>
        ) : !applied ? (
          <>
            {!writesEnabled && (
              <div className="border border-butter-600 bg-butter-100 px-3 py-2 text-xs text-text">
                Dashboard config writes are disabled for this gateway. Set{" "}
                <code>dashboard_config_writes = true</code> in the{" "}
                <a
                  href="https://clawpatrol.dev/docs/config-reference/#gateway--"
                  target="_blank"
                  rel="noreferrer"
                  className="underline"
                >
                  gateway block
                </a>{" "}
                to let the dashboard apply rules directly; until then, copy this HCL into your
                config and deploy it through your normal workflow.
              </div>
            )}
            {preview?.warnings?.map((w) => (
              <div key={w} className="border border-butter-600 bg-butter-100 px-3 py-2 text-xs">
                {w}
              </div>
            ))}
            {createsEndpoint && (
              <div className="border border-butter-600 bg-butter-100 px-3 py-2 text-xs">
                This will create endpoint <code>{preview.endpoint_name}</code> for future traffic.
                It does not retroactively inspect this request. A passthrough credential is added so
                existing profiles claim the endpoint; no auth is injected.
              </div>
            )}
            <textarea
              value={hcl}
              onChange={(e) => setHCL(e.target.value)}
              spellCheck={false}
              className="w-full min-h-[300px] resize-y border-1.5 border-navy bg-canvas p-3 font-mono text-xs text-text outline-none focus:bg-white"
            />
            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {msg && <div className="text-sm text-success-600">{msg}</div>}
          </>
        ) : null}
      </div>
      <div className="flex items-center gap-2 justify-end px-4 py-3 border-t border-navy bg-navy-100">
        {applied ? (
          <>
            <Button variant="outline" disabled={!preview} onClick={copyHCL}>
              Copy HCL
            </Button>
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </>
        ) : writesEnabled ? (
          <Button disabled={!preview || applying} onClick={applyRule}>
            {applying ? "Applying..." : "Apply rule"}
          </Button>
        ) : (
          <Button disabled={!preview} onClick={copyHCL}>
            Copy HCL
          </Button>
        )}
        {!applied && writesEnabled && (
          <Button variant="outline" disabled={!preview} onClick={copyHCL}>
            Copy HCL
          </Button>
        )}
      </div>
    </Modal>
  );
}

function CheckLargeIcon() {
  return (
    <svg
      width="28"
      height="28"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="m5 12 5 5L20 7" />
    </svg>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(href);
}

// --- SQL detail ---

// SQLDetail renders the postgres / clickhouse_native per-query view.
// Statement is the deliverable (operators want the raw SQL); verb /
// tables / functions are the parser's rule-targeting facets, surfaced
// here so it's obvious why a given rule fired or didn't. Reads from
// ev.facets (populated by the sql facet's Report hook) since the
// generic facet pipeline replaced the legacy direct fields.
function SQLDetail({ ev }: { ev: EventRecord }) {
  const f = ev.facets ?? {};
  const verb = (typeof f.verb === "string" ? f.verb : (ev.method ?? "")).toUpperCase();
  const tables = Array.isArray(f.tables) ? (f.tables as string[]) : [];
  const functions = Array.isArray(f.functions) ? (f.functions as string[]) : [];
  const statement = typeof f.statement === "string" ? f.statement : "";
  const facets: Array<{ label: string; value: string }> = [];
  if (verb) facets.push({ label: "Verb", value: verb });
  if (tables.length > 0) facets.push({ label: "Tables", value: tables.join(", ") });
  if (functions.length > 0) {
    facets.push({
      label: "Functions",
      value: functions.map((s) => s.toUpperCase()).join(", "),
    });
  }
  return (
    <div className="bg-canvas border-1.5 border-navy divide-y divide-canvas-dark">
      {facets.length > 0 && (
        <Section title="Details">
          <div className="px-4 py-3 grid grid-cols-[100px_1fr] gap-y-1.5 gap-x-3 text-xs">
            {facets.map((f) => (
              <div key={f.label} className="contents">
                <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle pt-0.5">
                  {f.label}
                </div>
                <div className="text-text font-mono break-all">{f.value}</div>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section title="Statement">
        {statement ? (
          <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs leading-relaxed text-text">
            {statement}
          </pre>
        ) : (
          <div className="px-4 py-3 text-xs text-text-subtle">(no parsed statement)</div>
        )}
      </Section>
    </div>
  );
}

// --- layout ---

function Shell({
  children,
  agentIP,
  agentName,
  requestId,
}: {
  children: React.ReactNode;
  agentIP?: string;
  agentName?: string;
  requestId?: string;
}) {
  const trail: Crumb[] = [];
  if (agentIP) {
    trail.push({ label: "Devices", href: "#/devices" });
    trail.push({
      label: agentName || agentIP,
      href: `#/device/${encodeURIComponent(agentIP)}`,
    });
  }
  if (requestId) {
    trail.push({
      label: (
        <span className="font-mono" title={requestId}>
          {requestId.split("-").pop()}
        </span>
      ),
    });
  }
  return (
    <Main>
      <PageTitle trail={trail} />
      {children}
    </Main>
  );
}

// facetDetailRows returns the per-family fields shown in the
// "facets" section under the request header. Renders every
// report-field the schema declares for which the event carries a
// non-empty value; unknown families fall back to the raw facets
// object so the operator still sees what was captured.
type FacetRow = { key: string; facet: string; description: string; value: string };

function facetDetailRows(ev: EventRecord, schema: FacetSchema | undefined): FacetRow[] {
  const facets = ev.facets;
  if (!facets || Object.keys(facets).length === 0) return [];
  if (!schema) {
    return Object.entries(facets).map(([k, v]) => ({
      key: k,
      facet: k,
      description: "",
      value: typeof v === "string" ? v : JSON.stringify(v),
    }));
  }
  const out: FacetRow[] = [];
  for (const f of schema.report_fields) {
    const v = formatFacetValue(f.kind, facets[f.name]);
    if (!v) continue;
    out.push({
      // The fully-qualified CEL name (e.g. "aws.action") is what an
      // operator writes in a matching rule — show it verbatim.
      key: f.name,
      facet: `${schema.name}.${f.name}`,
      description: f.description || f.label || "",
      value: v,
    });
  }
  return out;
}

// resultDetailRows returns the rows shown in the "result" section —
// the facet's result-field schema (e.g. the action's status). The
// only value available today is the action's status, which maps to
// the result field flagged `title`; the remaining declared fields
// have no per-field value yet, so they're skipped.
function resultDetailRows(ev: EventRecord, schema: FacetSchema | undefined): FacetRow[] {
  const fields = schema?.result_fields;
  if (!fields || fields.length === 0) return [];
  const status = ev.status ?? "";
  if (!status) return [];
  const out: FacetRow[] = [];
  for (const f of fields) {
    if (!f.title) continue;
    out.push({
      key: f.name,
      facet: `${schema!.name}.${f.name}`,
      description: f.description || f.label || "",
      value: status,
    });
  }
  return out;
}

// Facets renders the per-family report payload as a three-column table —
// the fully-qualified facet name (what you write in a rule), a human
// description, and the captured value — so an operator can see exactly
// what's matchable. No masking: the facets payload is policy metadata,
// not secret material (credentials live in headers).
function Facets({ rows }: { rows: FacetRow[] }) {
  return (
    <div className="overflow-auto px-4 py-3">
      <table className="w-full font-mono text-xs">
        <thead>
          <tr className="text-2xs uppercase tracking-wider text-text-subtle">
            <th className="text-left font-semibold pb-1.5 pr-4">Facet</th>
            <th className="text-left font-semibold pb-1.5 pr-4">Description</th>
            <th className="text-left font-semibold pb-1.5">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="align-top border-t border-canvas-muted">
              <td className="py-1.5 pr-4 font-semibold text-text whitespace-nowrap">{r.facet}</td>
              <td className="py-1.5 pr-4 text-text-subtle">{r.description}</td>
              <td className="py-1.5 text-text-muted break-all">{r.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Section({
  title,
  children,
  action,
}: {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <details open>
      <summary className="cursor-pointer flex items-center gap-2 px-4 py-1.5 text-xs font-mono uppercase tracking-wider font-bold text-navy bg-navy-100 border-b border-navy hover:text-text select-none">
        <span>{title}</span>
        {action && <span className="ml-auto">{action}</span>}
      </summary>
      <div>{children}</div>
    </details>
  );
}

// --- headers ---

const SENSITIVE = /auth|token|secret|key|password|cookie/i;

function Headers({ obj }: { obj: Record<string, string> }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs leading-relaxed">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k}>
          <span className="font-semibold text-text">{k}</span>
          <span className="text-text-subtle">: </span>
          {SENSITIVE.test(k) ? (
            <span className="text-text-subtle">{"*".repeat(Math.min(v.length, 24))}</span>
          ) : (
            <span className="text-text-muted">{v}</span>
          )}
        </div>
      ))}
    </pre>
  );
}

// --- body rendering (JSON tree / SSE / plain) ---

// tryParseJSON attempts JSON.parse; on failure (e.g. truncated at
// the 4KB sampler cap) walks backward to find the last position
// where closing all open containers yields valid JSON.
function tryParseJSON(text: string): {
  parsed: unknown;
  truncated: boolean;
} | null {
  try {
    return { parsed: JSON.parse(text), truncated: false };
  } catch {
    /* fall through */
  }
  // Walk the string tracking container depth, ignoring string
  // interiors. At each position where we're outside a string
  // and just finished a complete value (after , or : or [ or {),
  // record it as a candidate cut point.
  let inStr = false;
  let esc = false;
  const stack: string[] = [];
  let lastGoodCut = -1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (esc) {
      esc = false;
      continue;
    }
    if (ch === "\\") {
      esc = true;
      continue;
    }
    if (ch === '"') {
      inStr = !inStr;
      continue;
    }
    if (inStr) continue;
    if (ch === "{") stack.push("}");
    else if (ch === "[") stack.push("]");
    else if (ch === "}" || ch === "]") {
      stack.pop();
      lastGoodCut = i + 1;
    } else if (ch === ",") {
      lastGoodCut = i;
    }
  }
  // Try cutting at each candidate, newest first
  for (let cut = lastGoodCut; cut > 0; cut--) {
    // Re-scan up to cut to get the stack state
    const st: string[] = [];
    let ins = false;
    let es = false;
    for (let i = 0; i < cut; i++) {
      const c = text[i];
      if (es) {
        es = false;
        continue;
      }
      if (c === "\\") {
        es = true;
        continue;
      }
      if (c === '"') {
        ins = !ins;
        continue;
      }
      if (ins) continue;
      if (c === "{") st.push("}");
      else if (c === "[") st.push("]");
      else if (c === "}" || c === "]") st.pop();
    }
    let attempt = text.slice(0, cut);
    // Strip trailing comma
    if (attempt.endsWith(",")) {
      attempt = attempt.slice(0, -1);
    }
    attempt += st.reverse().join("");
    try {
      return { parsed: JSON.parse(attempt), truncated: true };
    } catch {
      continue;
    }
  }
  return null;
}

// SSE bodies (text/event-stream) are blocks of `event:`/`data:` lines
// separated by blank lines. Returns null when the body doesn't look
// like SSE.
type SseEvent = { type?: string; id?: string; data: string };
function parseSSE(text: string): SseEvent[] | null {
  if (!/^(event|data|id|retry):/m.test(text)) return null;
  const events: SseEvent[] = [];
  for (const block of text.split(/\r?\n\r?\n+/)) {
    if (!block.trim()) continue;
    const ev: SseEvent = { data: "" };
    let valid = false;
    for (const line of block.split(/\r?\n/)) {
      const idx = line.indexOf(":");
      if (idx <= 0) continue;
      const k = line.slice(0, idx);
      let v = line.slice(idx + 1);
      if (v.startsWith(" ")) v = v.slice(1);
      if (k === "event") {
        ev.type = v;
        valid = true;
      } else if (k === "data") {
        ev.data = ev.data ? ev.data + "\n" + v : v;
        valid = true;
      } else if (k === "id") ev.id = v;
    }
    if (valid) events.push(ev);
  }
  return events.length > 0 ? events : null;
}

// BODY_TRUNCATED_MARKER mirrors bodyTruncatedMarker in cmd/clawpatrol/web.go.
// The gateway appends it to a persisted body sample when the body exceeded
// the actions-table cap. We strip it before parsing/rendering and surface a
// badge so an operator knows they are looking at a prefix, not the whole body.
const BODY_TRUNCATED_MARKER = "\n[clawpatrol:body-truncated]";

function CapBadge() {
  return (
    <div className="mb-2 inline-block rounded bg-amber-500/15 px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wider text-amber-600">
      truncated — body exceeded actions cap
    </div>
  );
}

function HttpBody({ text: rawText }: { text: string }) {
  if (!rawText) return <div className="px-4 py-3 text-xs text-text-subtle">(empty)</div>;
  const capped = rawText.endsWith(BODY_TRUNCATED_MARKER);
  const text = capped ? rawText.slice(0, -BODY_TRUNCATED_MARKER.length) : rawText;
  if (!text) {
    return (
      <div className="px-4 py-3 text-xs text-text-subtle">
        <CapBadge />
      </div>
    );
  }
  const result = tryParseJSON(text);
  if (result) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-xs leading-relaxed">
        {capped && <CapBadge />}
        <JsonNode value={result.parsed} />
        {result.truncated && <div className="mt-2 text-2xs text-text-subtle">(truncated)</div>}
      </div>
    );
  }
  const sse = parseSSE(text);
  if (sse) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-xs leading-relaxed space-y-3">
        {capped && <CapBadge />}
        {sse.map((e, i) => {
          const dataJson = tryParseJSON(e.data);
          return (
            <div key={i}>
              {e.type && (
                <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle mb-1">
                  event:{" "}
                  <span className="normal-case tracking-normal text-text-muted">{e.type}</span>
                </div>
              )}
              {dataJson ? (
                <>
                  <JsonNode value={dataJson.parsed} />
                  {dataJson.truncated && (
                    <div className="mt-1 text-2xs text-text-subtle">(truncated)</div>
                  )}
                </>
              ) : (
                <pre className="whitespace-pre-wrap break-all text-text-muted">{e.data}</pre>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return (
    <div className="overflow-auto px-4 py-3">
      {capped && <CapBadge />}
      <pre className="whitespace-pre-wrap break-all font-mono text-xs text-text-muted">{text}</pre>
    </div>
  );
}

// --- JSON tree (ported from unclaw) ---

const LONG_STRING = 120;

function JsonNode({ value }: { value: unknown }) {
  if (value === null) {
    return <span className="font-semibold text-text-subtle">null</span>;
  }
  if (typeof value === "boolean") {
    return <span className="font-semibold text-rust-700">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="text-navy-500">{String(value)}</span>;
  }
  if (typeof value === "string") {
    return <StringNode value={value} />;
  }
  if (Array.isArray(value)) {
    return (
      <Collapsible bracket={["[", "]"]} count={value.length}>
        {value.map((v, i) => (
          <div key={i} className="pl-5">
            <JsonNode value={v} />
            {i < value.length - 1 && ","}
          </div>
        ))}
      </Collapsible>
    );
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      <Collapsible bracket={["{", "}"]} count={entries.length}>
        {entries.map(([k, v], i) => (
          <div key={k} className="pl-5">
            <span className="text-danger-700">{JSON.stringify(k)}</span>
            {": "}
            <JsonNode value={v} />
            {i < entries.length - 1 && ","}
          </div>
        ))}
      </Collapsible>
    );
  }
  return <span>{String(value)}</span>;
}

function StringNode({ value }: { value: string }) {
  const raw = JSON.stringify(value);
  const long = raw.length > LONG_STRING;
  const [expanded, setExpanded] = useState(!long);

  if (!long) {
    return <span className="text-success-700">{raw}</span>;
  }
  if (!expanded) {
    return (
      <span>
        <span className="text-success-700">{raw.slice(0, LONG_STRING)}</span>
        <button onClick={() => setExpanded(true)} className="ml-1 text-navy-500 hover:underline">
          +{raw.length - LONG_STRING} more
        </button>
      </span>
    );
  }
  const inner = raw.slice(1, -1);
  const lines = inner.split("\\n");
  return (
    <span className="text-success-700">
      {'"'}
      {lines.map((line, i) => (
        <span key={i}>
          {line}
          {i < lines.length - 1 && (
            <>
              <span className="text-text-subtle">\n</span>
              <br />
            </>
          )}
        </span>
      ))}
      {'"'}
      <button onClick={() => setExpanded(false)} className="ml-1 text-navy-500 hover:underline">
        less
      </button>
    </span>
  );
}

function Collapsible({
  bracket,
  count,
  children,
}: {
  bracket: [string, string];
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  if (count === 0) {
    return (
      <span>
        {bracket[0]}
        {bracket[1]}
      </span>
    );
  }
  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-text cursor-pointer">
        {bracket[0]} <span className="text-navy-500">{count} items</span> {bracket[1]}
      </button>
    );
  }
  return (
    <span>
      <button onClick={() => setOpen(false)} className="hover:text-text-subtle">
        {bracket[0]}
      </button>
      {children}
      <div>{bracket[1]}</div>
    </span>
  );
}

// --- utils ---

function fmtBytes(n: number): string {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}
