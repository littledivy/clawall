import { useEffect, useState } from "react";
import { AccountPage } from "./components/AccountPage";
import { AgentsTable, sortAgents } from "./components/AgentsTable";
import { AnalyticsPage } from "./components/AnalyticsPage";
import { ConnectModal } from "./components/ConnectModal";
import { DevicePage } from "./components/DevicePage";
import { DevicesPage } from "./components/DevicesPage";
import { Header } from "./components/Header";
import { HITLBar } from "./components/HITLBar";
import { LiveRequests } from "./components/LiveRequests";
import { Main } from "./components/Main";
import { OnboardPage } from "./components/OnboardPage";
import { PageTitle } from "./components/PageTitle";
import { PluginsPage } from "./components/PluginsPage";
import { RequestDetailPage } from "./components/RequestDetailPage";
import { SettingsPage } from "./components/SettingsPage";
import {
  getState,
  type Agent,
  type DashboardBranding,
  type Integration,
  type UpdateBanner,
  type Whoami,
} from "./lib/api";

declare global {
  interface Window {
    __CLAWPATROL_INITIAL_BRANDING__?: DashboardBranding;
  }
}

type Route =
  | { name: "main" }
  | { name: "devices" }
  | { name: "device"; ip: string }
  | { name: "analytics"; ip?: string }
  | { name: "onboard"; code: string }
  | { name: "request"; id: string }
  | { name: "settings" }
  | { name: "plugins" }
  | { name: "account" };

function parseRoute(): Route {
  const raw = window.location.hash;
  const qi = raw.indexOf("?");
  const h = qi < 0 ? raw : raw.slice(0, qi);
  if (h.startsWith("#/onboard/"))
    return {
      name: "onboard",
      code: decodeURIComponent(h.slice("#/onboard/".length)),
    };
  const r = h.match(/^#\/request\/([^/]+)$/);
  if (r) return { name: "request", id: decodeURIComponent(r[1]) };
  if (h === "#/settings") return { name: "settings" };
  if (h === "#/plugins") return { name: "plugins" };
  if (h === "#/devices") return { name: "devices" };
  if (h === "#/account") return { name: "account" };
  if (h === "#/analytics") return { name: "analytics" };
  const a = h.match(/^#\/analytics\/([^/]+)$/);
  if (a) return { name: "analytics", ip: decodeURIComponent(a[1]) };
  // Legacy device/IP/analytics URL
  const da = h.match(/^#\/device\/([^/]+)\/analytics$/);
  if (da) return { name: "analytics", ip: decodeURIComponent(da[1]) };
  const m = h.match(/^#\/device\/([^/]+)$/);
  if (m) return { name: "device", ip: decodeURIComponent(m[1]) };
  return { name: "main" };
}

export default function App() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  const [update, setUpdate] = useState<UpdateBanner | null>(null);
  const [branding, setBranding] = useState<DashboardBranding | null>(
    () => window.__CLAWPATROL_INITIAL_BRANDING__ ?? null,
  );
  const [configFile, setConfigFile] = useState<string>("gateway.hcl");
  const [connectId, setConnectId] = useState<string | null>(null);
  const [route, setRoute] = useState(parseRoute());

  useEffect(() => {
    const onHash = () => setRoute(parseRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  async function refresh() {
    try {
      // Single round-trip; getState ETags so the no-change path is a
      // 304 (no body, no JSON parse). Replaces three parallel fetches
      // that ran every 3 s — one bundled fetch every 5 s now.
      const s = await getState();
      setIntegrations(s.integrations || []);
      setAgents(s.agents || []);
      setWhoami(s.whoami);
      setUpdate(s.update ?? null);
      setBranding(s.branding ?? null);
      if (s.config_file) setConfigFile(s.config_file);
    } catch {
      /* swallow */
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    document.title = branding?.name?.trim() || "Claw Patrol";
  }, [branding]);

  const productName = branding?.name?.trim() || "Claw Patrol";

  function navigate(hash: string) {
    window.location.hash = hash;
    setRoute(parseRoute());
  }

  return (
    <div className="flex flex-col min-h-screen bg-canvas">
      <UpdateNotice update={update} productName={productName} />
      <Header branding={branding} whoami={whoami} currentRoute={route.name} />
      {route.name === "main" ? (
        <Main>
          <PageTitle trail={[{ label: "Live overview" }]} />
          <HomeAgents
            agents={agents}
            integrations={integrations}
            onSelect={(ip) => navigate("#/device/" + encodeURIComponent(ip))}
          />
          <HITLBar />
          <LiveRequests height="420px" />
        </Main>
      ) : route.name === "devices" ? (
        <DevicesPage
          agents={agents}
          integrations={integrations}
          whoami={whoami}
          onSelect={(ip) => navigate("#/device/" + encodeURIComponent(ip))}
        />
      ) : route.name === "analytics" ? (
        <AnalyticsPage ip={route.ip} agents={agents} />
      ) : route.name === "request" ? (
        <RequestDetailPage id={route.id} agents={agents} productName={productName} />
      ) : route.name === "onboard" ? (
        <OnboardPage code={route.code} />
      ) : route.name === "settings" ? (
        <SettingsPage
          integrations={integrations}
          onConnect={(id) => setConnectId(id)}
          onRefresh={refresh}
        />
      ) : route.name === "plugins" ? (
        <PluginsPage />
      ) : route.name === "account" ? (
        <AccountPage whoami={whoami} />
      ) : (
        <DevicePage
          ip={route.ip}
          agents={agents}
          integrations={integrations}
          configFile={configFile}
          productName={productName}
          onBack={() => navigate("")}
          onConnect={(id) => setConnectId(id)}
          onRefresh={refresh}
        />
      )}
      {connectId && (
        <ConnectModal
          id={connectId}
          oauth={integrations.find((i) => i.id === connectId)?.oauth}
          onClose={() => setConnectId(null)}
          onDone={() => {
            setConnectId(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}

// HomeAgents shows the first N agents on the home page with a link
// to the full devices list when there's more. Sorted by activity
// (last_at, bucketed to the hour) so the most-recently-active devices
// surface but the order doesn't churn on every ping.
const HOME_AGENTS_LIMIT = 10;
function HomeAgents({
  agents,
  integrations,
  onSelect,
}: {
  agents: Agent[];
  integrations: Integration[];
  onSelect: (ip: string) => void;
}) {
  const sorted = sortAgents(agents, "activity");
  const shown = sorted.slice(0, HOME_AGENTS_LIMIT);
  const overflow = sorted.length - shown.length;
  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="overflow-x-auto">
        <AgentsTable
          agents={shown}
          integrations={integrations}
          onSelect={onSelect}
          sortBy="activity"
        />
      </div>
      {overflow > 0 && (
        <a
          href="#/devices"
          className={
            "block bg-canvas px-4 py-2.5 text-left underline text-xs " +
            "font-mono uppercase tracking-wider text-navy font-bold " +
            "hover:bg-canvas-muted transition-colors"
          }
        >
          …and {overflow} more →
        </a>
      )}
    </section>
  );
}

function UpdateNotice({
  update,
  productName,
}: {
  update: UpdateBanner | null;
  productName: string;
}) {
  if (!update?.update_available) return null;
  const dismissKey = "clawpatrol:update-dismissed:" + update.latest;
  const [dismissed, setDismissed] = useState(
    typeof localStorage !== "undefined" && localStorage.getItem(dismissKey) === "1",
  );
  if (dismissed) return null;
  return (
    <div className="bg-butter-100 border-b border-butter-300 px-4 sm:px-4 py-2 text-xs text-text flex items-center justify-between gap-3">
      <div className="flex-1">
        <span className="font-semibold">
          {productName} {update.latest}
        </span>
        {" available — "}
        <a
          href={update.url}
          target="_blank"
          rel="noopener noreferrer"
          className="underline hover:no-underline"
        >
          release notes
        </a>
        {update.advisory && <span className="ml-2 text-rust-700">({update.advisory})</span>}
      </div>
      <button
        onClick={() => {
          localStorage.setItem(dismissKey, "1");
          setDismissed(true);
        }}
        className="text-butter-900 hover:text-text text-lg leading-none px-1 cursor-pointer hover:bg-butter-300 squircle-md p-1 pb-1.5 pt-0.5 aspect-square h-6 transition-colors"
        title="dismiss"
      >
        <span aria-hidden="true">&times;</span>
        <span className="sr-only">Dismiss</span>
      </button>
    </div>
  );
}
