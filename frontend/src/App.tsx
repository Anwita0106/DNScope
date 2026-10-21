import { useEffect, useState } from "react";
import { api } from "./api";
import type { Page } from "./types";
import OverviewPage from "./pages/Overview";
import LookupPage from "./pages/Lookup";
import ComparePage from "./pages/Compare";
import AlertsPage from "./pages/Alerts";
import HistoryPage from "./pages/History";

const PAGES: { id: Page; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "lookup", label: "DNS Lookup" },
  { id: "compare", label: "Response Comparison" },
  { id: "alerts", label: "Security Alerts" },
  { id: "history", label: "Domain History" },
];

export type Navigate = (page: Page, domain?: string) => void;

function readHash(): { page: Page; domain: string } {
  const [p, q] = window.location.hash.replace(/^#\/?/, "").split("?");
  const page = (PAGES.find((x) => x.id === p)?.id ?? "overview") as Page;
  return { page, domain: new URLSearchParams(q).get("d") ?? "" };
}

export default function App() {
  const [{ page, domain }, setRoute] = useState(readHash);
  const [health, setHealth] = useState<"checking" | "ok" | "down">("checking");
  const [ai, setAi] = useState("");

  useEffect(() => {
    const onHash = () => setRoute(readHash());
    window.addEventListener("hashchange", onHash);
    api.health().then((h) => { setHealth("ok"); setAi(h.ai.available ? `AI: ${h.ai.model}` : "AI: rule-based fallback"); })
      .catch(() => setHealth("down"));
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const navigate: Navigate = (p, d) => {
    window.location.hash = `/${p}${d ? `?d=${encodeURIComponent(d)}` : ""}`;
  };

  return (
    <div className="flex min-h-screen bg-ink-900 text-white">
      <aside className="flex w-60 shrink-0 flex-col bg-ink-950 px-4 py-6">
        <div className="mb-8 flex items-center gap-2 px-2">
          <span className="grid h-8 w-8 place-items-center rounded-full bg-teal-500"><span className="h-3 w-3 rounded-full bg-ink-900" /></span>
          <span className="text-xl font-bold">DNScope</span>
        </div>
        <nav className="space-y-1" aria-label="Main">
          {PAGES.map((p, i) => (
            <button key={p.id} onClick={() => navigate(p.id, domain || undefined)}
              className={`w-full rounded-lg px-3 py-2.5 text-left text-sm transition ${page === p.id ? "bg-teal-500 font-semibold text-ink-900" : "text-muted hover:bg-ink-800 hover:text-white"}`}>
              <span className="mr-2 opacity-70">{i + 1}</span>{p.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-1 px-2 text-xs">
          <div className={health === "ok" ? "text-teal-300" : health === "down" ? "text-red-300" : "text-muted"}>
            ● Backend {health === "ok" ? "connected" : health === "down" ? "not reachable" : "…"}
          </div>
          {ai && <div className="text-muted">{ai}</div>}
          <div className="pt-2 text-muted">Observe. Compare. Investigate.</div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-8 py-7">
        {page === "overview" && <OverviewPage navigate={navigate} />}
        {page === "lookup" && <LookupPage initialDomain={domain} navigate={navigate} />}
        {page === "compare" && <ComparePage initialDomain={domain} navigate={navigate} />}
        {page === "alerts" && <AlertsPage initialDomain={domain} />}
        {page === "history" && <HistoryPage initialDomain={domain} navigate={navigate} />}
      </main>
    </div>
  );
}
