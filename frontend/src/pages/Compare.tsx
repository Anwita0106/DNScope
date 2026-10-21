import { useEffect, useState } from "react";
import { api } from "../api";
import type { Navigate } from "../App";
import { AlertDetail, Card, DomainForm, Empty, ErrorBox, STATUS_STYLE, SimulatedTag, Spinner } from "../components/ui";
import type { CheckResult } from "../types";

const STATUS_TEXT: Record<string, { label: string; tone: string }> = {
  agree: { label: "Resolvers agree", tone: "text-green-400" },
  outlier: { label: "Outlier detected", tone: "text-red-400" },
  all_different: { label: "All different (CDN / geo-DNS likely)", tone: "text-amber-300" },
  differ: { label: "Two resolvers differ", tone: "text-amber-300" },
  insufficient: { label: "Not enough answers", tone: "text-muted" },
};

export default function ComparePage({ initialDomain, navigate }: { initialDomain: string; navigate: Navigate }) {
  const [rtype, setRtype] = useState<"A" | "AAAA">("A");
  const [result, setResult] = useState<CheckResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const run = async (domain: string, rt = rtype) => {
    setBusy(true); setErr("");
    try { setResult(await api.compare(domain, rt)); } catch (e) { setErr((e as Error).message); setResult(null); } finally { setBusy(false); }
  };
  useEffect(() => { if (initialDomain) run(initialDomain); }, [initialDomain]); // eslint-disable-line react-hooks/exhaustive-deps

  const outliers = new Set(result?.comparison?.outliers ?? []);
  const ttlMax = Math.max(0, ...(result?.rows ?? []).map((r) => r.ttl ?? 0));
  const st = STATUS_TEXT[result?.comparison?.status ?? "insufficient"];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Response Comparison</h1>
      <Card>
        <DomainForm key={initialDomain} busy={busy} initial={initialDomain} button="Compare resolvers" onSubmit={(d) => run(d)}
          extra={
            <select value={rtype} aria-label="Record type" onChange={(e) => { const v = e.target.value as "A" | "AAAA"; setRtype(v); if (result) run(result.domain, v); }}
              className="rounded-lg border border-ink-600 bg-ink-900 px-3 py-2.5">
              <option value="A">A (IPv4)</option><option value="AAAA">AAAA (IPv6)</option>
            </select>
          } />
      </Card>
      {busy && <Spinner />}
      {err && <ErrorBox message={err} />}
      {!result && !busy && !err && <Empty>Send the same query to your system resolver, Google (8.8.8.8), Cloudflare (1.1.1.1) and Quad9 (9.9.9.9) and compare the answers side by side.</Empty>}
      {result && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-lg">{result.domain}</span>
            {result.simulated && <SimulatedTag />}
            <span className={`font-semibold ${st.tone}`}>{st.label}</span>
            <span className="text-sm text-muted">{result.comparison?.note}</span>
          </div>
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-muted">
                  <tr><th className="pb-2">Resolver</th><th>Answer ({result.record_type})</th><th>Network</th><th>TTL (s)</th><th>RCODE</th><th>AD</th><th>Time</th><th>Match</th></tr>
                </thead>
                <tbody>
                  {result.rows?.map((r) => {
                    const out = outliers.has(r.resolver);
                    return (
                      <tr key={r.resolver} className={`border-t border-ink-700 ${out ? "bg-red-500/10" : ""}`}>
                        <td className="py-3 pr-3"><div className="font-medium">{r.resolver}</div><div className="font-mono text-xs text-muted">{r.resolver_ip}</div></td>
                        <td className={`pr-3 font-mono ${out ? "font-bold text-red-300" : "text-slate-200"}`}>{r.values.join(", ") || <span className="text-muted">—</span>}</td>
                        <td className="pr-3 font-mono text-xs text-muted">{r.prefixes.join(", ") || "—"}</td>
                        <td className="pr-3">
                          <div className="flex items-center gap-2">
                            <span className={out ? "font-bold text-red-300" : ""}>{r.ttl ?? "—"}</span>
                            {r.ttl != null && ttlMax > 0 && <span className="h-1.5 w-16 rounded bg-ink-700"><span className="block h-1.5 rounded bg-teal-500" style={{ width: `${(100 * r.ttl) / ttlMax}%` }} /></span>}
                          </div>
                        </td>
                        <td className={`pr-3 font-mono ${STATUS_STYLE[r.status] ?? ""}`}>{r.rcode || r.status.toUpperCase()}</td>
                        <td className="pr-3">{r.flags.ad ? "✓" : "—"}</td>
                        <td className="pr-3 whitespace-nowrap text-muted">{r.response_ms} ms</td>
                        <td>
                          {r.values.length === 0 ? <span className="text-muted">no answer</span>
                            : out ? <span className="rounded bg-red-500 px-2 py-0.5 text-xs font-bold text-ink-900">differs</span>
                              : <span className="rounded bg-green-500 px-2 py-0.5 text-xs font-bold text-ink-900">agrees</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs text-muted">“Network” groups addresses by /24 (IPv4) or /48 (IPv6) prefix, so hosts in the same provider network count as agreeing. Cached answers report the remaining TTL, so small TTL differences are normal.</p>
          </Card>
          {result.alerts.length > 0 ? (
            <div className="grid gap-4 xl:grid-cols-2">
              {result.alerts.map((a) => <Card key={a.alert_id}><AlertDetail alert={a} /></Card>)}
            </div>
          ) : (
            <Card><p className="text-green-300">No rule was triggered for this check.</p>
              {!result.warmup.complete && <p className="mt-1 text-sm text-amber-300">Warm-up {result.warmup.checks_completed}/{result.warmup.required}: history-based rules (R1, R3) start after {result.warmup.required} successful checks.</p>}
            </Card>
          )}
          <button className="text-sm text-teal-300 hover:underline" onClick={() => navigate("history", result.domain)}>See this domain's history →</button>
        </>
      )}
    </div>
  );
}
