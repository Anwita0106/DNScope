import { useEffect, useState } from "react";
import { api } from "../api";
import type { Navigate } from "../App";
import { Card, DomainForm, Empty, ErrorBox, STATUS_STYLE, SeverityBadge, SimulatedTag, Spinner } from "../components/ui";
import type { CheckResult } from "../types";

const TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"];

export default function LookupPage({ initialDomain, navigate }: { initialDomain: string; navigate: Navigate }) {
  const [result, setResult] = useState<CheckResult | null>(null);
  const [types, setTypes] = useState<string[]>(TYPES);
  const [tab, setTab] = useState("A");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const run = async (domain: string) => {
    setBusy(true); setErr("");
    try { const r = await api.lookup(domain, types); setResult(r); setTab("A"); }
    catch (e) { setErr((e as Error).message); setResult(null); }
    finally { setBusy(false); }
  };
  useEffect(() => { if (initialDomain) run(initialDomain); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const rows = result?.records?.[tab] ?? [];
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">DNS Lookup</h1>
      <Card>
        <DomainForm busy={busy} initial={initialDomain} onSubmit={run} />
        <div className="mt-4 flex flex-wrap gap-2 text-sm">
          {TYPES.map((t) => (
            <label key={t} className={`cursor-pointer rounded-md border px-3 py-1 ${types.includes(t) ? "border-teal-400 text-teal-300" : "border-ink-600 text-muted"}`}>
              <input type="checkbox" className="sr-only" checked={types.includes(t)} disabled={t === "A"}
                onChange={() => setTypes((cur) => cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t])} />
              {t}
            </label>
          ))}
          <span className="self-center text-xs text-muted">A records are always queried (they drive the comparison).</span>
        </div>
      </Card>
      {busy && <Spinner />}
      {err && <ErrorBox message={err} />}
      {!result && !busy && !err && <Empty>Enter a domain to see its records from four resolvers, with TTL, response code and DNS flags.</Empty>}
      {result && (
        <>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted">
            <span className="font-mono text-lg text-white">{result.domain}</span>
            {result.simulated && <SimulatedTag />}
            <span>run {result.run_id}</span>
            {!result.warmup.complete && <span className="text-amber-300">Warm-up: {result.warmup.checks_completed}/{result.warmup.required} checks — history rules not active yet</span>}
            <button className="text-teal-300 hover:underline" onClick={() => navigate("compare", result.domain)}>Open comparison →</button>
          </div>
          {result.alerts.length > 0 && (
            <Card title={`Alerts from this check (${result.alerts.length})`}>
              <ul className="space-y-2">
                {result.alerts.map((a) => (
                  <li key={a.alert_id} className="flex flex-wrap items-center gap-2 text-sm">
                    <SeverityBadge severity={a.severity} /><span className="font-mono text-teal-300">{a.rule_id}</span>
                    <span className="text-slate-200">{a.explanation}</span>
                    {a.repeat && <span className="text-xs text-muted">(already open)</span>}
                  </li>
                ))}
              </ul>
              <button className="mt-3 text-sm text-teal-300 hover:underline" onClick={() => navigate("alerts", result.domain)}>Investigate in Security Alerts →</button>
            </Card>
          )}
          <Card>
            <div className="mb-4 flex flex-wrap gap-1" role="tablist">
              {Object.keys(result.records ?? {}).map((t) => (
                <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                  className={`rounded-md px-3 py-1.5 text-sm ${tab === t ? "bg-ink-700 font-semibold text-white" : "text-muted hover:text-white"}`}>{t}</button>
              ))}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-muted">
                  <tr><th className="pb-2">Resolver</th><th>Status</th><th>Records</th><th>TTL (s)</th><th>Flags</th><th>Time</th></tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.resolver} className="border-t border-ink-700 align-top">
                      <td className="py-2.5 pr-3"><div>{r.resolver}</div><div className="font-mono text-xs text-muted">{r.resolver_ip}</div></td>
                      <td className={`pr-3 font-mono ${STATUS_STYLE[r.status] ?? ""}`}>{r.rcode || r.status.toUpperCase()}</td>
                      <td className="pr-3 font-mono text-slate-200">
                        {r.values.length ? r.values.map((v) => <div key={v} className="break-all">{v}</div>) : <span className="text-muted">{r.status === "ok" ? "no records of this type" : r.error || "—"}</span>}
                        {r.cname_chain.length > 0 && <div className="text-xs text-muted">via CNAME {r.cname_chain.join(" → ")}</div>}
                      </td>
                      <td className="pr-3">{r.ttl ?? "—"}</td>
                      <td className="pr-3 font-mono text-xs">
                        {(["aa", "tc", "ra", "ad"] as const).filter((f) => r.flags[f]).map((f) => f.toUpperCase()).join(" ") || "—"}
                        {r.used_tcp && <div className="text-amber-300">TCP retry</div>}
                      </td>
                      <td className="whitespace-nowrap text-muted">{r.response_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs text-muted">Flags: AA authoritative answer · TC truncated · RA recursion available · AD DNSSEC-authenticated data.</p>
          </Card>
        </>
      )}
    </div>
  );
}
