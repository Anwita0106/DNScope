import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import type { Navigate } from "../App";
import { Card, DomainForm, Empty, ErrorBox, SeverityBadge, Spinner, StatCard, fmtTime } from "../components/ui";
import type { History } from "../types";

export default function HistoryPage({ initialDomain, navigate }: { initialDomain: string; navigate: Navigate }) {
  const [data, setData] = useState<History | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = async (domain: string) => {
    setBusy(true); setErr("");
    try { setData(await api.history(domain)); } catch (e) { setErr((e as Error).message); setData(null); } finally { setBusy(false); }
  };
  useEffect(() => { if (initialDomain) load(initialDomain); }, [initialDomain]); // eslint-disable-line react-hooks/exhaustive-deps

  const p = data?.profile;
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Domain History</h1>
      <Card><DomainForm key={initialDomain} busy={busy} initial={initialDomain} button="Show history" onSubmit={load} /></Card>
      {busy && <Spinner label="Loading history…" />}
      {err && <ErrorBox message={err} />}
      {!data && !busy && !err && <Empty>Pick a domain you have checked before to see its addresses, TTL trend and alerts over time.</Empty>}
      {data && p && (
        <>
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            <StatCard label="Checks recorded" value={data.total_runs} tone="text-teal-400" />
            <StatCard label="Known addresses" value={p.known_ips.length} tone="text-cyan-400" />
            <StatCard label="TTL baseline" value={p.ttl_baseline ? `${p.ttl_baseline} s` : "—"} tone="text-white" />
            <StatCard label="DNSSEC seen" value={p.dnssec_seen ? "Yes" : "No"} tone={p.dnssec_seen ? "text-green-400" : "text-muted"} />
          </div>
          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="TTL trend (highest TTL per check, A records)">
              {data.ttl_series.length === 0 ? <Empty>No A-record answers yet.</Empty> : (
                <div className="h-60">
                  <ResponsiveContainer>
                    <LineChart data={data.ttl_series} margin={{ left: -10, right: 8 }}>
                      <CartesianGrid stroke="#2B4163" vertical={false} />
                      <XAxis dataKey="time" tickFormatter={(t: string) => fmtTime(t)} stroke="#B6C3D4" fontSize={11} minTickGap={30} />
                      <YAxis stroke="#B6C3D4" fontSize={12} />
                      <Tooltip labelFormatter={(t) => fmtTime(String(t))} contentStyle={{ background: "#0B1628", border: "1px solid #2B4163", borderRadius: 8 }} />
                      <Line type="stepAfter" dataKey="max_ttl" name="TTL (s)" stroke="#22D3EE" strokeWidth={2.5} dot={{ r: 2 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
            <Card title="Known networks (baseline)">
              <div className="flex flex-wrap gap-2">
                {p.known_prefixes.map((x) => <span key={x} className="rounded bg-ink-700 px-2 py-1 font-mono text-xs">{x}</span>)}
                {p.known_prefixes.length === 0 && <span className="text-muted">None yet.</span>}
              </div>
              <p className="mt-4 text-sm text-muted">First seen {fmtTime(p.first_seen_at)} · last checked {fmtTime(p.last_checked_at)} · {p.check_count} successful checks</p>
              <button className="mt-3 text-sm text-teal-300 hover:underline" onClick={() => navigate("compare", p.domain_name)}>Run a new comparison →</button>
            </Card>
          </div>
          <Card title="Observed addresses">
            <table className="w-full text-left text-sm">
              <thead className="text-muted"><tr><th className="pb-2">Type</th><th>Address</th><th>First seen</th><th>Last seen</th><th>Checks</th><th>Returned by</th></tr></thead>
              <tbody>
                {data.address_changes.map((r) => {
                  const known = p.known_ips.includes(r.value);
                  return (
                    <tr key={r.record_type + r.value} className="border-t border-ink-700">
                      <td className="py-2">{r.record_type}</td>
                      <td className={`font-mono ${known ? "text-slate-200" : "text-red-300"}`}>{r.value}{!known && <span className="ml-2 text-xs">(not in baseline)</span>}</td>
                      <td className="text-muted">{fmtTime(r.first_seen)}</td><td className="text-muted">{fmtTime(r.last_seen)}</td>
                      <td>{r.runs}</td><td className="text-xs text-muted">{r.resolvers.join(", ")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>
          <Card title="Previous alerts">
            {data.alerts.length === 0 ? <p className="text-muted">No alerts for this domain.</p> : (
              <ul className="space-y-2">
                {data.alerts.map((a) => (
                  <li key={a.alert_id} className="flex flex-wrap items-center gap-2 text-sm">
                    <SeverityBadge severity={a.severity} /><span className="font-mono text-teal-300">{a.rule_id}</span>
                    <span className="text-slate-200">{a.explanation}</span><span className="text-xs text-muted">{fmtTime(a.created_at)} · {a.status}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
