import { useEffect, useState } from "react";
import { Bar, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import type { Navigate } from "../App";
import { Card, DomainForm, Empty, ErrorBox, SeverityBadge, SimulatedTag, Spinner, StatCard, fmtTime } from "../components/ui";
import type { Overview, Scenario, Severity } from "../types";

const SEV_BAR: Record<Severity, string> = { High: "bg-red-500", Medium: "bg-amber-500", Low: "bg-blue-400", Info: "bg-slate-500" };

export default function OverviewPage({ navigate }: { navigate: Navigate }) {
  const [data, setData] = useState<Overview | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.overview().then(setData).catch((e) => setErr(e.message));
    api.scenarios().then((s) => setScenarios(s.items)).catch(() => undefined);
  }, []);

  const maxSev = data ? Math.max(1, ...Object.values(data.alerts_by_severity)) : 1;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl font-bold">Overview</h1>
        <div className="w-full max-w-xl"><DomainForm busy={false} onSubmit={(d) => navigate("compare", d)} /></div>
      </header>
      {err && <ErrorBox message={err} />}
      {!data && !err && <Spinner label="Loading…" />}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            <StatCard label="Total DNS checks" value={data.total_checks.toLocaleString()} tone="text-teal-400" />
            <StatCard label="Domains checked" value={data.domains_checked} tone="text-cyan-400" />
            <StatCard label="Alerts requiring investigation" value={data.open_alerts} tone="text-red-400" />
            <StatCard label="Resolver agreement" value={data.resolver_agreement_pct == null ? "—" : `${data.resolver_agreement_pct}%`} tone="text-green-400" />
          </div>
          <div className="grid gap-6 xl:grid-cols-3">
            <Card title="Recent DNS activity (last 14 days)" className="xl:col-span-2">
              <div className="h-64">
                <ResponsiveContainer>
                  <ComposedChart data={data.activity} margin={{ left: -20, right: 8 }}>
                    <CartesianGrid stroke="#2B4163" vertical={false} />
                    <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} stroke="#B6C3D4" fontSize={12} />
                    <YAxis allowDecimals={false} stroke="#B6C3D4" fontSize={12} />
                    <Tooltip contentStyle={{ background: "#0B1628", border: "1px solid #2B4163", borderRadius: 8 }} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Bar dataKey="alerts" name="Alerts raised" fill="#EF4444" barSize={10} radius={[3, 3, 0, 0]} />
                    <Line dataKey="checks" name="DNS checks" stroke="#14B8A6" strokeWidth={2.5} dot={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card title="Open alerts by severity">
              <div className="space-y-4">
                {(Object.keys(data.alerts_by_severity) as Severity[]).map((s) => (
                  <div key={s} className="flex items-center gap-3 text-sm">
                    <span className="w-16 text-slate-200">{s}</span>
                    <div className="h-3 flex-1 rounded bg-ink-700">
                      <div className={`h-3 rounded ${SEV_BAR[s]}`} style={{ width: `${(100 * data.alerts_by_severity[s]) / maxSev}%` }} />
                    </div>
                    <span className="w-6 text-right">{data.alerts_by_severity[s]}</span>
                  </div>
                ))}
              </div>
              <p className="mt-5 text-xs text-muted">Alerts ask for review — they do not confirm an attack.</p>
            </Card>
          </div>
          <Card title="Recent alerts" right={<button className="text-sm text-teal-300 hover:underline" onClick={() => navigate("alerts")}>View all</button>}>
            {data.recent_alerts.length === 0 ? <Empty>No alerts yet. Check a domain to start building its history.</Empty> : (
              <table className="w-full text-left text-sm">
                <thead className="text-muted"><tr><th className="pb-2">Severity</th><th>Domain</th><th>Rule</th><th>Summary</th><th>Time</th></tr></thead>
                <tbody>
                  {data.recent_alerts.map((a) => (
                    <tr key={a.alert_id} className="border-t border-ink-700">
                      <td className="py-2.5"><SeverityBadge severity={a.severity} /></td>
                      <td><button className="text-teal-300 hover:underline" onClick={() => navigate("history", a.domain_name)}>{a.domain_name}</button> {a.simulated && <SimulatedTag />}</td>
                      <td className="font-mono">{a.rule_id}</td>
                      <td className="max-w-md truncate text-slate-200" title={a.explanation}>{a.explanation}</td>
                      <td className="whitespace-nowrap text-muted">{fmtTime(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          {scenarios.length > 0 && (
            <Card title="Try a simulated scenario (answered by the mock resolver, labelled SIMULATED)">
              <div className="flex flex-wrap gap-2">
                {scenarios.map((s) => (
                  <button key={s.domain} title={s.description} onClick={() => navigate("compare", s.domain)}
                    className="rounded-full border border-ink-600 px-3 py-1 font-mono text-xs text-slate-200 hover:border-teal-400">
                    {s.domain}
                  </button>
                ))}
              </div>
              <p className="mt-3 text-xs text-muted">History-based rules stay silent during the warm-up checks, so run scenarios such as spoof, poison or hijack several times.</p>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
