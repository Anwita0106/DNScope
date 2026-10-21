import { useEffect, useState } from "react";
import { api } from "../api";
import { AlertDetail, Card, Empty, ErrorBox, SeverityBadge, SimulatedTag, Spinner, fmtTime } from "../components/ui";
import type { Alert } from "../types";

export default function AlertsPage({ initialDomain }: { initialDomain: string }) {
  const [items, setItems] = useState<Alert[] | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [domain, setDomain] = useState(initialDomain);
  const [err, setErr] = useState("");

  const load = () => {
    setErr("");
    api.alerts({ severity, status, domain }).then((r) => {
      setItems(r.items);
      setSelected((cur) => r.items.find((a) => a.alert_id === cur?.alert_id) ?? r.items[0] ?? null);
    }).catch((e) => setErr(e.message));
  };
  useEffect(load, [severity, status, domain]); // eslint-disable-line react-hooks/exhaustive-deps

  const select = "rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-sm";
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Security Alerts</h1>
      <div className="flex flex-wrap gap-3">
        <select className={select} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>{["High", "Medium", "Low", "Info"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className={select} value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">Any status</option><option value="open">Open</option><option value="reviewed">Reviewed</option><option value="dismissed">Dismissed</option>
        </select>
        <input className={select + " w-64"} placeholder="Filter by domain" value={domain} onChange={(e) => setDomain(e.target.value.trim())} />
      </div>
      {err && <ErrorBox message={err} />}
      {!items && !err && <Spinner label="Loading alerts…" />}
      {items && items.length === 0 && <Empty>No alerts match these filters.</Empty>}
      {items && items.length > 0 && (
        <div className="grid gap-6 xl:grid-cols-5">
          <Card className="xl:col-span-2">
            <ul className="divide-y divide-ink-700">
              {items.map((a) => (
                <li key={a.alert_id}>
                  <button onClick={() => setSelected(a)}
                    className={`w-full rounded-lg px-3 py-3 text-left ${selected?.alert_id === a.alert_id ? "bg-ink-700" : "hover:bg-ink-700/50"}`}>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={a.severity} /><span className="font-mono text-sm text-teal-300">{a.rule_id}</span>
                      <span className="truncate text-sm">{a.domain_name}</span>{a.simulated && <SimulatedTag />}
                    </div>
                    <div className="mt-1 flex justify-between gap-3 text-xs text-muted">
                      <span className="truncate">{a.evidence.title as string}</span><span className="whitespace-nowrap">{fmtTime(a.created_at)} · {a.status}</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          <Card className="xl:col-span-3" title="Investigation details">
            {selected ? <AlertDetail key={selected.alert_id} alert={selected} onStatus={() => load()} /> : <Empty>Select an alert.</Empty>}
          </Card>
        </div>
      )}
    </div>
  );
}
