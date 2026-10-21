import { useState, type ReactNode } from "react";
import { api } from "../api";
import type { AIExplanation, Alert, Severity } from "../types";

export const SEV_STYLE: Record<Severity, string> = {
  High: "bg-red-500 text-ink-900",
  Medium: "bg-amber-500 text-ink-900",
  Low: "bg-blue-400 text-ink-900",
  Info: "bg-slate-500 text-white",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block rounded-md px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEV_STYLE[severity]}`}>
      {severity}
    </span>
  );
}

export function Card({ title, right, children, className = "" }: { title?: string; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl bg-ink-800 p-5 ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title && <h2 className="text-sm font-semibold text-muted">{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatCard({ label, value, tone }: { label: string; value: ReactNode; tone: string }) {
  return (
    <div className="rounded-xl bg-ink-800 p-5">
      <div className="text-sm text-muted">{label}</div>
      <div className={`mt-2 text-3xl font-bold ${tone}`}>{value}</div>
    </div>
  );
}

export function DomainForm({ onSubmit, busy, initial = "", button = "Check Domain", extra }: {
  onSubmit: (domain: string) => void; busy: boolean; initial?: string; button?: string; extra?: ReactNode;
}) {
  const [value, setValue] = useState(initial);
  return (
    <form
      className="flex flex-wrap items-center gap-3"
      onSubmit={(e) => { e.preventDefault(); if (value.trim()) onSubmit(value.trim()); }}
    >
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Enter a domain, e.g. example.com or spoof.dnscope.test"
        aria-label="Domain name"
        className="min-w-[18rem] flex-1 rounded-lg border border-ink-600 bg-ink-900 px-4 py-2.5 text-white placeholder:text-slate-500 focus:border-teal-400 focus:outline-none"
      />
      {extra}
      <button
        type="submit"
        disabled={busy}
        className="rounded-lg bg-teal-500 px-5 py-2.5 font-semibold text-ink-900 hover:bg-teal-400 disabled:opacity-60"
      >
        {busy ? "Checking…" : button}
      </button>
    </form>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return <div role="alert" className="rounded-lg border border-red-500/60 bg-red-500/10 px-4 py-3 text-red-200">{message}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-ink-600 px-6 py-10 text-center text-muted">{children}</div>;
}

export function Spinner({ label = "Querying resolvers…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-muted">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-teal-400 border-t-transparent" />
      {label}
    </div>
  );
}

export function SimulatedTag() {
  return <span className="rounded bg-purple-500/20 px-2 py-0.5 text-xs font-semibold text-purple-300">SIMULATED</span>;
}

const HIDE = new Set(["title", "possible_causes", "fingerprint", "observation_ids", "run_id", "per_resolver"]);

export function AlertDetail({ alert, onStatus }: { alert: Alert; onStatus?: (a: Alert) => void }) {
  const ev = alert.evidence;
  const causes = (ev.possible_causes ?? []) as string[];
  const fields = Object.entries(ev).filter(([k]) => !HIDE.has(k));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} />
        <span className="font-mono text-sm text-teal-300">{alert.rule_id}</span>
        <span className="font-semibold text-white">{ev.title as string}</span>
        {alert.simulated && <SimulatedTag />}
      </div>
      <p className="text-white">{alert.explanation}</p>
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Evidence</h3>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          {fields.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k.replace(/_/g, " ")}</dt>
              <dd className="break-all font-mono text-slate-200">{typeof v === "string" ? v : JSON.stringify(v)}</dd>
            </div>
          ))}
        </dl>
      </div>
      {causes.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Possible legitimate causes</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-200">{causes.map((c) => <li key={c}>{c}</li>)}</ul>
        </div>
      )}
      <AIExplain alert={alert} />
      {onStatus && (
        <div className="flex gap-2 pt-1">
          {(["reviewed", "dismissed", "open"] as const).filter((s) => s !== alert.status).map((s) => (
            <button key={s} onClick={async () => onStatus(await api.setAlertStatus(alert.alert_id, s))}
              className="rounded-lg border border-ink-600 px-3 py-1.5 text-sm text-slate-200 hover:border-teal-400">
              Mark {s}
            </button>
          ))}
        </div>
      )}
      <p className="text-xs text-muted">An alert means “investigate”, not “spoofing confirmed”.</p>
    </div>
  );
}

export function AIExplain({ alert }: { alert: Alert }) {
  const [out, setOut] = useState<AIExplanation | null>(
    alert.ai_explanation ? { alert_id: alert.alert_id, text: alert.ai_explanation, source: "cached", model: null } : null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const ask = async (refresh = false) => {
    setBusy(true); setErr("");
    try { setOut(await api.explain(alert.alert_id, refresh)); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="rounded-lg border border-teal-500/40 bg-teal-500/5 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-teal-300">AI explanation</h3>
        <button onClick={() => ask(!!out)} disabled={busy}
          className="rounded-md bg-teal-500/90 px-3 py-1 text-sm font-semibold text-ink-900 hover:bg-teal-400 disabled:opacity-60">
          {busy ? "Thinking…" : out ? "Regenerate" : "Explain this alert"}
        </button>
      </div>
      {err && <p className="mt-2 text-sm text-red-300">{err}</p>}
      {out && (
        <>
          <p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-slate-100">{out.text}</p>
          <p className="mt-2 text-xs text-muted">
            {out.source === "rule-based"
              ? "Rule-based explanation (no AI key configured). " + (out.note ?? "")
              : out.source === "cached" ? "Saved AI explanation." : `Generated by ${out.model}. AI text can be wrong — check the evidence.`}
          </p>
        </>
      )}
      {!out && !err && <p className="mt-2 text-xs text-muted">Get a plain-language summary and suggested next checks. Only the alert's DNS evidence is sent.</p>}
    </div>
  );
}

export function fmtTime(iso: string | null | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export const STATUS_STYLE: Record<string, string> = {
  ok: "text-green-400", nxdomain: "text-amber-400", servfail: "text-red-400", refused: "text-red-400",
  timeout: "text-red-400", error: "text-red-400",
};
