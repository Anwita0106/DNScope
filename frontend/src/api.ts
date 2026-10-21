import type { AIExplanation, Alert, AlertStatus, CheckResult, History, Overview, Scenario } from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, { headers: { "Content-Type": "application/json" }, ...init });
  } catch {
    throw new Error("Cannot reach the DNScope backend. Is it running on port 8000?");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; resolver_mode: string; ai: { available: boolean; mode: string; model: string | null } }>("/api/health"),
  lookup: (domain: string, record_types?: string[]) =>
    request<CheckResult>("/api/lookup", { method: "POST", body: JSON.stringify({ domain, record_types }) }),
  compare: (domain: string, record_type: "A" | "AAAA" = "A") =>
    request<CheckResult>("/api/compare", { method: "POST", body: JSON.stringify({ domain, record_type }) }),
  alerts: (params: { severity?: string; status?: string; domain?: string } = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]);
    return request<{ items: Alert[]; count: number }>(`/api/alerts?${q}`);
  },
  setAlertStatus: (id: number, status: AlertStatus) =>
    request<Alert>(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  explain: (id: number, refresh = false) =>
    request<AIExplanation>(`/api/alerts/${id}/ai-explanation${refresh ? "?refresh=true" : ""}`, { method: "POST" }),
  history: (domain: string, days = 30) => request<History>(`/api/domains/${encodeURIComponent(domain)}/history?days=${days}`),
  overview: () => request<Overview>("/api/stats/overview"),
  scenarios: () => request<{ items: Scenario[]; warmup_checks: number }>("/api/scenarios"),
};
