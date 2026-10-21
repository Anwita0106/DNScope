export type Severity = "Info" | "Low" | "Medium" | "High";
export type AlertStatus = "open" | "reviewed" | "dismissed";

export interface ResolverResult {
  resolver: string;
  resolver_ip: string;
  record_type: string;
  status: string; // ok | nxdomain | servfail | refused | timeout | error
  rcode: string;
  values: string[];
  prefixes: string[];
  ttl: number | null;
  cname_chain: string[];
  flags: { aa: boolean; tc: boolean; ra: boolean; ad: boolean };
  used_tcp: boolean;
  response_ms: number;
  cd_retry_answered: boolean | null;
  error: string;
}

export interface Comparison {
  answered: string[];
  outliers: string[];
  status: "agree" | "outlier" | "all_different" | "differ" | "insufficient";
  note: string;
}

export interface Alert {
  alert_id: number;
  domain_id: number;
  domain_name: string;
  check_id: number | null;
  run_id: string;
  rule_id: string;
  severity: Severity;
  explanation: string;
  evidence: Record<string, unknown> & { title?: string; possible_causes?: string[]; observation_ids?: number[] };
  status: AlertStatus;
  created_at: string;
  simulated: boolean;
  ai_explanation: string | null;
  repeat?: boolean;
}

export interface CheckResult {
  run_id: string;
  domain: string;
  checked_at: string;
  simulated: boolean;
  scenario: string | null;
  warmup: { checks_completed: number; required: number; complete: boolean };
  results: ResolverResult[];
  comparisons: Record<string, Comparison>;
  alerts: Alert[];
  records?: Record<string, ResolverResult[]>;
  rows?: ResolverResult[];
  comparison?: Comparison;
  record_type?: string;
}

export interface Overview {
  total_checks: number;
  domains_checked: number;
  open_alerts: number;
  resolver_agreement_pct: number | null;
  alerts_by_severity: Record<Severity, number>;
  activity: { date: string; checks: number; alerts: number }[];
  recent_alerts: Alert[];
}

export interface History {
  profile: {
    domain_name: string;
    first_seen_at: string;
    last_checked_at: string | null;
    known_ips: string[];
    known_prefixes: string[];
    ttl_baseline: number | null;
    check_count: number;
    consecutive_failures: number;
    dnssec_seen: boolean;
  };
  total_runs: number;
  address_changes: { record_type: string; value: string; first_seen: string; last_seen: string; runs: number; resolvers: string[] }[];
  ttl_series: { time: string; max_ttl: number }[];
  alerts: Alert[];
}

export interface AIExplanation {
  alert_id: number;
  text: string;
  source: "claude" | "rule-based" | "cached";
  model: string | null;
  note?: string;
}

export interface Scenario { domain: string; description: string }

export type Page = "overview" | "lookup" | "compare" | "alerts" | "history";
