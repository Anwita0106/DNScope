"""SQLite Repository - the only module that runs SQL. All queries are parameterised."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_profiles (
    domain_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name          TEXT NOT NULL UNIQUE,
    first_seen_at        TEXT NOT NULL,
    last_checked_at      TEXT,
    known_ips            TEXT NOT NULL DEFAULT '[]',   -- JSON list
    known_prefixes       TEXT NOT NULL DEFAULT '[]',   -- JSON list (/24 or /48)
    ttl_baseline         INTEGER,                      -- median of past max TTLs (A records)
    ttl_history          TEXT NOT NULL DEFAULT '[]',   -- JSON list of recent max TTLs
    check_count          INTEGER NOT NULL DEFAULT 0,   -- successful checks (drives warm-up)
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    dnssec_seen          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS resolver_checks (
    check_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id     INTEGER NOT NULL REFERENCES domain_profiles(domain_id) ON DELETE CASCADE,
    run_id        TEXT NOT NULL,
    resolver_name TEXT NOT NULL,
    resolver_ip   TEXT,
    record_type   TEXT NOT NULL,
    checked_at    TEXT NOT NULL,
    rcode         TEXT,
    status        TEXT NOT NULL,          -- ok | nxdomain | servfail | refused | timeout | error
    response_ms   REAL,
    ad_flag       INTEGER NOT NULL DEFAULT 0,
    tc_flag       INTEGER NOT NULL DEFAULT 0,
    used_tcp      INTEGER NOT NULL DEFAULT 0,
    cd_retry_answered INTEGER,
    simulated     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dns_observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id       INTEGER NOT NULL REFERENCES resolver_checks(check_id) ON DELETE CASCADE,
    domain_id      INTEGER NOT NULL REFERENCES domain_profiles(domain_id) ON DELETE CASCADE,
    record_type    TEXT NOT NULL,
    value          TEXT NOT NULL,
    ttl            INTEGER,
    observed_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id      INTEGER NOT NULL REFERENCES domain_profiles(domain_id) ON DELETE CASCADE,
    check_id       INTEGER REFERENCES resolver_checks(check_id) ON DELETE SET NULL,
    run_id         TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    severity       TEXT NOT NULL,         -- Info | Low | Medium | High
    explanation    TEXT NOT NULL,
    evidence_json  TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open',   -- open | reviewed | dismissed
    created_at     TEXT NOT NULL,
    simulated      INTEGER NOT NULL DEFAULT 0,
    ai_explanation TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_domain_time ON resolver_checks(domain_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_checks_run ON resolver_checks(run_id);
CREATE INDEX IF NOT EXISTS idx_obs_check ON dns_observations(check_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status, severity);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as c:
        c.executescript(SCHEMA)


# ----------------------------------------------------------------- profiles
def _profile(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in ("known_ips", "known_prefixes", "ttl_history"):
        d[k] = json.loads(d[k])
    d["dnssec_seen"] = bool(d["dnssec_seen"])
    return d


def get_or_create_profile(domain: str) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM domain_profiles WHERE domain_name = ?", (domain,)).fetchone()
        if row is None:
            c.execute("INSERT INTO domain_profiles (domain_name, first_seen_at) VALUES (?, ?)", (domain, now_iso()))
            row = c.execute("SELECT * FROM domain_profiles WHERE domain_name = ?", (domain,)).fetchone()
        return _profile(row)


def get_profile(domain: str) -> dict | None:
    with connect() as c:
        return _profile(c.execute("SELECT * FROM domain_profiles WHERE domain_name = ?", (domain,)).fetchone())


def save_profile(p: dict) -> None:
    with connect() as c:
        c.execute("""UPDATE domain_profiles SET last_checked_at=?, known_ips=?, known_prefixes=?, ttl_baseline=?,
                     ttl_history=?, check_count=?, consecutive_failures=?, dnssec_seen=? WHERE domain_id=?""",
                  (p["last_checked_at"], json.dumps(p["known_ips"]), json.dumps(p["known_prefixes"]),
                   p["ttl_baseline"], json.dumps(p["ttl_history"]), p["check_count"], p["consecutive_failures"],
                   int(p["dnssec_seen"]), p["domain_id"]))


# ----------------------------------------------------------------- checks & observations
def insert_check(domain_id: int, run_id: str, raw, checked_at: str) -> int:
    with connect() as c:
        cur = c.execute("""INSERT INTO resolver_checks (domain_id, run_id, resolver_name, resolver_ip, record_type,
                           checked_at, rcode, status, response_ms, ad_flag, tc_flag, used_tcp, cd_retry_answered, simulated)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (domain_id, run_id, raw.resolver, raw.resolver_ip, raw.record_type, checked_at, raw.rcode,
                         raw.status, raw.response_ms, int(raw.ad), int(raw.tc), int(raw.used_tcp),
                         None if raw.cd_retry_answered is None else int(raw.cd_retry_answered), int(raw.simulated)))
        check_id = cur.lastrowid
        for rr in raw.answer:
            for v in rr.values:
                c.execute("""INSERT INTO dns_observations (check_id, domain_id, record_type, value, ttl, observed_at)
                             VALUES (?,?,?,?,?,?)""", (check_id, domain_id, rr.rtype, v, rr.ttl, checked_at))
        return check_id


def observation_ids(check_ids: list[int]) -> dict[int, list[int]]:
    if not check_ids:
        return {}
    marks = ",".join("?" * len(check_ids))
    with connect() as c:
        rows = c.execute(f"SELECT check_id, observation_id FROM dns_observations WHERE check_id IN ({marks})", check_ids).fetchall()
    out: dict[int, list[int]] = {}
    for r in rows:
        out.setdefault(r["check_id"], []).append(r["observation_id"])
    return out


def recent_run_failures(domain_id: int, window: int) -> list[bool]:
    """For the last `window` runs (newest first): True if no resolver produced an A-record answer
    or NXDOMAIN (i.e. every resolver timed out, returned SERVFAIL/REFUSED or errored)."""
    with connect() as c:
        rows = c.execute("""
            SELECT run_id, MAX(checked_at) AS t,
                   SUM(CASE WHEN record_type='A' AND status IN ('ok','nxdomain') THEN 1 ELSE 0 END) AS good,
                   SUM(CASE WHEN record_type='A' THEN 1 ELSE 0 END) AS a_rows
            FROM resolver_checks WHERE domain_id = ? GROUP BY run_id ORDER BY t DESC LIMIT ?""",
                         (domain_id, window)).fetchall()
    return [r["good"] == 0 for r in rows if r["a_rows"] > 0]


# ----------------------------------------------------------------- alerts
def _alert(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d.pop("evidence_json"))
    d["simulated"] = bool(d["simulated"])
    return d


ALERT_SELECT = """SELECT a.*, p.domain_name FROM security_alerts a JOIN domain_profiles p ON p.domain_id = a.domain_id"""


def find_open_alert(domain_id: int, rule_id: str, fingerprint: str) -> dict | None:
    with connect() as c:
        rows = c.execute(ALERT_SELECT + " WHERE a.domain_id=? AND a.rule_id=? AND a.status='open' ORDER BY a.alert_id DESC",
                         (domain_id, rule_id)).fetchall()
    for r in rows:
        a = _alert(r)
        if a["evidence"].get("fingerprint") == fingerprint:
            return a
    return None


def insert_alert(domain_id: int, check_id: int | None, run_id: str, rule_id: str, severity: str,
                 explanation: str, evidence: dict, simulated: bool) -> dict:
    with connect() as c:
        cur = c.execute("""INSERT INTO security_alerts (domain_id, check_id, run_id, rule_id, severity, explanation,
                           evidence_json, created_at, simulated) VALUES (?,?,?,?,?,?,?,?,?)""",
                        (domain_id, check_id, run_id, rule_id, severity, explanation, json.dumps(evidence),
                         now_iso(), int(simulated)))
        row = c.execute(ALERT_SELECT + " WHERE a.alert_id = ?", (cur.lastrowid,)).fetchone()
        return _alert(row)


def list_alerts(severity: str | None = None, status: str | None = None, domain: str | None = None,
                limit: int = 100, offset: int = 0) -> list[dict]:
    q, args = ALERT_SELECT + " WHERE 1=1", []
    if severity:
        q += " AND a.severity = ?"; args.append(severity)
    if status:
        q += " AND a.status = ?"; args.append(status)
    if domain:
        q += " AND p.domain_name = ?"; args.append(domain)
    q += " ORDER BY a.alert_id DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    with connect() as c:
        return [_alert(r) for r in c.execute(q, args).fetchall()]


def get_alert(alert_id: int) -> dict | None:
    with connect() as c:
        row = c.execute(ALERT_SELECT + " WHERE a.alert_id = ?", (alert_id,)).fetchone()
    return _alert(row) if row else None


def update_alert_status(alert_id: int, status: str) -> dict | None:
    with connect() as c:
        c.execute("UPDATE security_alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
    return get_alert(alert_id)


def save_ai_explanation(alert_id: int, text: str) -> None:
    with connect() as c:
        c.execute("UPDATE security_alerts SET ai_explanation = ? WHERE alert_id = ?", (text, alert_id))


# ----------------------------------------------------------------- history & stats
def domain_history(domain: str, days: int = 30) -> dict | None:
    p = get_profile(domain)
    if not p:
        return None
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with connect() as c:
        ips = c.execute("""
            SELECT o.record_type, o.value, MIN(o.observed_at) AS first_seen, MAX(o.observed_at) AS last_seen,
                   COUNT(DISTINCT rc.run_id) AS runs, GROUP_CONCAT(DISTINCT rc.resolver_name) AS resolvers
            FROM dns_observations o JOIN resolver_checks rc ON rc.check_id = o.check_id
            WHERE o.domain_id = ? AND o.record_type IN ('A','AAAA') AND o.observed_at >= ?
            GROUP BY o.record_type, o.value ORDER BY first_seen""", (p["domain_id"], since)).fetchall()
        ttl = c.execute("""
            SELECT rc.run_id, MAX(rc.checked_at) AS t, MAX(o.ttl) AS max_ttl
            FROM resolver_checks rc JOIN dns_observations o ON o.check_id = rc.check_id
            WHERE rc.domain_id = ? AND o.record_type = 'A' AND rc.checked_at >= ?
            GROUP BY rc.run_id ORDER BY t""", (p["domain_id"], since)).fetchall()
        runs = c.execute("SELECT COUNT(DISTINCT run_id) FROM resolver_checks WHERE domain_id = ?", (p["domain_id"],)).fetchone()[0]
    return {
        "profile": p,
        "total_runs": runs,
        "address_changes": [dict(r) | {"resolvers": (r["resolvers"] or "").split(",")} for r in ips],
        "ttl_series": [{"time": r["t"], "max_ttl": r["max_ttl"]} for r in ttl],
        "alerts": list_alerts(domain=domain, limit=50),
    }


def overview(days: int = 14) -> dict:
    since_dt = datetime.now(timezone.utc) - timedelta(days=days - 1)
    since = since_dt.date().isoformat()
    with connect() as c:
        total_runs = c.execute("SELECT COUNT(DISTINCT run_id) FROM resolver_checks").fetchone()[0]
        domains = c.execute("SELECT COUNT(*) FROM domain_profiles WHERE check_count > 0 OR last_checked_at IS NOT NULL").fetchone()[0]
        open_alerts = c.execute("SELECT COUNT(*) FROM security_alerts WHERE status = 'open'").fetchone()[0]
        r2_runs = c.execute("SELECT COUNT(DISTINCT run_id) FROM security_alerts WHERE rule_id = 'R2'").fetchone()[0]
        by_sev = {r["severity"]: r["n"] for r in c.execute(
            "SELECT severity, COUNT(*) AS n FROM security_alerts WHERE status='open' GROUP BY severity")}
        runs_day = {r["d"]: r["n"] for r in c.execute(
            "SELECT substr(checked_at,1,10) AS d, COUNT(DISTINCT run_id) AS n FROM resolver_checks WHERE checked_at >= ? GROUP BY d", (since,))}
        alerts_day = {r["d"]: r["n"] for r in c.execute(
            "SELECT substr(created_at,1,10) AS d, COUNT(*) AS n FROM security_alerts WHERE created_at >= ? GROUP BY d", (since,))}
    series = []
    for i in range(days):
        d = (since_dt + timedelta(days=i)).date().isoformat()
        series.append({"date": d, "checks": runs_day.get(d, 0), "alerts": alerts_day.get(d, 0)})
    agreement = None if total_runs == 0 else round(100 * (1 - r2_runs / total_runs), 1)
    return {"total_checks": total_runs, "domains_checked": domains, "open_alerts": open_alerts,
            "resolver_agreement_pct": agreement,
            "alerts_by_severity": {s: by_sev.get(s, 0) for s in ("High", "Medium", "Low", "Info")},
            "activity": series, "recent_alerts": list_alerts(limit=8)}
