"""Orchestrates one DNScope check: query -> normalise -> compare -> rules -> alerts -> store."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from . import repository as repo
from .config import SIMULATED_ZONE, SUPPORTED_RECORD_TYPES, settings
from .normalizer import Answer, normalise
from .resolver_service import RawResponse, backend_for, scenario_for
from .rules import RULE_TITLES, evaluate, update_profile
from .validator import validate_domain


def _query_all(domain: str, record_types: list[str], run_number: int) -> list[RawResponse]:
    backend = backend_for(domain)
    jobs = [(r, rt) for r in settings.resolvers for rt in record_types]

    def one(job):
        resolver, rt = job
        raw = backend.query(resolver, domain, rt, run_number=run_number)
        # R5 support: a validating resolver's SERVFAIL is retried with Checking Disabled (CD = 1).
        if rt == "A" and resolver.validates_dnssec and raw.status == "servfail":
            retry = backend.query(resolver, domain, rt, cd=True, run_number=run_number)
            raw.cd_retry_answered = retry.status == "ok" and any(rr.rtype == "A" for rr in retry.answer)
        return raw

    with ThreadPoolExecutor(max_workers=min(16, len(jobs))) as pool:
        return list(pool.map(one, jobs))


def run_check(raw_domain: str, record_types: list[str] | None = None) -> dict:
    domain = validate_domain(raw_domain)
    rtypes = [t.upper() for t in (record_types or SUPPORTED_RECORD_TYPES) if t.upper() in SUPPORTED_RECORD_TYPES]
    if "A" not in rtypes:
        rtypes.insert(0, "A")   # A records drive comparison and rules
    simulated = domain.endswith("." + SIMULATED_ZONE) or settings.resolver_mode == "mock"

    profile = repo.get_or_create_profile(domain)
    run_id = uuid.uuid4().hex[:12]
    checked_at = repo.now_iso()
    raws = _query_all(domain, rtypes, profile["check_count"])

    check_ids: dict[tuple[str, str], int] = {}
    for raw in raws:
        check_ids[(raw.resolver, raw.record_type)] = repo.insert_check(profile["domain_id"], run_id, raw, checked_at)
    obs_ids = repo.observation_ids(list(check_ids.values()))

    answers = [normalise(r) for r in raws]
    by_type: dict[str, list[Answer]] = {}
    for a in answers:
        by_type.setdefault(a.record_type, []).append(a)

    failures = repo.recent_run_failures(profile["domain_id"], settings.fail_window)
    hits, comparisons = evaluate(profile, by_type, failures)

    alerts = []
    for h in hits:
        existing = repo.find_open_alert(profile["domain_id"], h.rule_id, h.fingerprint)
        if existing:
            alerts.append(existing | {"repeat": True})
            continue
        cid = check_ids.get((h.resolver, h.record_type)) if h.resolver else None
        evidence = h.evidence | {"fingerprint": h.fingerprint, "title": h.title, "possible_causes": h.possible_causes,
                                 "observation_ids": obs_ids.get(cid, []) if cid else [], "run_id": run_id}
        alerts.append(repo.insert_alert(profile["domain_id"], cid, run_id, h.rule_id, h.severity,
                                        h.explanation, evidence, simulated))

    new_profile = update_profile(profile, by_type, hits, checked_at)
    repo.save_profile(new_profile)

    return {
        "run_id": run_id, "domain": domain, "checked_at": checked_at, "simulated": simulated,
        "scenario": scenario_for(domain) if simulated else None,
        "warmup": {"checks_completed": new_profile["check_count"], "required": settings.warmup_checks,
                   "complete": new_profile["check_count"] >= settings.warmup_checks},
        "resolvers": [{"name": r.name, "ip": r.ip or "system", "validates_dnssec": r.validates_dnssec} for r in settings.resolvers],
        "results": [_answer_dict(a, raws) for a in answers],
        "comparisons": comparisons,
        "alerts": alerts,
        "rule_titles": RULE_TITLES,
    }


def _answer_dict(a: Answer, raws: list[RawResponse]) -> dict:
    raw = next(r for r in raws if r.resolver == a.resolver and r.record_type == a.record_type)
    return {"resolver": a.resolver, "resolver_ip": a.resolver_ip, "record_type": a.record_type, "status": a.status,
            "rcode": a.rcode, "values": a.values, "prefixes": a.prefixes, "ttl": a.max_ttl, "cname_chain": a.cname_chain,
            "flags": {"aa": raw.aa, "tc": raw.tc, "ra": raw.ra, "ad": raw.ad}, "used_tcp": a.used_tcp,
            "response_ms": a.response_ms, "cd_retry_answered": a.cd_retry_answered, "error": raw.error}
