"""Comparison Engine + Rule-Based Detection Engine (rules R1-R6).

Every rule returns plain data: what was compared, why it is unusual, and which harmless
reasons could also explain it. An alert means "investigate", never "spoofing confirmed".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

from .config import settings
from .normalizer import Answer, is_internal, prefix_of

SEVERITIES = ["Info", "Low", "Medium", "High"]


def bump(sev: str, levels: int = 1) -> str:
    return SEVERITIES[min(SEVERITIES.index(sev) + levels, len(SEVERITIES) - 1)]


@dataclass
class RuleHit:
    rule_id: str
    title: str
    severity: str
    explanation: str
    evidence: dict
    possible_causes: list[str]
    resolver: str | None = None          # resolver whose check row the alert points at
    record_type: str = "A"
    fingerprint: str = ""
    meta: dict = field(default_factory=dict)


RULE_TITLES = {
    "R1": "Unexpected address change",
    "R2": "Resolver disagreement",
    "R3": "Unusual TTL",
    "R4": "Repeated resolution failures",
    "R5": "DNSSEC validation failure",
    "R6": "Private address in public answer",
}


# --------------------------------------------------------------------------- comparison
def _shares(a: Answer, b: Answer) -> bool:
    return bool(set(a.values) & set(b.values) or set(a.prefixes) & set(b.prefixes))


def compare(answers: list[Answer]) -> dict:
    """Agreement analysis for one record type (A or AAAA) across resolvers."""
    answered = [a for a in answers if a.answered]
    result = {"answered": [a.resolver for a in answered], "outliers": [], "status": "insufficient",
              "note": "Fewer than three resolvers returned addresses, so no majority can be formed."}
    if len(answered) < 2:
        return result
    links = {a.resolver: [b.resolver for b in answered if b is not a and _shares(a, b)] for a in answered}
    if all(links[a.resolver] for a in answered) and len(answered) >= 2:
        result.update(status="agree", note="All answering resolvers returned addresses in common networks.")
        return result
    if len(answered) < 3:
        result.update(status="differ", note="Two resolvers returned unrelated addresses; a third is needed to judge.")
        return result
    isolated = [a.resolver for a in answered if not links[a.resolver]]
    connected = [a.resolver for a in answered if links[a.resolver]]
    if connected and len(isolated) < len(connected):
        result.update(status="outlier", outliers=isolated,
                      note="Most resolvers agree; the outlier returned addresses from an unrelated network.")
    else:
        result.update(status="all_different",
                      note="Every resolver returned a different network - typical of CDN or geo-DNS steering. No majority, so no alert.")
    return result


# --------------------------------------------------------------------------- rules
COMMON_CAUSES = {
    "R1": ["The site moved to a new hosting provider or data centre", "A CDN added new edge servers",
           "Round-robin or failover addresses not seen before"],
    "R2": ["CDN or geo-DNS steering gives different resolvers different servers",
           "A resolver still holds an older cached answer after a legitimate change",
           "A filtering resolver (e.g. Quad9 blocks known-malicious domains) altered the answer on purpose"],
    "R3": ["The operator lowered the TTL before a planned change", "The operator raised the TTL after a change settled"],
    "R4": ["A temporary outage of the domain's name servers", "The domain expired or was deleted",
           "A local network or firewall problem blocking DNS"],
    "R5": ["The zone operator made a mistake during a DNSSEC key rollover", "Expired DNSSEC signatures"],
    "R6": ["Split-horizon DNS: some organisations publish internal addresses on purpose",
           "Misconfigured DNS record"],
}


def evaluate(profile: dict, by_type: dict[str, list[Answer]], run_failures: list[bool]) -> tuple[list[RuleHit], dict]:
    """Apply R1-R6. Returns (hits, comparisons per record type)."""
    hits: list[RuleHit] = []
    warmed_up = profile["check_count"] >= settings.warmup_checks and bool(profile["known_ips"])
    known_ips, known_prefixes = set(profile["known_ips"]), set(profile["known_prefixes"])
    comparisons = {rt: compare(by_type.get(rt, [])) for rt in ("A", "AAAA") if rt in by_type}
    a_answers = by_type.get("A", [])

    # ---- R6: private / loopback / link-local address in a public answer
    for rt in ("A", "AAAA"):
        for_rt = by_type.get(rt, [])
        internal = {}
        for a in for_rt:
            for ip in a.values:
                if is_internal(ip):
                    internal.setdefault(ip, []).append(a.resolver)
        for ip, resolvers in internal.items():
            others = [a.resolver for a in for_rt if a.answered and a.resolver not in resolvers]
            sev = "High" if len(resolvers) == 1 and others else "Medium"
            hits.append(RuleHit("R6", RULE_TITLES["R6"], sev,
                                f"{', '.join(resolvers)} returned {ip}, a private/internal address that is not reachable on the Internet.",
                                {"address": ip, "record_type": rt, "returned_by": resolvers, "other_resolvers": others},
                                COMMON_CAUSES["R6"], resolver=resolvers[0], record_type=rt, fingerprint=f"{rt}:{ip}"))

    # ---- R2: resolver disagreement (outlier against a majority)
    r2_outliers: dict[str, list[str]] = {}
    for rt, cmp_ in comparisons.items():
        if cmp_["status"] != "outlier":
            continue
        answers = {a.resolver: a for a in by_type[rt]}
        majority = sorted({ip for r in cmp_["answered"] if r not in cmp_["outliers"] for ip in answers[r].values})
        for r in cmp_["outliers"]:
            out = answers[r]
            r2_outliers[r] = out.values
            hits.append(RuleHit(
                "R2", RULE_TITLES["R2"], "Medium",
                f"{r} returned {', '.join(out.values)}, which shares no address or network with the other resolvers "
                f"({', '.join(majority)}).",
                {"record_type": rt, "outlier": r, "outlier_values": out.values, "outlier_ttl": out.max_ttl,
                 "majority_values": majority,
                 "per_resolver": {a.resolver: {"values": a.values, "ttl": a.max_ttl, "status": a.status} for a in by_type[rt]}},
                COMMON_CAUSES["R2"], resolver=r, record_type=rt, fingerprint=f"{rt}:{r}:{','.join(out.values)}",
                meta={"system_outlier": r == "System resolver"}))
    # NXDOMAIN rewriting: system resolver answers while public resolvers say the name does not exist
    sys_a = next((a for a in a_answers if a.resolver == "System resolver"), None)
    nx_public = [a.resolver for a in a_answers if a.resolver != "System resolver" and a.status == "nxdomain"]
    if sys_a and sys_a.answered and len(nx_public) >= 2:
        hits.append(RuleHit("R2", RULE_TITLES["R2"], "Info",
                            f"The system resolver returned {', '.join(sys_a.values)} but {', '.join(nx_public)} say the name does not exist (NXDOMAIN).",
                            {"record_type": "A", "outlier": "System resolver", "outlier_values": sys_a.values, "nxdomain_from": nx_public},
                            ["Many ISPs redirect non-existent names to a search or advertising page (NXDOMAIN rewriting)"],
                            resolver="System resolver", fingerprint=f"nx:{','.join(sys_a.values)}"))

    # ---- R1: address never seen before and outside known networks (after warm-up)
    if warmed_up:
        for rt in ("A", "AAAA"):
            new: dict[str, list[str]] = {}
            for a in by_type.get(rt, []):
                for ip in a.values:
                    if ip not in known_ips and prefix_of(ip) not in known_prefixes and not is_internal(ip):
                        new.setdefault(ip, []).append(a.resolver)
            if new:
                sample = sorted(known_prefixes)[:4]
                returned_by = sorted({r for rs in new.values() for r in rs})
                hits.append(RuleHit(
                    "R1", RULE_TITLES["R1"], "Low",
                    f"New address(es) {', '.join(sorted(new))} have never been seen for this domain and are outside its usual "
                    f"networks ({', '.join(sample)}{'…' if len(known_prefixes) > 4 else ''}).",
                    {"record_type": rt, "new_addresses": new, "known_prefixes": sorted(known_prefixes),
                     "checks_in_baseline": profile["check_count"]},
                    COMMON_CAUSES["R1"], resolver=returned_by[0], record_type=rt,
                    fingerprint=f"{rt}:{','.join(sorted(new))}", meta={"resolvers": returned_by}))

    # ---- R3: unusual TTL compared with the domain's baseline (after warm-up)
    a_ttls = [a.max_ttl for a in a_answers if a.answered and a.max_ttl is not None]
    if warmed_up and profile["ttl_baseline"] and a_ttls:
        run_max, base = max(a_ttls), profile["ttl_baseline"]
        if run_max < settings.ttl_low_ratio * base or run_max > settings.ttl_high_ratio * base:
            direction = "below" if run_max < base else "above"
            hits.append(RuleHit("R3", RULE_TITLES["R3"], "Info",
                                f"The highest TTL seen in this check is {run_max} s, far {direction} this domain's usual {base} s.",
                                {"max_ttl": run_max, "baseline_ttl": base, "low_ratio": settings.ttl_low_ratio,
                                 "high_ratio": settings.ttl_high_ratio},
                                COMMON_CAUSES["R3"], fingerprint=f"ttl:{run_max}"))

    # ---- R4: repeated failures / unexpected NXDOMAIN
    current_failed = bool(run_failures) and run_failures[0]
    if current_failed:
        n_fail = sum(run_failures)
        if n_fail >= settings.fail_count:
            hits.append(RuleHit("R4", RULE_TITLES["R4"], "Low",
                                f"The domain failed to resolve at every resolver in {n_fail} of the last {len(run_failures)} checks.",
                                {"failed_runs": n_fail, "window": len(run_failures),
                                 "statuses": {a.resolver: a.status for a in a_answers}},
                                COMMON_CAUSES["R4"], fingerprint=f"fail:{n_fail}/{len(run_failures)}"))
    nx = [a.resolver for a in a_answers if a.status == "nxdomain"]
    if known_ips and nx and len(nx) > len(a_answers) / 2 and not (sys_a and sys_a.answered and len(nx_public) >= 2):
        hits.append(RuleHit("R4", RULE_TITLES["R4"], "Medium",
                            f"{', '.join(nx)} now say this domain does not exist (NXDOMAIN), although it resolved before.",
                            {"nxdomain_from": nx, "previously_known": sorted(known_ips)[:6]},
                            COMMON_CAUSES["R4"], fingerprint="nxdomain"))

    # ---- R5: DNSSEC validation failure
    validating = {r.name for r in settings.resolvers if r.validates_dnssec}
    bogus = [a.resolver for a in a_answers if a.resolver in validating and a.status == "servfail" and a.cd_retry_answered]
    if bogus:
        hits.append(RuleHit("R5", RULE_TITLES["R5"], "High",
                            f"{', '.join(bogus)} rejected the answer (SERVFAIL) but returned data when validation was "
                            "switched off (CD bit): the DNSSEC signatures could not be verified.",
                            {"servfail_with_cd_answer": bogus}, COMMON_CAUSES["R5"], resolver=bogus[0], fingerprint="bogus"))
    elif profile["dnssec_seen"]:
        ok_valid = [a for a in a_answers if a.resolver in validating and a.answered]
        if ok_valid and not any(a.ad for a in ok_valid):
            hits.append(RuleHit("R5", RULE_TITLES["R5"], "Medium",
                                "This domain was previously DNSSEC-authenticated (AD flag set), but no validating resolver set the AD flag now.",
                                {"resolvers_without_ad": [a.resolver for a in ok_valid]},
                                ["The operator removed or is rolling over DNSSEC keys"], fingerprint="lost-ad"))

    _combine_severities(hits)
    return hits, comparisons


def _combine_severities(hits: list[RuleHit]) -> None:
    """R1 Low -> Medium with R2; R2 Medium -> High if the outlier is the system resolver and R1 also fires;
    R3 raises R1 and R2 by one level."""
    ids = {h.rule_id for h in hits}
    r1 = [h for h in hits if h.rule_id == "R1"]
    r2 = [h for h in hits if h.rule_id == "R2" and h.severity != "Info"]
    for h in r1:
        if r2:
            h.severity = "Medium"
    for h in r2:
        if h.meta.get("system_outlier") and any(set(h.evidence["outlier_values"]) & set(x.evidence["new_addresses"]) for x in r1):
            h.severity = "High"
    if "R3" in ids:
        for h in r1 + r2:
            h.severity = bump(h.severity)


def update_profile(profile: dict, by_type: dict[str, list[Answer]], hits: list[RuleHit], checked_at: str) -> dict:
    """Learn from this run. Addresses flagged as outliers (R2) or internal (R6) are NOT added to the baseline."""
    p = dict(profile)
    a_answers = by_type.get("A", [])
    answered = [a for a in a_answers if a.status in ("ok",) and a.values]
    excluded = {(h.evidence.get("outlier"), v) for h in hits if h.rule_id == "R2" for v in h.evidence.get("outlier_values", [])}
    known_ips, known_prefixes = set(p["known_ips"]), set(p["known_prefixes"])
    for rt in ("A", "AAAA"):
        for a in by_type.get(rt, []):
            for ip in a.values:
                if (a.resolver, ip) in excluded or is_internal(ip):
                    continue
                known_ips.add(ip)
                known_prefixes.add(prefix_of(ip))
    p["known_ips"], p["known_prefixes"] = sorted(known_ips), sorted(known_prefixes)
    if answered or any(a.status == "nxdomain" for a in a_answers):
        p["check_count"] += 1
        p["consecutive_failures"] = 0
    else:
        p["consecutive_failures"] += 1
    ttls = [a.max_ttl for a in answered if a.max_ttl is not None and a.resolver not in {h.evidence.get("outlier") for h in hits}]
    if ttls:
        p["ttl_history"] = (p["ttl_history"] + [max(ttls)])[-settings.ttl_history_size:]
        p["ttl_baseline"] = int(median(p["ttl_history"]))
    validating = {r.name for r in settings.resolvers if r.validates_dnssec}
    if any(a.ad for a in answered if a.resolver in validating):
        p["dnssec_seen"] = True
    p["last_checked_at"] = checked_at
    return p
