"""End-to-end detection tests using the labelled mock resolver (no real network needed)."""
from app.config import settings
from app.service import run_check


def run_n(domain, n):
    return [run_check(domain) for _ in range(n)]


def rules(result):
    return {(a["rule_id"], a["severity"]) for a in result["alerts"]}


def test_normal_no_alerts():
    for r in run_n("normal.dnscope.test", settings.warmup_checks + 2):
        assert r["alerts"] == []
        assert r["simulated"]


def test_cdn_same_network_no_alert():
    for r in run_n("cdn.dnscope.test", settings.warmup_checks + 2):
        assert r["alerts"] == []


def test_geo_all_different_no_alert():
    r = run_check("geo.dnscope.test")
    assert r["comparisons"]["A"]["status"] == "all_different"
    assert r["alerts"] == []


def test_migration_within_network_no_alert():
    results = run_n("migrate.dnscope.test", settings.warmup_checks + 2)
    assert all(r["alerts"] == [] for r in results)


def test_spoofed_system_resolver_is_high():
    results = run_n("spoof.dnscope.test", settings.warmup_checks + 1)
    assert all(r["alerts"] == [] for r in results[:-1])          # warm-up is quiet
    hits = rules(results[-1])
    assert ("R2", "High") in hits and ("R1", "Medium") in hits


def test_poisoned_public_resolver_is_medium():
    r = run_n("poison.dnscope.test", settings.warmup_checks + 1)[-1]
    assert ("R2", "Medium") in rules(r) and ("R1", "Medium") in rules(r)


def test_hijack_all_agree_r1_plus_r3():
    r = run_n("hijack.dnscope.test", settings.warmup_checks + 1)[-1]
    got = rules(r)
    assert ("R1", "Medium") in got and ("R3", "Info") in got
    assert not any(rule == "R2" for rule, _ in got)


def test_private_address_r6_high():
    r = run_check("private.dnscope.test")
    assert ("R6", "High") in rules(r)


def test_dnssec_bogus_r5_high():
    r = run_check("dnssec-bad.dnscope.test")
    assert ("R5", "High") in rules(r)


def test_dnssec_ok_no_alert_and_profile_learns():
    r = run_check("dnssec-ok.dnscope.test")
    assert r["alerts"] == []
    assert any(x["flags"]["ad"] for x in r["results"] if x["record_type"] == "A")


def test_repeated_failures_r4_after_threshold():
    results = run_n("fail.dnscope.test", settings.fail_count)
    assert all(not any(a["rule_id"] == "R4" for a in r["alerts"]) for r in results[:-1])
    assert any(a["rule_id"] == "R4" for a in results[-1]["alerts"])


def test_nxdomain_rewriting_info():
    r = run_check("nxredirect.dnscope.test")
    assert ("R2", "Info") in rules(r)


def test_truncated_reply_uses_tcp():
    r = run_check("truncated.dnscope.test", ["A", "TXT"])
    txt = [x for x in r["results"] if x["record_type"] == "TXT"]
    assert all(x["used_tcp"] for x in txt)


def test_duplicate_alert_not_repeated():
    run_n("private.dnscope.test", 1)
    second = run_check("private.dnscope.test")
    assert all(a.get("repeat") for a in second["alerts"])
