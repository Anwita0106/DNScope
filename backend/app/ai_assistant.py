"""Optional AI assistant: explains an alert in plain language and suggests next checks.

Design rules (keep the detection itself transparent):
  * The AI never decides whether an alert is raised - rules R1-R6 do that.
  * Only the alert's DNS evidence (domain, addresses, TTLs, resolver names) is sent - no user data.
  * Without an ANTHROPIC_API_KEY (or if the call fails) a rule-based explanation is returned instead,
    so the project works fully offline.
"""
from __future__ import annotations

import json
import logging

from .config import settings

log = logging.getLogger("dnscope.ai")

SYSTEM_PROMPT = """You are a network-security teaching assistant inside DNScope, a DNS monitoring tool built by a \
Computer Networks student. You explain DNS alerts to a user with basic networking knowledge.

Rules:
- Explain in plain language what the evidence shows and why the rule fired. Define any acronym you use.
- Never say spoofing or an attack is confirmed. Treat the alert as a reason to investigate.
- Weigh the legitimate explanations (CDN / geo-DNS routing, caching and TTL countdown, planned migrations, \
filtering resolvers, ISP NXDOMAIN rewriting, DNSSEC key-rollover mistakes) against the suspicious one.
- Give 2-3 concrete next checks a student can run (for example `dig @8.8.8.8 example.com A +dnssec`, \
comparing again in a few minutes after the TTL expires, checking whether the address belongs to the expected \
network/organisation, checking the site's TLS certificate).
- If the evidence is labelled simulated, say it is a simulated test scenario.
- Maximum 170 words. Use short paragraphs or a short list. No headings."""

NEXT_STEPS = {
    "R1": ["Re-run the check in a few minutes and see whether the new address persists.",
           "Look up who owns the new address range (a whois / RDAP lookup) and compare with the old one.",
           "Open the site over HTTPS and confirm the certificate is valid for this domain."],
    "R2": ["Query the outlier resolver directly again, e.g. `dig @9.9.9.9 <domain> A`, and compare with `dig @8.8.8.8`.",
           "Wait for the TTL to expire and check again - stale caches correct themselves.",
           "If the outlier is your own (system) resolver, try another network (e.g. mobile data) to rule out local tampering."],
    "R3": ["Check again later: a planned change often explains a temporary TTL drop.",
           "Compare with the TTL returned by the domain's authoritative name server (`dig +norecurse @<ns> <domain>`)."],
    "R4": ["Check whether the site is reachable from another network or an online status checker.",
           "Look up the domain's registration (RDAP/whois) to see if it expired."],
    "R5": ["Run `dig <domain> A +dnssec` against a validating resolver and look for SERVFAIL.",
           "Use a DNSSEC analysis tool to see which signature or key is failing.",
           "Do not trust the unvalidated answer until the problem is understood."],
    "R6": ["Check whether you are on a network that uses split-horizon DNS (e.g. a company or campus network).",
           "Compare with a public resolver; a public site should not resolve to a private address."],
}


def is_available() -> bool:
    if not settings.anthropic_api_key:
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def status() -> dict:
    return {"available": is_available(), "model": settings.ai_model if is_available() else None,
            "mode": "claude" if is_available() else "rule-based fallback"}


def _evidence_payload(alert: dict) -> dict:
    ev = {k: v for k, v in alert["evidence"].items() if k not in ("fingerprint", "observation_ids", "run_id")}
    return {"domain": alert["domain_name"], "rule": alert["rule_id"], "title": ev.pop("title", alert["rule_id"]),
            "severity": alert["severity"], "explanation": alert["explanation"], "simulated": alert["simulated"],
            "evidence": ev}


def fallback_explanation(alert: dict) -> str:
    ev = alert["evidence"]
    causes = ev.get("possible_causes", [])
    parts = [alert["explanation"],
             "This is a signal to investigate, not proof of spoofing."]
    if causes:
        parts.append("Harmless explanations to rule out first: " + "; ".join(causes) + ".")
    steps = NEXT_STEPS.get(alert["rule_id"], [])
    if steps:
        parts.append("Suggested next checks: " + " ".join(f"({i}) {s}" for i, s in enumerate(steps, 1)))
    if alert["simulated"]:
        parts.append("Note: this alert comes from a simulated test scenario.")
    return "\n\n".join(parts)


def explain_alert(alert: dict) -> dict:
    """Return {'text', 'source', 'model'}; never raises."""
    if not is_available():
        return {"text": fallback_explanation(alert), "source": "rule-based", "model": None}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=30.0)
        msg = client.messages.create(
            model=settings.ai_model,
            max_tokens=settings.ai_max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content":
                       "Explain this DNScope alert:\n```json\n" + json.dumps(_evidence_payload(alert), indent=2) + "\n```"}],
        )
        text = "".join(block.text for block in msg.content if getattr(block, "type", "") == "text").strip()
        if not text:
            raise ValueError("empty response")
        return {"text": text, "source": "claude", "model": settings.ai_model}
    except Exception as exc:  # noqa: BLE001 - network, auth, quota... fall back gracefully
        log.warning("AI explanation failed, using fallback: %s", exc)
        return {"text": fallback_explanation(alert), "source": "rule-based", "model": None,
                "note": "AI service unavailable; showing the rule-based explanation."}
