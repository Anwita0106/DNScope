"""DNS Resolver Service.

Sends one DNS query per (resolver, record type) and records the protocol-level details:
RCODE, header flags (AA, TC, RA, AD), the answer RRsets with TTLs, round-trip time,
and whether the query fell back to TCP because the UDP reply was truncated (TC = 1).

Two backends implement the same interface:
  * LiveBackend  - real queries with dnspython (EDNS(0) with the DO bit set, RD = 1)
  * MockBackend  - scripted responses for testing and demos; every result is labelled simulated
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .config import ResolverConfig, SIMULATED_ZONE, settings


@dataclass
class RRset:
    name: str
    rtype: str
    ttl: int
    values: list[str]


@dataclass
class RawResponse:
    resolver: str
    resolver_ip: str
    record_type: str
    status: str                 # ok | nxdomain | servfail | refused | timeout | error
    rcode: str = ""
    aa: bool = False
    tc: bool = False
    ra: bool = False
    ad: bool = False
    used_tcp: bool = False
    response_ms: float = 0.0
    answer: list[RRset] = field(default_factory=list)
    cd_retry_answered: bool | None = None   # set for SERVFAIL from a validating resolver (rule R5)
    error: str = ""
    simulated: bool = False


_RCODE_STATUS = {"NOERROR": "ok", "NXDOMAIN": "nxdomain", "SERVFAIL": "servfail", "REFUSED": "refused"}


def system_resolver_ip() -> str | None:
    try:
        ns = dns.resolver.get_default_resolver().nameservers
        return str(ns[0]) if ns else None
    except Exception:  # noqa: BLE001 - no resolv.conf, etc.
        return None


class LiveBackend:
    """Real DNS queries over UDP port 53, retried over TCP when the reply is truncated."""

    def query(self, resolver: ResolverConfig, domain: str, rtype: str, cd: bool = False, run_number: int = 0) -> RawResponse:
        where = resolver.ip or system_resolver_ip()
        if not where:
            return RawResponse(resolver.name, "", rtype, "error", error="No system resolver configured")
        q = dns.message.make_query(domain, rtype, want_dnssec=True)   # RD=1, EDNS(0) with DO bit
        if cd:
            q.flags |= dns.flags.CD
        last_error = ""
        for _attempt in range(settings.query_retries + 1):
            start = time.perf_counter()
            try:
                resp, used_tcp = dns.query.udp_with_fallback(q, where, timeout=settings.query_timeout_s)
            except dns.exception.Timeout:
                last_error = "timeout"
                continue
            except Exception as exc:  # noqa: BLE001 - network unreachable, malformed reply...
                last_error = str(exc)
                continue
            ms = (time.perf_counter() - start) * 1000
            rcode = dns.rcode.to_text(resp.rcode())
            answer = [RRset(str(r.name).rstrip("."), dns.rdatatype.to_text(r.rdtype), int(r.ttl),
                            sorted(rd.to_text() for rd in r))
                      for r in resp.answer if r.rdtype != dns.rdatatype.RRSIG]
            return RawResponse(
                resolver=resolver.name, resolver_ip=where, record_type=rtype,
                status=_RCODE_STATUS.get(rcode, "error"), rcode=rcode,
                aa=bool(resp.flags & dns.flags.AA), tc=bool(resp.flags & dns.flags.TC),
                ra=bool(resp.flags & dns.flags.RA), ad=bool(resp.flags & dns.flags.AD),
                used_tcp=bool(used_tcp), response_ms=round(ms, 1), answer=answer)
        status = "timeout" if last_error == "timeout" else "error"
        return RawResponse(resolver.name, where, rtype, status, error=last_error)


# --------------------------------------------------------------------------- mock
# Addresses come from documentation ranges (RFC 5737 / RFC 3849) so nothing real is implied.
NORMAL_V4 = ["198.51.100.20", "198.51.100.21"]
NORMAL_V6 = ["2001:db8:10::20"]
SCENARIOS = {
    "normal":      "Stable domain; all resolvers agree.",
    "cdn":         "CDN: resolvers get different hosts inside the same /24 network (should NOT alert).",
    "geo":         "Geo-DNS: every resolver gets a different network (no majority, should NOT alert).",
    "migrate":     "After warm-up the domain moves to a new host in the same network (should NOT alert).",
    "spoof":       "After warm-up the system resolver returns an unrelated address (on-path / poisoned local resolver).",
    "poison":      "After warm-up one public resolver (Quad9) returns an unrelated address.",
    "hijack":      "After warm-up ALL resolvers agree on an unrelated address with a short TTL (registrar hijack / migration).",
    "private":     "System resolver returns a private address 10.0.0.5 for a public name.",
    "dnssec-bad":  "Signed zone with a broken signature: validating resolvers return SERVFAIL, but answer with CD = 1.",
    "dnssec-ok":   "Signed zone that validates: validating resolvers set the AD flag.",
    "fail":        "Every resolver times out (outage or interference).",
    "nxredirect":  "System resolver returns an address while public resolvers say NXDOMAIN (ISP NXDOMAIN rewriting).",
    "truncated":   "Large TXT answer: UDP reply truncated (TC = 1), answered over TCP.",
}


def scenario_for(domain: str) -> str:
    """normal.dnscope.test -> 'normal'. Other domains (mock mode only) behave normally."""
    if domain.endswith("." + SIMULATED_ZONE):
        label = domain[: -len(SIMULATED_ZONE) - 1].split(".")[-1]
        return label if label in SCENARIOS else "normal"
    return "normal"


class MockBackend:
    """Scripted DNS answers. `run_number` = completed checks for the domain, so scenarios can
    behave normally during the warm-up period and change afterwards."""

    def query(self, resolver: ResolverConfig, domain: str, rtype: str, cd: bool = False, run_number: int = 0) -> RawResponse:
        sc = scenario_for(domain)
        after_warmup = run_number >= settings.warmup_checks
        ip = resolver.ip or "192.0.2.1"
        base = dict(resolver=resolver.name, resolver_ip=ip, record_type=rtype, ra=True, simulated=True,
                    response_ms=12.0 + 7 * len(resolver.name) % 23)

        def ok(values: list[str], ttl: int = 300, ad: bool = False, rt: str | None = None, **kw) -> RawResponse:
            return RawResponse(status="ok", rcode="NOERROR", ad=ad,
                               answer=[RRset(domain, rt or rtype, ttl, sorted(values))] if values else [], **base, **kw)

        def nodata() -> RawResponse:
            return RawResponse(status="ok", rcode="NOERROR", **base)

        sys_res = resolver.ip is None
        if sc == "fail":
            return RawResponse(status="timeout", error="timeout", **base)
        if sc == "dnssec-bad" and resolver.validates_dnssec and not cd:
            return RawResponse(status="servfail", rcode="SERVFAIL", **base)
        if sc == "nxredirect":
            if rtype == "A" and sys_res:
                return ok(["192.0.2.53"], ttl=60)
            return RawResponse(status="nxdomain", rcode="NXDOMAIN", **base)

        if rtype == "A":
            if sc == "cdn":
                host = {None: 10, "8.8.8.8": 11, "1.1.1.1": 40, "9.9.9.9": 77}[resolver.ip]
                return ok([f"198.51.100.{host}"], ttl=60)
            if sc == "geo":
                net = {None: "198.51.100.", "8.8.8.8": "203.0.113.", "1.1.1.1": "192.0.2.", "9.9.9.9": "198.18.0."}[resolver.ip]
                return ok([net + "10"], ttl=60)
            if sc == "migrate" and after_warmup:
                return ok(["198.51.100.99"])
            if sc == "spoof" and after_warmup and sys_res:
                return ok(["203.0.113.66"], ttl=60)
            if sc == "poison" and after_warmup and resolver.ip == "9.9.9.9":
                return ok(["203.0.113.66"], ttl=60)
            if sc == "hijack" and after_warmup:
                return ok(["203.0.113.77"], ttl=20)
            if sc == "private" and sys_res:
                return ok(["10.0.0.5"])
            if sc in ("dnssec-ok", "dnssec-bad"):
                return ok(NORMAL_V4, ad=resolver.validates_dnssec and sc == "dnssec-ok")
            return ok(NORMAL_V4)
        if rtype == "AAAA":
            return ok(NORMAL_V6) if sc not in ("private",) else nodata()
        if rtype == "NS":
            return ok([f"ns1.{domain}.", f"ns2.{domain}."], ttl=86400)
        if rtype == "MX":
            return ok([f"10 mail.{domain}."], ttl=3600)
        if rtype == "TXT":
            if sc == "truncated":
                r = ok(['"v=spf1 include:_spf.' + domain + ' ~all"'] + [f'"verification-token-{i}"' for i in range(12)])
                r.used_tcp = True
                return r
            return ok(['"v=spf1 -all"'])
        if rtype == "CNAME":
            return nodata()
        return nodata()


def backend_for(domain: str):
    if domain.endswith("." + SIMULATED_ZONE) or settings.resolver_mode == "mock":
        return MockBackend()
    return LiveBackend()
