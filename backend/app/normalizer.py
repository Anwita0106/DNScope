"""Record Normalizer: turns raw responses into comparable answer sets."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .config import settings
from .resolver_service import RawResponse


@dataclass
class Answer:
    resolver: str
    resolver_ip: str
    record_type: str
    status: str
    rcode: str
    values: list[str] = field(default_factory=list)      # final addresses / record values, sorted
    prefixes: list[str] = field(default_factory=list)    # /24 or /48 networks of the addresses
    max_ttl: int | None = None
    cname_chain: list[str] = field(default_factory=list)
    ad: bool = False
    used_tcp: bool = False
    response_ms: float = 0.0
    cd_retry_answered: bool | None = None

    @property
    def answered(self) -> bool:
        return self.status == "ok" and bool(self.values)


def prefix_of(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    plen = settings.ipv4_prefix if addr.version == 4 else settings.ipv6_prefix
    return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))


def normalise(raw: RawResponse) -> Answer:
    ans = Answer(raw.resolver, raw.resolver_ip, raw.record_type, raw.status, raw.rcode,
                 ad=raw.ad, used_tcp=raw.used_tcp, response_ms=raw.response_ms,
                 cd_retry_answered=raw.cd_retry_answered)
    if raw.status != "ok":
        return ans
    wanted = [rr for rr in raw.answer if rr.rtype == raw.record_type]
    # follow the CNAME chain: everything in the answer section that is a CNAME is part of it
    ans.cname_chain = [v.rstrip(".").lower() for rr in raw.answer if rr.rtype == "CNAME" and raw.record_type != "CNAME"
                       for v in rr.values]
    values = sorted({v.rstrip(".").lower() if raw.record_type not in ("TXT",) else v for rr in wanted for v in rr.values})
    ans.values = values
    if wanted:
        # cached copies only count down, so the largest TTL is the best estimate of the real value
        ans.max_ttl = max(rr.ttl for rr in wanted)
    if raw.record_type in ("A", "AAAA"):
        ans.prefixes = sorted({prefix_of(v) for v in values})
    return ans


PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(ip: str) -> bool:
    """Private, loopback, link-local or carrier-grade NAT - not reachable as a public server."""
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in PRIVATE_NETS)
