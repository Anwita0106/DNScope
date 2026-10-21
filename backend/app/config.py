"""Central configuration. Every threshold used by the detection rules lives here.

Values can be overridden with environment variables (see .env.example).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _load_dotenv() -> None:
    """Minimal .env loader so students don't need an extra package."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


@dataclass(frozen=True)
class ResolverConfig:
    name: str
    ip: str | None          # None = use the operating system's configured resolver
    validates_dnssec: bool  # public resolvers below validate DNSSEC; the system resolver may not


@dataclass
class Settings:
    # --- storage -----------------------------------------------------------
    db_path: str = _env("DNSCOPE_DB_PATH", str(Path(__file__).resolve().parent.parent / "dnscope.db"))

    # --- resolvers (vantage points) ---------------------------------------
    resolvers: list[ResolverConfig] = field(default_factory=lambda: [
        ResolverConfig("System resolver", None, False),
        ResolverConfig("Google Public DNS", "8.8.8.8", True),
        ResolverConfig("Cloudflare", "1.1.1.1", True),
        ResolverConfig("Quad9", "9.9.9.9", True),
    ])
    # "live" sends real DNS queries; "mock" answers every domain from scripted scenarios.
    # Domains under dnscope.test are ALWAYS answered by the mock resolver (labelled simulated).
    resolver_mode: str = _env("DNSCOPE_RESOLVER_MODE", "live")
    query_timeout_s: float = float(_env("DNSCOPE_QUERY_TIMEOUT", "2.0"))
    query_retries: int = int(_env("DNSCOPE_QUERY_RETRIES", "1"))

    # --- detection thresholds (calibrate these, see README) ---------------
    warmup_checks: int = int(_env("DNSCOPE_WARMUP_CHECKS", "5"))      # R1/R3 silent until baseline exists
    ttl_low_ratio: float = float(_env("DNSCOPE_TTL_LOW_RATIO", "0.1"))  # R3
    ttl_high_ratio: float = float(_env("DNSCOPE_TTL_HIGH_RATIO", "10"))  # R3
    ttl_history_size: int = 20
    fail_count: int = int(_env("DNSCOPE_FAIL_COUNT", "3"))   # R4: at least fail_count ...
    fail_window: int = int(_env("DNSCOPE_FAIL_WINDOW", "5"))  # ... of the last fail_window runs
    ipv4_prefix: int = 24   # "same network" heuristic for R1/R2
    ipv6_prefix: int = 48

    # --- optional AI assistant ---------------------------------------------
    anthropic_api_key: str = _env("ANTHROPIC_API_KEY", "")
    ai_model: str = _env("DNSCOPE_AI_MODEL", "claude-haiku-5-5")
    ai_max_tokens: int = 400

    # --- web ----------------------------------------------------------------
    cors_origins: list[str] = field(default_factory=lambda: _env(
        "DNSCOPE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","))


settings = Settings()

SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
SIMULATED_ZONE = "dnscope.test"   # .test is reserved by RFC 6761 and never resolves on the Internet
