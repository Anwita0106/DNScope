"""Fill the database with labelled SIMULATED checks so every dashboard page has something to show.

    python -m app.seed_demo

Only domains under dnscope.test are used; they are answered by the mock resolver.
"""
from . import repository as repo
from .config import settings
from .service import run_check

PLAN = {
    "normal.dnscope.test": settings.warmup_checks + 3,
    "cdn.dnscope.test": settings.warmup_checks + 3,
    "migrate.dnscope.test": settings.warmup_checks + 2,
    "spoof.dnscope.test": settings.warmup_checks + 1,
    "poison.dnscope.test": settings.warmup_checks + 1,
    "hijack.dnscope.test": settings.warmup_checks + 2,
    "private.dnscope.test": 1,
    "dnssec-ok.dnscope.test": 2,
    "dnssec-bad.dnscope.test": 1,
    "fail.dnscope.test": settings.fail_count,
    "nxredirect.dnscope.test": 1,
    "geo.dnscope.test": 2,
}


def main() -> None:
    repo.init_db()
    for domain, n in PLAN.items():
        for _ in range(n):
            r = run_check(domain)
        print(f"{domain:28s} {n:2d} checks  -> alerts: {[(a['rule_id'], a['severity']) for a in r['alerts']] or 'none'}")
    print(f"\nDatabase: {settings.db_path}")


if __name__ == "__main__":
    main()
