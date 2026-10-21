"""FastAPI application: REST endpoints used by the React dashboard."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import ai_assistant, repository as repo
from .config import SIMULATED_ZONE, SUPPORTED_RECORD_TYPES, settings
from .resolver_service import SCENARIOS
from .service import run_check
from .validator import InvalidDomain, validate_domain

log = logging.getLogger("dnscope")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    repo.init_db()
    # On a fresh deployment the database is empty; DNSCOPE_SEED_DEMO=1 fills it with SIMULATED demo data.
    if os.environ.get("DNSCOPE_SEED_DEMO") == "1" and repo.overview(1)["total_checks"] == 0:
        from .seed_demo import main as seed
        log.info("Seeding simulated demo data")
        seed()
    yield


app = FastAPI(title="DNScope API", version="1.0.0", lifespan=lifespan,
              description="DNS monitoring and spoofing-detection API (Computer Networks project).")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


class LookupRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    record_types: list[str] | None = Field(None, examples=[["A", "AAAA", "MX"]])


class CompareRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    record_type: Literal["A", "AAAA"] = "A"


class StatusUpdate(BaseModel):
    status: Literal["open", "reviewed", "dismissed"]


def _check(domain: str, rtypes: list[str] | None) -> dict:
    try:
        return run_check(domain, rtypes)
    except InvalidDomain as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "resolver_mode": settings.resolver_mode,
            "resolvers": [r.name for r in settings.resolvers], "ai": ai_assistant.status()}


@app.post("/api/lookup")
def lookup(req: LookupRequest) -> dict:
    """Full check (all resolvers) returning records grouped by type."""
    result = _check(req.domain, req.record_types)
    records: dict[str, list[dict]] = {}
    for r in result["results"]:
        records.setdefault(r["record_type"], []).append(r)
    result["records"] = records
    return result


@app.post("/api/compare")
def compare(req: CompareRequest) -> dict:
    """Query all resolvers for A/AAAA and return the side-by-side comparison."""
    result = _check(req.domain, ["A", "AAAA"])
    result["record_type"] = req.record_type
    result["rows"] = [r for r in result["results"] if r["record_type"] == req.record_type]
    result["comparison"] = result["comparisons"].get(req.record_type)
    return result


@app.get("/api/alerts")
def alerts(severity: str | None = None, status: str | None = None, domain: str | None = None,
           limit: int = Query(100, le=500), offset: int = 0) -> dict:
    items = repo.list_alerts(severity, status, domain, limit, offset)
    return {"items": items, "count": len(items)}


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int) -> dict:
    a = repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@app.patch("/api/alerts/{alert_id}")
def alert_status(alert_id: int, body: StatusUpdate) -> dict:
    a = repo.update_alert_status(alert_id, body.status)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@app.post("/api/alerts/{alert_id}/ai-explanation")
def alert_ai(alert_id: int, refresh: bool = False) -> dict:
    """Plain-language explanation of an alert (Claude if configured, otherwise rule-based)."""
    a = repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    if a.get("ai_explanation") and not refresh:
        return {"alert_id": alert_id, "text": a["ai_explanation"], "source": "cached", "model": None}
    out = ai_assistant.explain_alert(a)
    if out["source"] == "claude":
        repo.save_ai_explanation(alert_id, out["text"])
    return {"alert_id": alert_id} | out


@app.get("/api/ai/status")
def ai_status() -> dict:
    return ai_assistant.status()


@app.get("/api/domains/{domain}/history")
def history(domain: str, days: int = Query(30, ge=1, le=365)) -> dict:
    try:
        name = validate_domain(domain)
    except InvalidDomain as exc:
        raise HTTPException(422, str(exc)) from exc
    h = repo.domain_history(name, days)
    if not h:
        raise HTTPException(404, "This domain has not been checked yet.")
    return h


@app.get("/api/stats/overview")
def stats(days: int = Query(14, ge=1, le=90)) -> dict:
    return repo.overview(days)


@app.get("/api/scenarios")
def scenarios() -> dict:
    """Simulated test scenarios (answered by the mock resolver, labelled simulated)."""
    return {"zone": SIMULATED_ZONE, "warmup_checks": settings.warmup_checks,
            "items": [{"domain": f"{k}.{SIMULATED_ZONE}", "description": v} for k, v in SCENARIOS.items()],
            "record_types": SUPPORTED_RECORD_TYPES}


# ---------------------------------------------------------------------------
# Serve the built React dashboard from the same server (used for deployment).
# Locally you normally run the Vite dev server instead, so this is skipped when no build exists.
_STATIC = Path(os.environ.get("DNSCOPE_STATIC_DIR", Path(__file__).resolve().parents[2] / "frontend" / "dist"))
if (_STATIC / "index.html").exists():
    app.mount("/", StaticFiles(directory=_STATIC, html=True), name="dashboard")
