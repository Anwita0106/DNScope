def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_invalid_domain_422(client):
    r = client.post("/api/lookup", json={"domain": "https://example.com/x"})
    assert r.status_code == 422
    assert "URL" in r.json()["detail"]


def test_lookup_compare_alerts_history_stats(client):
    r = client.post("/api/lookup", json={"domain": "private.dnscope.test"})
    assert r.status_code == 200
    body = r.json()
    assert set(body["records"]) >= {"A", "AAAA", "MX"}
    assert body["alerts"]

    c = client.post("/api/compare", json={"domain": "normal.dnscope.test", "record_type": "A"}).json()
    assert len(c["rows"]) == 4 and c["comparison"]["status"] == "agree"

    alerts = client.get("/api/alerts", params={"status": "open"}).json()["items"]
    aid = alerts[0]["alert_id"]
    assert client.get(f"/api/alerts/{aid}").json()["evidence"]["possible_causes"]

    upd = client.patch(f"/api/alerts/{aid}", json={"status": "reviewed"}).json()
    assert upd["status"] == "reviewed"

    h = client.get("/api/domains/private.dnscope.test/history").json()
    assert h["address_changes"] and h["alerts"]

    s = client.get("/api/stats/overview").json()
    assert s["total_checks"] == 2 and s["domains_checked"] == 2 and len(s["activity"]) == 14


def test_ai_explanation_falls_back_without_key(client):
    client.post("/api/lookup", json={"domain": "dnssec-bad.dnscope.test"})
    aid = client.get("/api/alerts").json()["items"][0]["alert_id"]
    out = client.post(f"/api/alerts/{aid}/ai-explanation").json()
    assert out["source"] == "rule-based"
    assert "not proof" in out["text"]
    assert client.get("/api/ai/status").json()["available"] is False


def test_unknown_history_404(client):
    assert client.get("/api/domains/never-checked.example/history").status_code == 404


def test_ai_explanation_uses_claude_when_configured(client, monkeypatch):
    """The Claude call is stubbed: checks the request shape and that the answer is cached."""
    import anthropic
    from app.config import settings

    calls = {}

    class FakeMessages:
        def create(self, **kw):
            calls.update(kw)
            block = type("B", (), {"type": "text", "text": "Plain-language explanation."})()
            return type("M", (), {"content": [block]})()

    class FakeClient:
        def __init__(self, **kw):
            self.messages = FakeMessages()

    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
    client.post("/api/lookup", json={"domain": "private.dnscope.test"})
    aid = client.get("/api/alerts").json()["items"][0]["alert_id"]
    out = client.post(f"/api/alerts/{aid}/ai-explanation").json()
    assert out["source"] == "claude" and out["text"] == "Plain-language explanation."
    assert calls["model"] == settings.ai_model and "spoofing" in calls["system"]
    assert "private.dnscope.test" in calls["messages"][0]["content"]
    assert client.post(f"/api/alerts/{aid}/ai-explanation").json()["source"] == "cached"
