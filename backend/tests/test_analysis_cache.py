import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import analysis_cache, orchestrator

BASE = "https://proj.supabase.co"
TABLE_URL = BASE + "/rest/v1/analysis_cache"
client = TestClient(app)


@pytest.fixture
def cache_on(monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_URL", BASE)
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_KEY", "service-secret")
    monkeypatch.setattr(settings, "SUPABASE_TIMEOUT", 2)


def _report(**over):
    report = {
        "report_id": "origin-id", "created_at": 1.0,
        "package": {"name": "demo-pkg", "version": "1.0.0", "ecosystem": "npm"},
        "source": {"repository": "https://github.com/o/r", "commit": None, "resolution_method": None,
                   "correspondence": "EXACT", "directory": None, "confidence": None, "notes": []},
        "integrity": {"tarball_verified": True, "provenance_status": "NOT_AVAILABLE"},
        "summary": {"identical": 1, "modified": 0, "added": 0, "removed": 0, "expected_generated": 0, "uncertain": 0, "unexplained": 0},
        "risk": {"level": "LOW", "score": 0, "verdict": "VERIFIED", "confidence": "HIGH", "rationale": []},
        "findings": [], "comparison": [], "limitations": [], "analysis_complete": True,
        "ai_explanation": {"status": "disabled"},
    }
    report.update(over)
    return report


def test_key_is_normalised_per_ecosystem():
    k = analysis_cache.make_key
    assert k("npm", "Lodash", "4.17.21", None) == k("npm", " lodash ", "4.17.21", "")
    assert k("pypi", "Typing_Extensions", "4.0", None) == k("pypi", "typing-extensions", "4.0", None)
    assert k("npm", "a", "1.0.0", "https://github.com/O/R.git/") == k("npm", "a", "1.0.0", "https://github.com/o/r")
    assert k("npm", "a", "1.0.0", None) != k("npm", "a", "1.0.0", "https://github.com/o/r")  # repo changes the result
    assert k("npm", "a", "1.0.0", None) != k("pypi", "a", "1.0.0", None)


def test_cache_is_off_without_credentials_or_over_plain_http(monkeypatch):
    assert analysis_cache.is_enabled() is False
    monkeypatch.setattr(settings, "SUPABASE_URL", "http://evil.example.com")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_KEY", "k")
    assert analysis_cache.is_enabled() is False  # the key must not travel in clear text
    monkeypatch.setattr(settings, "SUPABASE_URL", "http://localhost:54321")
    assert analysis_cache.is_enabled() is True


@respx.mock
async def test_lookup_hit_and_miss(cache_on):
    route = respx.get(TABLE_URL).mock(return_value=httpx.Response(200, json=[
        {"document": _report(), "created_at": "2026-10-31T10:00:00+00:00"}]))
    hit = await analysis_cache.lookup("npm", "demo-pkg", "1.0.0", None)
    assert hit["document"]["package"]["name"] == "demo-pkg" and hit["analyzed_at"] > 0
    req = route.calls[0].request
    assert req.headers["apikey"] == "service-secret" and req.headers["authorization"] == "Bearer service-secret"
    assert "cache_key=eq.npm%7Cdemo-pkg%7C1.0.0%7C%7C1" in str(req.url) and "created_at=gte." in str(req.url)

    respx.get(TABLE_URL).mock(return_value=httpx.Response(200, json=[]))
    assert await analysis_cache.lookup("npm", "demo-pkg", "1.0.0", None) is None


@respx.mock
@pytest.mark.parametrize("response", [httpx.Response(401), httpx.Response(500), httpx.Response(200, text="not json"),
                                      httpx.Response(200, json=[{"document": "nope"}])])
async def test_lookup_failures_are_misses(cache_on, response):
    respx.get(TABLE_URL).mock(return_value=response)
    assert await analysis_cache.lookup("npm", "demo-pkg", "1.0.0", None) is None


@respx.mock
async def test_lookup_network_error_is_a_miss(cache_on):
    respx.get(TABLE_URL).mock(side_effect=httpx.ConnectError("down"))
    assert await analysis_cache.lookup("npm", "demo-pkg", "1.0.0", None) is None


@respx.mock
async def test_store_upserts_without_local_ids_and_skips_incomplete(cache_on):
    route = respx.post(TABLE_URL).mock(return_value=httpx.Response(201))
    assert await analysis_cache.store(_report(), None) is True
    sent = json.loads(route.calls[0].request.content)
    assert sent["cache_key"] == "npm|demo-pkg|1.0.0||1" and sent["verdict"] == "VERIFIED"
    assert "report_id" not in sent["document"] and "created_at" not in sent["document"]
    assert "on_conflict=cache_key" in str(route.calls[0].request.url)
    assert "merge-duplicates" in route.calls[0].request.headers["prefer"]

    assert await analysis_cache.store(_report(analysis_complete=False), None) is False
    assert route.call_count == 1


@respx.mock
def test_api_serves_hit_without_running_analysis(cache_on, monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("analysis must not run on a cache hit")

    monkeypatch.setattr(orchestrator, "analyze_package", boom)
    respx.get(TABLE_URL).mock(return_value=httpx.Response(200, json=[
        {"document": {k: v for k, v in _report().items() if k not in ("report_id", "created_at")},
         "created_at": "2026-10-31T10:00:00+00:00"}]))

    resp = client.post("/api/analyze", json={"package_name": "demo-pkg", "version": "1.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cache"]["hit"] is True and body["report_id"] != "origin-id"
    # the hit is a normal entry in this server's history
    assert client.get(f"/api/analysis/{body['report_id']}").json()["package"]["name"] == "demo-pkg"
    assert any(h["id"] == body["report_id"] for h in client.get("/api/history").json())
    assert client.post("/analyses", json={"ecosystem": "npm", "name": "demo-pkg", "version": "1.0.0"}).status_code == 200


@respx.mock
def test_api_miss_runs_analysis_then_stores(cache_on, monkeypatch):
    from app.services import report_generator

    async def fake_analyze(name, version, ecosystem="npm", repository_url=None):
        report = _report()
        report.pop("report_id"); report.pop("created_at")
        report_generator.save_report(report)
        return report

    monkeypatch.setattr(orchestrator, "analyze_package", fake_analyze)
    respx.get(TABLE_URL).mock(return_value=httpx.Response(200, json=[]))
    post = respx.post(TABLE_URL).mock(return_value=httpx.Response(201))

    resp = client.post("/api/analyze", json={"package_name": "demo-pkg", "version": "1.0.0"})
    assert resp.status_code == 200 and resp.json()["cache"] is None
    assert post.call_count == 1


@respx.mock
def test_api_survives_a_broken_cache(cache_on, monkeypatch):
    from app.services import report_generator

    async def fake_analyze(name, version, ecosystem="npm", repository_url=None):
        report = _report()
        report.pop("report_id"); report.pop("created_at")
        report_generator.save_report(report)
        return report

    monkeypatch.setattr(orchestrator, "analyze_package", fake_analyze)
    respx.get(TABLE_URL).mock(side_effect=httpx.ConnectError("down"))
    respx.post(TABLE_URL).mock(return_value=httpx.Response(500))

    resp = client.post("/api/analyze", json={"package_name": "demo-pkg", "version": "1.0.0"})
    assert resp.status_code == 200 and resp.json()["analysis_complete"] is True
