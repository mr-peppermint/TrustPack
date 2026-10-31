import pytest
import respx
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import settings
from app.main import app
from app.utils import rate_limit
from app.utils.errors import RateLimitExceededError
from tests.conftest import make_tar_gz, mock_pypi_provenance_missing, mock_pypi_release

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clean_limiter_state(monkeypatch):
    """Isolate each test's counters from every other test (and from the module's real clock state)."""
    monkeypatch.setattr(rate_limit, "_hits", {})
    monkeypatch.setattr(rate_limit, "_last_cleanup", 0.0)


def _request(ip: str = "1.2.3.4", forwarded_for: str = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded_for.encode())] if forwarded_for else []
    return Request({"type": "http", "client": (ip, 12345), "headers": headers})


def test_disabled_by_default_setting_never_raises(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 0)
    req = _request()
    for _ in range(100):
        rate_limit.enforce_rate_limit(req)  # must never raise, and must not touch _hits
    assert rate_limit._hits == {}


def test_allows_up_to_the_limit_then_blocks(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 3)
    req = _request()
    for _ in range(3):
        rate_limit.enforce_rate_limit(req, _now=1000.0)
    with pytest.raises(RateLimitExceededError) as exc_info:
        rate_limit.enforce_rate_limit(req, _now=1000.0)
    assert exc_info.value.http_status == 429
    assert exc_info.value.code == "rate_limited"
    assert "Retry-After" in exc_info.value.headers


def test_window_resets_after_sixty_seconds(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 1)
    req = _request()
    rate_limit.enforce_rate_limit(req, _now=1000.0)
    with pytest.raises(RateLimitExceededError):
        rate_limit.enforce_rate_limit(req, _now=1010.0)  # still inside the same 60s window
    rate_limit.enforce_rate_limit(req, _now=1061.0)  # a new window: must succeed again


def test_different_ips_are_tracked_independently(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 1)
    rate_limit.enforce_rate_limit(_request(ip="1.1.1.1"), _now=1000.0)
    rate_limit.enforce_rate_limit(_request(ip="2.2.2.2"), _now=1000.0)  # a different address: not blocked
    with pytest.raises(RateLimitExceededError):
        rate_limit.enforce_rate_limit(_request(ip="1.1.1.1"), _now=1000.0)


def test_x_forwarded_for_takes_priority_and_uses_the_first_hop():
    req = _request(ip="10.0.0.1", forwarded_for="203.0.113.5, 10.0.0.1")
    assert rate_limit._client_ip(req) == "203.0.113.5"


def test_direct_connection_used_when_no_forwarded_header():
    assert rate_limit._client_ip(_request(ip="203.0.113.9")) == "203.0.113.9"


def test_stale_entries_are_cleaned_up(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 100)
    rate_limit.enforce_rate_limit(_request(ip="1.1.1.1"), _now=1000.0)
    assert "1.1.1.1" in rate_limit._hits
    # Far enough past WINDOW_SECONDS*2 that a cleanup sweep (triggered by any call) evicts the old entry.
    rate_limit.enforce_rate_limit(_request(ip="2.2.2.2"), _now=1000.0 + rate_limit._STALE_AFTER + 120)
    assert "1.1.1.1" not in rate_limit._hits


@respx.mock
def test_api_returns_429_with_retry_after_once_the_limit_is_hit(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 2)
    sdist = make_tar_gz({"setup.py": b"x=1\n", "PKG-INFO": b"Name: demo\nVersion: 1.0\n"}, root_dir="demo-1.0")
    mock_pypi_release("demo", "1.0", [("demo-1.0.tar.gz", "sdist", sdist)], project_urls={})
    mock_pypi_provenance_missing("demo", "1.0", "demo-1.0.tar.gz")
    body = {"package_name": "demo", "version": "1.0", "ecosystem": "pypi"}

    assert client.post("/api/analyze", json=body).status_code == 200
    assert client.post("/api/analyze", json=body).status_code == 200
    blocked = client.post("/api/analyze", json=body)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["retry-after"]) > 0


@respx.mock
def test_api_read_endpoints_are_not_rate_limited(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 1)
    sdist = make_tar_gz({"setup.py": b"x=1\n", "PKG-INFO": b"Name: demo\nVersion: 1.0\n"}, root_dir="demo-1.0")
    mock_pypi_release("demo", "1.0", [("demo-1.0.tar.gz", "sdist", sdist)], project_urls={})
    mock_pypi_provenance_missing("demo", "1.0", "demo-1.0.tar.gz")
    body = {"package_name": "demo", "version": "1.0", "ecosystem": "pypi"}

    assert client.post("/api/analyze", json=body).status_code == 200
    assert client.post("/api/analyze", json=body).status_code == 429  # the write path is now throttled
    for _ in range(5):
        assert client.get("/api/history").status_code == 200  # reads never go through the limiter
