import httpx
import respx
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import make_tar_gz, mock_github_tag, mock_pypi_provenance_missing, mock_pypi_release

client = TestClient(app)


def _mock_pypi(name="demo", version="1.0"):
    sdist = make_tar_gz({"setup.py": b"x=1\n", "PKG-INFO": f"Name: {name}\nVersion: {version}\n".encode()}, root_dir=f"{name}-{version}")
    mock_pypi_release(name, version, [(f"{name}-{version}.tar.gz", "sdist", sdist)], project_urls={})
    mock_pypi_provenance_missing(name, version, f"{name}-{version}.tar.gz")


def test_health_endpoints():
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/health").json() == {"status": "ok"}


def test_request_validation():
    bad = [
        {"package_name": "requests", "version": "2.32.0", "ecosystem": "rubygems"},
        {"package_name": "requests", "version": "not a version", "ecosystem": "pypi"},
        {"package_name": "-bad-", "version": "1.0", "ecosystem": "pypi"},
        {"package_name": "Bad Name", "version": "1.0.0", "ecosystem": "npm"},
        {"package_name": "lodash", "version": "4.17.21", "repository_url": "https://gitlab.com/a/b"},
        {"package_name": "lodash", "version": "4.17.21", "repository_url": "https://github.com.evil.io/a/b"},
        {"package_name": "lodash", "version": "4.17.21", "repository_url": "https://github.com/../etc"},
        {"package_name": "lodash", "version": "4.17.21", "repository_url": "file:///etc/passwd"},
    ]
    for body in bad:
        resp = client.post("/api/analyze", json=body)
        assert resp.status_code == 422, body
        assert resp.json()["error"]["code"] == "validation_error"


@respx.mock
def test_pypi_analysis_history_and_retrieval():
    _mock_pypi()
    resp = client.post("/api/analyze", json={"package_name": "demo", "ecosystem": "PyPI", "version": "1.0", "repository_url": None})
    assert resp.status_code == 200
    body = resp.json()
    assert body["package"]["ecosystem"] == "pypi" and body["risk"]["verdict"] == "WARNING"
    assert body["distribution"]["kind"] == "sdist" and body["ai_explanation"]["status"] == "disabled"

    fetched = client.get(f"/api/analysis/{body['report_id']}")
    assert fetched.status_code == 200 and fetched.json()["report_id"] == body["report_id"]

    history = client.get("/api/history").json()
    assert history[0]["id"] == body["report_id"]
    assert history[0]["package"] == {"name": "demo", "version": "1.0", "ecosystem": "pypi"}
    assert history[0]["verdict"] == "WARNING"
    assert client.get("/api/history?limit=1").status_code == 200
    assert client.get("/api/history?limit=0").status_code == 422


def test_unknown_analysis_is_404():
    resp = client.get("/api/analysis/nope")
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "report_not_found"


@respx.mock
def test_package_not_found_is_404_for_pypi():
    respx.get("https://pypi.org/pypi/ghost/1.0/json").mock(return_value=httpx.Response(404))
    respx.get("https://pypi.org/pypi/ghost/json").mock(return_value=httpx.Response(404))
    resp = client.post("/api/analyze", json={"package_name": "ghost", "ecosystem": "pypi", "version": "1.0"})
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "package_not_found"


@respx.mock
def test_registry_failure_is_502():
    respx.get("https://pypi.org/pypi/demo/1.0/json").mock(return_value=httpx.Response(503))
    resp = client.post("/api/analyze", json={"package_name": "demo", "ecosystem": "pypi", "version": "1.0"})
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "registry_error"


@respx.mock
def test_frontend_contract_matches_src_types_analysis_ts():
    _mock_pypi("demo", "1.0")
    started = client.post("/analyses", json={"ecosystem": "PyPI", "name": "demo", "version": "1.0", "repoUrl": ""})
    assert started.status_code == 200
    analysis_id = started.json()["id"]

    result = client.get(f"/analyses/{analysis_id}").json()
    assert set(result) == {"id", "package", "sourceRepo", "status", "createdAt", "risk", "aiExplanation", "comparison", "files", "provenance"}
    assert result["package"] == {"name": "demo", "ecosystem": "PyPI", "version": "1.0"}
    assert result["status"] in ("verified", "warning", "high_risk")
    assert set(result["risk"]) == {"status", "score", "findings"} and isinstance(result["risk"]["findings"], list)
    assert set(result["comparison"]) == {"added", "removed", "modified", "unchanged"}
    assert set(result["provenance"]) == {"sourceRepo", "sourceCommit", "publishedAt", "publisher", "registryChecksum", "signatureVerified", "buildProvenance", "attestation"}
    assert result["provenance"]["signatureVerified"] is False
    assert isinstance(result["aiExplanation"], str) and result["aiExplanation"]

    listing = client.get("/analyses").json()
    assert listing[0] == {k: result[k] for k in ("id", "package", "sourceRepo", "status", "createdAt")}


@respx.mock
def test_legacy_endpoints_still_work():
    _mock_pypi()
    body = client.post("/analyze", json={"package_name": "demo", "ecosystem": "pypi", "version": "1.0"}).json()
    assert client.get(f"/report/{body['report_id']}").status_code == 200
