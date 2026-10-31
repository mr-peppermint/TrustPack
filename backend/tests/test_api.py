import base64
import hashlib
import json

import httpx
import respx
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import make_tar_gz

client = TestClient(app)

GIT_HEAD = "a" * 40


def _integrity_for(data: bytes) -> str:
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_analyze_rejects_invalid_package_name():
    resp = client.post("/analyze", json={"package_name": "Invalid Name!", "version": "1.0.0"})
    assert resp.status_code == 422


def test_analyze_rejects_invalid_version():
    resp = client.post("/analyze", json={"package_name": "demo-pkg", "version": "not-a-version"})
    assert resp.status_code == 422


@respx.mock
def test_analyze_nonexistent_package_returns_404():
    respx.get("https://registry.npmjs.org/totally-fake-pkg-xyz/1.0.0").mock(return_value=httpx.Response(404))
    respx.get("https://registry.npmjs.org/totally-fake-pkg-xyz").mock(return_value=httpx.Response(404))

    resp = client.post("/analyze", json={"package_name": "totally-fake-pkg-xyz", "version": "1.0.0"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "package_not_found"


@respx.mock
def test_analyze_end_to_end_with_matching_source(tmp_path):
    package_json = {
        "name": "demo-pkg", "version": "1.0.0", "main": "index.js",
        "scripts": {"test": "jest"},
        "dependencies": {"left-pad": "^1.0.0"},
        "repository": {"type": "git", "url": "git+https://github.com/demo/demo-pkg.git"},
        "gitHead": GIT_HEAD,
    }
    tarball_bytes = make_tar_gz(
        {"package.json": json.dumps(package_json).encode(), "index.js": b"console.log('hi')"},
        root_dir="package",
    )
    source_bytes = make_tar_gz(
        {"package.json": json.dumps(package_json).encode(), "index.js": b"console.log('hi')"},
        root_dir=f"demo-pkg-{GIT_HEAD}",
    )

    respx.get("https://registry.npmjs.org/demo-pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "demo-pkg", "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
            "integrity": _integrity_for(tarball_bytes),
        },
        "repository": package_json["repository"],
        "gitHead": GIT_HEAD,
        "scripts": package_json["scripts"],
        "dependencies": package_json["dependencies"],
    }))
    respx.get("https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )
    respx.get(f"https://api.github.com/repos/demo/demo-pkg/commits/{GIT_HEAD}").mock(
        return_value=httpx.Response(200, json={"sha": GIT_HEAD})
    )
    respx.get(f"https://codeload.github.com/demo/demo-pkg/tar.gz/{GIT_HEAD}").mock(
        return_value=httpx.Response(200, content=source_bytes)
    )

    resp = client.post("/analyze", json={"package_name": "demo-pkg", "version": "1.0.0"})
    assert resp.status_code == 200
    body = resp.json()

    assert body["package"] == {"name": "demo-pkg", "version": "1.0.0"}
    assert body["source"]["correspondence"] == "EXACT"
    assert body["source"]["commit"] == GIT_HEAD
    assert body["integrity"]["tarball_verified"] is True
    assert body["summary"]["identical"] == 2
    assert body["analysis_complete"] is True
    assert body["risk"]["level"] in ("LOW", "INCONCLUSIVE")

    report_id = body["report_id"]
    report_resp = client.get(f"/report/{report_id}")
    assert report_resp.status_code == 200
    assert report_resp.json()["report_id"] == report_id


@respx.mock
def test_analyze_missing_gitHead_falls_back_to_tag(tmp_path):
    package_json = {
        "name": "tag-pkg", "version": "2.0.0", "main": "index.js",
        "repository": {"type": "git", "url": "https://github.com/demo/tag-pkg.git"},
    }
    tarball_bytes = make_tar_gz(
        {"package.json": json.dumps(package_json).encode(), "index.js": b"x=1"}, root_dir="package"
    )
    source_bytes = make_tar_gz(
        {"package.json": json.dumps(package_json).encode(), "index.js": b"x=1"}, root_dir="tag-pkg-v2.0.0"
    )

    respx.get("https://registry.npmjs.org/tag-pkg/2.0.0").mock(return_value=httpx.Response(200, json={
        "name": "tag-pkg", "version": "2.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/tag-pkg/-/tag-pkg-2.0.0.tgz",
            "integrity": _integrity_for(tarball_bytes),
        },
        "repository": package_json["repository"],
    }))
    respx.get("https://registry.npmjs.org/tag-pkg/-/tag-pkg-2.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )
    respx.get("https://api.github.com/repos/demo/tag-pkg/git/refs/tags/v2.0.0").mock(
        return_value=httpx.Response(200, json={"ref": "refs/tags/v2.0.0"})
    )
    respx.get("https://codeload.github.com/demo/tag-pkg/tar.gz/v2.0.0").mock(
        return_value=httpx.Response(200, content=source_bytes)
    )

    resp = client.post("/analyze", json={"package_name": "tag-pkg", "version": "2.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"]["correspondence"] == "INFERRED"
    assert body["source"]["resolution_method"] == "tag"


@respx.mock
def test_analyze_missing_source_repository_is_inconclusive():
    package_json = {"name": "norepo-pkg", "version": "1.0.0", "main": "index.js"}
    tarball_bytes = make_tar_gz(
        {"package.json": json.dumps(package_json).encode(), "index.js": b"x=1"}, root_dir="package"
    )

    respx.get("https://registry.npmjs.org/norepo-pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "norepo-pkg", "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/norepo-pkg/-/norepo-pkg-1.0.0.tgz",
            "integrity": _integrity_for(tarball_bytes),
        },
    }))
    respx.get("https://registry.npmjs.org/norepo-pkg/-/norepo-pkg-1.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )

    resp = client.post("/analyze", json={"package_name": "norepo-pkg", "version": "1.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"]["correspondence"] == "NONE"
    assert body["risk"]["level"] == "INCONCLUSIVE"
    assert any("source correspondence" in lim.lower() for lim in body["limitations"])


@respx.mock
def test_analyze_invalid_tarball_integrity_returns_report_with_failed_integrity():
    package_json = {"name": "badintegrity-pkg", "version": "1.0.0"}
    tarball_bytes = make_tar_gz({"package.json": json.dumps(package_json).encode()}, root_dir="package")

    respx.get("https://registry.npmjs.org/badintegrity-pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "badintegrity-pkg", "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/badintegrity-pkg/-/badintegrity-pkg-1.0.0.tgz",
            "integrity": _integrity_for(b"totally different content"),
        },
    }))
    respx.get("https://registry.npmjs.org/badintegrity-pkg/-/badintegrity-pkg-1.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )

    resp = client.post("/analyze", json={"package_name": "badintegrity-pkg", "version": "1.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["integrity"]["tarball_verified"] is False
    assert body["analysis_complete"] is False
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")


def test_report_not_found_returns_404():
    resp = client.get("/report/does-not-exist")
    assert resp.status_code == 404
