import asyncio
import json

import httpx
import respx

from app.config import settings
from app.services import orchestrator
from tests.conftest import make_tar_gz


async def test_concurrent_analyses_are_bounded(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_ANALYSES", 2)
    semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_ANALYSES)
    in_flight = {"current": 0, "max_seen": 0}

    async def fake_analyze(name, version):
        async with semaphore:
            in_flight["current"] += 1
            in_flight["max_seen"] = max(in_flight["max_seen"], in_flight["current"])
            await asyncio.sleep(0.02)
            in_flight["current"] -= 1
            return {"package": {"name": name, "version": version}}

    await asyncio.gather(*[fake_analyze("pkg", str(i)) for i in range(6)])
    assert in_flight["max_seen"] <= 2


@respx.mock
async def test_partial_failure_from_corrupted_source_archive_still_returns_report():
    """If the source archive download succeeds but the archive itself is
    corrupted, the pipeline must not crash — it degrades to a report with
    correspondence NONE and a limitation explaining what failed, rather than
    silently claiming success or raising an unhandled exception.
    """
    package_json = {"name": "partial-fail-pkg", "version": "1.0.0"}
    tarball_bytes = make_tar_gz({"package.json": json.dumps(package_json).encode()}, root_dir="package")

    import hashlib
    import base64
    def integrity_for(data):
        return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    respx.get("https://registry.npmjs.org/partial-fail-pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "partial-fail-pkg", "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/partial-fail-pkg/-/partial-fail-pkg-1.0.0.tgz",
            "integrity": integrity_for(tarball_bytes),
        },
        "repository": {"url": "https://github.com/owner/partial-fail-repo"},
    }))
    respx.get("https://registry.npmjs.org/partial-fail-pkg/-/partial-fail-pkg-1.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )
    respx.get("https://api.github.com/repos/owner/partial-fail-repo/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://api.github.com/repos/owner/partial-fail-repo/git/refs/tags/1.0.0").mock(
        return_value=httpx.Response(200, json={"ref": "refs/tags/1.0.0"})
    )
    respx.get("https://codeload.github.com/owner/partial-fail-repo/tar.gz/1.0.0").mock(
        return_value=httpx.Response(200, content=b"this is not a valid gzip tarball")
    )

    report = await orchestrator.analyze_package("partial-fail-pkg", "1.0.0")

    assert report["analysis_complete"] is True
    assert report["source"]["correspondence"] == "NONE"
    assert any("could not be safely processed" in lim for lim in report["limitations"])


@respx.mock
async def test_unexpected_executable_only_in_published_is_flagged():
    package_json = {"name": "exec-pkg", "version": "1.0.0"}
    tarball_bytes = make_tar_gz({
        "package.json": __import__("json").dumps(package_json).encode(),
        "bin/run.sh": b"#!/bin/sh\necho hi\n",
    }, root_dir="package")
    source_bytes = make_tar_gz({
        "package.json": __import__("json").dumps(package_json).encode(),
    }, root_dir="exec-pkg-v1.0.0")

    import hashlib
    import base64
    def integrity_for(data):
        return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    respx.get("https://registry.npmjs.org/exec-pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "exec-pkg", "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/exec-pkg/-/exec-pkg-1.0.0.tgz",
            "integrity": integrity_for(tarball_bytes),
        },
        "repository": {"url": "https://github.com/owner/exec-pkg"},
    }))
    respx.get("https://registry.npmjs.org/exec-pkg/-/exec-pkg-1.0.0.tgz").mock(
        return_value=httpx.Response(200, content=tarball_bytes)
    )
    respx.get("https://api.github.com/repos/owner/exec-pkg/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(200, json={"ref": "refs/tags/v1.0.0"})
    )
    respx.get("https://codeload.github.com/owner/exec-pkg/tar.gz/v1.0.0").mock(
        return_value=httpx.Response(200, content=source_bytes)
    )

    report = await orchestrator.analyze_package("exec-pkg", "1.0.0")

    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "UNEXPECTED_EXECUTABLE_FILE" in rule_ids
