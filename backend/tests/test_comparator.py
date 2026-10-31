from app.services.comparator import compare_manifests
from app.services.manifest_generator import FileRecord


def _rec(path, content):
    import hashlib
    return FileRecord(
        path=path, size=len(content), sha256=hashlib.sha256(content).hexdigest(),
        extension="." + path.rsplit(".", 1)[-1] if "." in path else "",
        category="javascript", is_executable=False,
    )


def test_identical_files_are_matched():
    src = {"index.js": _rec("index.js", b"same")}
    pub = {"index.js": _rec("index.js", b"same")}
    result = compare_manifests(src, pub, {})
    assert result.summary["identical"] == 1
    assert result.entries[0]["status"] == "IDENTICAL"


def test_modified_doc_file_is_flagged_modified():
    src = {"README.md": _rec("README.md", b"old docs")}
    pub = {"README.md": _rec("README.md", b"new docs")}
    result = compare_manifests(src, pub, {})
    assert result.summary["modified"] == 1


def test_modified_source_file_is_unexplained():
    src = {"index.js": _rec("index.js", b"old code")}
    pub = {"index.js": _rec("index.js", b"new code")}
    result = compare_manifests(src, pub, {})
    assert result.summary["unexplained"] == 1
    assert result.entries[0]["status"] == "UNEXPLAINED"


def test_added_file_only_in_published():
    src = {}
    pub = {"extra.js": _rec("extra.js", b"new file")}
    result = compare_manifests(src, pub, {})
    assert result.summary["added"] == 1


def test_removed_file_only_in_source():
    src = {"old.js": _rec("old.js", b"gone")}
    pub = {}
    result = compare_manifests(src, pub, {})
    assert result.summary["removed"] == 1


def test_dist_file_with_no_evidence_is_uncertain_not_trusted():
    """Location alone must never earn trust: a bundle in dist/ with nothing tying it to the source is
    UNCERTAIN (and later scored), not EXPECTED_GENERATED."""
    src = {}
    pub = {"dist/bundle.min.js": _rec("dist/bundle.min.js", b"minified")}
    result = compare_manifests(src, pub, {})
    assert result.summary["expected_generated"] == 0
    assert result.summary["uncertain"] == 1


def test_dist_file_with_source_counterpart_is_expected_generated():
    src = {"src/parser.ts": _rec("src/parser.ts", b"export const x = 1")}
    pub = {"dist/parser.js": _rec("dist/parser.js", b"exports.x = 1")}
    result = compare_manifests(src, pub, {})
    entry = next(e for e in result.entries if e["path"] == "dist/parser.js")
    assert entry["status"] == "EXPECTED_GENERATED"
    assert any("src/parser.ts" in ev for ev in entry["evidence"])


def test_declared_main_output_is_expected_generated():
    src = {"src/index.ts": _rec("src/index.ts", b"export {}")}
    pub = {"index.js": _rec("index.js", b"compiled")}
    pkg_json = {"main": "index.js"}
    result = compare_manifests(src, pub, pkg_json)
    added_entry = next(e for e in result.entries if e["path"] == "index.js")
    assert added_entry["status"] == "EXPECTED_GENERATED"
