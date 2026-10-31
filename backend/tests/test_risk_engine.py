from app.services import risk_engine


def test_no_findings_with_exact_correspondence_is_low_risk():
    risk = risk_engine.compute_risk([], tarball_verified=True, correspondence="EXACT")
    assert risk["level"] == "LOW"
    assert risk["score"] == 0


def test_failed_integrity_forces_at_least_high():
    risk = risk_engine.compute_risk([], tarball_verified=False, correspondence="NONE")
    assert risk["level"] == "HIGH"


def test_failed_integrity_with_high_finding_is_critical():
    findings = [{"severity": "HIGH", "confidence": "HIGH", "category": "x",
                 "evidence": "e", "explanation": "x", "recommendation": "x"}]
    risk = risk_engine.compute_risk(findings, tarball_verified=False, correspondence="NONE")
    assert risk["level"] == "CRITICAL"


def test_unresolved_correspondence_without_findings_is_inconclusive():
    risk = risk_engine.compute_risk([], tarball_verified=True, correspondence="NONE")
    assert risk["level"] == "INCONCLUSIVE"


def test_unresolved_correspondence_with_high_finding_still_surfaces_it():
    findings = [{"severity": "HIGH", "confidence": "HIGH", "category": "lifecycle_script",
                 "evidence": "e", "explanation": "x", "recommendation": "x"}]
    risk = risk_engine.compute_risk(findings, tarball_verified=True, correspondence="NONE")
    assert risk["level"] in ("HIGH", "CRITICAL")


def test_critical_finding_forces_critical_level():
    findings = [{"severity": "CRITICAL", "confidence": "HIGH", "category": "x",
                 "evidence": "e", "explanation": "x", "recommendation": "x"}]
    risk = risk_engine.compute_risk(findings, tarball_verified=True, correspondence="EXACT")
    assert risk["level"] == "CRITICAL"


def test_build_unexplained_findings_flags_executable_as_high():
    from app.services.manifest_generator import FileRecord
    manifest = {"script.js": FileRecord(path="script.js", size=1, sha256="a", extension=".js",
                                         category="javascript", is_executable=True)}
    entries = [{"path": "script.js", "status": "UNEXPLAINED", "source_sha256": "a", "published_sha256": "b",
                "source_size": 1, "published_size": 1}]
    findings = risk_engine.build_unexplained_findings(entries, manifest)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
