"""Explainable, rule-based risk scoring.

Design principles (see README "Security Limitations" for full rationale):
- A package is never labeled malicious; only "risk level" with explicit evidence.
- Missing source correspondence forces INCONCLUSIVE unless independent
  (script/pattern) findings are themselves severe enough to warrant attention.
- A failed tarball integrity check always floors the result at HIGH — this
  reflects that the analyzed bytes cannot be trusted to match the registry
  record, NOT a verdict that the content is malicious. Integrity status and
  security risk are reported as separate fields for exactly this reason.
- Missing evidence never increases the score: findings are only ever added
  for observed, concrete signals, and the absence of a signal contributes
  nothing (not a penalty, not a bonus).
- Findings are deduplicated by (file, rule_id) before scoring so one piece
  of evidence is never counted twice toward the total.
"""
from typing import Any, Dict, List, Optional

_SEVERITY_WEIGHT = {"LOW": 3, "MEDIUM": 8, "HIGH": 20, "CRITICAL": 40}


def build_unexplained_findings(
    comparison_entries: List[Dict[str, Any]],
    published_manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings = []
    for entry in comparison_entries:
        if entry["status"] != "UNEXPLAINED":
            continue
        record = published_manifest.get(entry["path"])
        is_risky_type = bool(record) and (
            record.is_executable or record.category in ("javascript", "typescript", "script")
        )
        severity = "HIGH" if is_risky_type else "MEDIUM"
        findings.append({
            "rule_id": "UNEXPLAINED_SOURCE_DIFF",
            "file": entry["path"],
            "category": "unexplained_file_difference",
            "severity": severity,
            "confidence": "MEDIUM",
            "evidence": (
                f"File content differs between source and published package and does not "
                "match any recognized build-generated pattern "
                f"(source_sha256={entry['source_sha256']}, published_sha256={entry['published_sha256']})."
            ),
            "explanation": (
                "A source-like file that differs between the repository and the published "
                "tarball, without a known build explanation, warrants manual review."
            ),
            "recommendation": f"Diff {entry['path']} between the resolved source commit and the published tarball.",
        })
    return findings


def build_unexpected_executable_findings(
    comparison_entries: List[Dict[str, Any]],
    published_manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Flag executable files that exist only in the published tarball (status
    ADDED) — distinct from build-generated executables (EXPECTED_GENERATED,
    which is never flagged here) and from UNEXPLAINED (already covered by
    build_unexplained_findings for files present on both sides).
    """
    findings = []
    for entry in comparison_entries:
        if entry["status"] != "ADDED":
            continue
        record = published_manifest.get(entry["path"])
        if not record or not record.is_executable:
            continue
        findings.append({
            "rule_id": "UNEXPECTED_EXECUTABLE_FILE",
            "file": entry["path"],
            "category": "unexpected_executable_file",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "evidence": (
                f"{entry['path']} is executable (execute bit or shebang) and exists only in "
                "the published package, not in the resolved source."
            ),
            "explanation": (
                "An executable file with no corresponding source-repository counterpart was "
                "introduced at publish time and was never visible in the public source history."
            ),
            "recommendation": f"Manually inspect {entry['path']} before running anything that depends on this package.",
        })
    return findings


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep at most one finding per (file, rule_id) pair, preferring the
    highest-severity instance, so the same evidence is never counted twice.
    """
    best: Dict[Any, Dict[str, Any]] = {}
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for finding in findings:
        key = (finding.get("file"), finding.get("rule_id") or finding.get("category"))
        existing = best.get(key)
        if existing is None or order.get(finding["severity"], 0) > order.get(existing["severity"], 0):
            best[key] = finding
    return list(best.values())


def compute_risk(
    findings: List[Dict[str, Any]],
    *,
    tarball_verified: Optional[bool],
    correspondence: str,
) -> Dict[str, Any]:
    findings = _dedupe_findings(findings)
    rationale: List[str] = []
    severities = [f["severity"] for f in findings]
    has_critical = "CRITICAL" in severities
    has_high = "HIGH" in severities
    score = min(100, sum(_SEVERITY_WEIGHT.get(s, 0) for s in severities))

    if tarball_verified is False:
        level = "CRITICAL" if (has_critical or has_high) else "HIGH"
        rationale.append(
            "Tarball integrity check failed against the registry-published digest; "
            "analyzed content cannot be trusted to match the registry record. This "
            "reflects an inability to trust the downloaded bytes, not a confirmed "
            "finding of malicious modification."
        )
        return {"level": level, "score": score, "rationale": rationale}

    if correspondence == "NONE" and not has_critical and not has_high:
        rationale.append(
            "Source correspondence could not be established (no matching gitHead or tag), "
            "so a comparison-based verdict would be misleading. Independent script/pattern "
            "findings, if any, were still evaluated. The absence of comparison evidence does "
            "not itself raise the score."
        )
        return {"level": "INCONCLUSIVE", "score": score if findings else None, "rationale": rationale}

    if has_critical or score >= 60:
        level = "CRITICAL"
    elif has_high or score >= 30:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    rationale.append(f"Derived from {len(findings)} deduplicated, evidence-based finding(s), weighted score={score}.")
    if correspondence == "INFERRED":
        rationale.append("Source match is inferred from a version tag, not a cryptographically exact gitHead commit.")
    return {"level": level, "score": score, "rationale": rationale}
