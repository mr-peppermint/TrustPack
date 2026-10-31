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
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional

from app.services.suspicious_code import find_suspicious_content

_SEVERITY_WEIGHT = {"LOW": 3, "MEDIUM": 8, "HIGH": 20, "CRITICAL": 40}
_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Files whose content decides what runs at install/import time. A difference in one of these matters
# more than a difference in, say, a README.
SECURITY_SENSITIVE_NAMES = {
    "setup.py", "setup.cfg", "pyproject.toml", "manifest.in", "conftest.py", "sitecustomize.py",
    "usercustomize.py", "__main__.py", "install.js", "preinstall.js", "postinstall.js", "binding.gyp",
    ".npmrc", "dockerfile",
}
_CODE_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pyx", ".sh", ".bash", ".bat", ".cmd", ".ps1", ".rb", ".pl", ".php", ".c", ".cpp", ".node", ".so", ".dll", ".dylib", ".pyd"}
_INSTALL_PATH_HINTS = ("scripts/", "bin/", "install", "postinstall", "preinstall", "setup")
_MAX_INDIVIDUAL_FINDINGS = 25


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
        name = PurePosixPath(entry["path"]).name.lower()
        security_manifest_change = str(entry.get("reason") or "").startswith("security-relevant package.json")
        severity = "HIGH" if (is_risky_type or name in SECURITY_SENSITIVE_NAMES or security_manifest_change) else "MEDIUM"
        findings.append({
            "rule_id": "UNEXPLAINED_SOURCE_DIFF",
            "file": entry["path"],
            "category": "unexplained_file_difference",
            "severity": severity,
            "confidence": "MEDIUM",
            "evidence": (
                f"File content differs between source and published package and is not explained as "
                "build output "
                f"(source_sha256={entry['source_sha256']}, published_sha256={entry['published_sha256']})."
                + (f" {entry['reason']}." if entry.get("reason") else "")
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


def _finding(rule_id, file, category, severity, confidence, evidence, explanation, recommendation):
    return {
        "rule_id": rule_id, "file": file, "category": category, "severity": severity,
        "confidence": confidence, "evidence": evidence, "explanation": explanation,
        "recommendation": recommendation,
    }


def _aggregate(rule_id: str, category: str, severity: str, paths: List[str], what: str, explanation: str, recommendation: str):
    shown = ", ".join(paths[:10]) + (f" and {len(paths) - 10} more" if len(paths) > 10 else "")
    return _finding(rule_id, None, category, severity, "MEDIUM", f"{len(paths)} {what}: {shown}.", explanation, recommendation)


def build_added_file_findings(
    comparison_entries: List[Dict[str, Any]], published_manifest: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Files that exist only in the published artifact (status ADDED). They were never visible in the
    repository history, so each is reported: code or install-time files individually, harmless-looking
    ones (docs, data) grouped into one low-severity finding. Executables are handled by
    build_unexpected_executable_findings and skipped here to avoid double counting.
    """
    individual: List[Dict[str, Any]] = []
    low_paths: List[str] = []
    for entry in comparison_entries:
        if entry["status"] != "ADDED":
            continue
        path = entry["path"]
        record = published_manifest.get(path)
        if record is not None and record.is_executable:
            continue
        lower = path.lower()
        ext = PurePosixPath(lower).suffix
        if lower.endswith(".pth") or any(h in lower for h in _INSTALL_PATH_HINTS) and ext in _CODE_EXTS:
            severity = "HIGH"
        elif ext in _CODE_EXTS:
            severity = "MEDIUM"
        else:
            low_paths.append(path)
            continue
        individual.append(_finding(
            "ADDED_FILE_NOT_IN_SOURCE", path, "added_file_not_in_source", severity, "MEDIUM",
            f"{path} exists in the published artifact but not in the resolved source repository.",
            "A code or install-time file that is absent from the repository was introduced at publish time and "
            "was never reviewable in the public history.",
            f"Inspect {path} and ask the maintainers why it is not in the repository.",
        ))
    findings = individual[:_MAX_INDIVIDUAL_FINDINGS]
    overflow = [f["file"] for f in individual[_MAX_INDIVIDUAL_FINDINGS:]]
    if overflow:
        findings.append(_aggregate(
            "ADDED_FILES_NOT_IN_SOURCE_MORE", "added_file_not_in_source", "MEDIUM", overflow,
            "additional code files absent from the repository", "More code files were added at publish time.",
            "Review the listed files.",
        ))
    if low_paths:
        findings.append(_aggregate(
            "ADDED_NON_CODE_FILES_NOT_IN_SOURCE", "added_file_not_in_source", "LOW", low_paths,
            "non-code files absent from the repository",
            "Documentation, data or metadata files exist only in the published artifact. This is common "
            "(license copies, generated metadata) and low risk on its own.",
            "Skim the list for anything unexpected.",
        ))
    return findings


def build_uncertain_findings(comparison_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Files that look like build output but could not be tied to the source. They are NOT treated as safe:
    each contributes (a small) risk and lowers the confidence of the verdict. Entries flagged for suspicious
    content are reported by build_suspicious_content_findings instead, so evidence is never counted twice.
    """
    paths = [
        e["path"] for e in comparison_entries
        if e["status"] == "UNCERTAIN" and not any(str(x).startswith("suspicious content") for x in e.get("evidence", []))
    ]
    if not paths:
        return []
    return [_aggregate(
        "GENERATED_FILE_UNVERIFIED", "uncertain_generated_file", "LOW" if len(paths) < 5 else "MEDIUM", paths,
        "files resemble build output but could not be tied to the repository source",
        "Their location or name looks like build output, but no source file, source map or build configuration "
        "supports that, or they are compiled and cannot be compared. They are not assumed to be safe.",
        "Rebuild the package from the tagged source and compare, or review these files directly.",
    )]


def build_suspicious_content_findings(
    comparison_entries: List[Dict[str, Any]], published_root: Optional[Path]
) -> List[Dict[str, Any]]:
    """Scan only files that differ from (or are absent in) the source: the same text in a file identical to
    the public repository is not a tampering signal. Location does not matter — dist/ is scanned like any
    other directory."""
    if published_root is None:
        return []
    findings: List[Dict[str, Any]] = []
    for entry in comparison_entries:
        if entry["status"] not in ("ADDED", "MODIFIED", "UNEXPLAINED", "UNCERTAIN", "EXPECTED_GENERATED"):
            continue
        path = entry["path"]
        if PurePosixPath(path.lower()).suffix not in _CODE_EXTS:
            continue
        try:
            with open(published_root / path, "rb") as fh:
                text = fh.read(2_000_000).decode("utf-8", errors="ignore")
        except OSError:
            continue
        reasons = find_suspicious_content(path, text)
        if reasons:
            findings.append(_finding(
                "SUSPICIOUS_CONTENT_IN_CHANGED_FILE", path, "suspicious_content", "HIGH", "MEDIUM",
                f"{path} ({entry['status']}) " + "; ".join(reasons) + ".",
                "Obfuscation and dynamic code decoding in a file that differs from the repository are common in "
                "malicious packages, though some legitimate bundles show them too.",
                f"Read {path} in full; deobfuscate or diff it against the repository before trusting this release.",
            ))
            if len(findings) >= _MAX_INDIVIDUAL_FINDINGS:
                break
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


def _confidence(
    *,
    correspondence: str,
    tarball_verified: Optional[bool],
    source_confidence: Optional[str],
    uncertain_count: int,
    changed_count: int,
    analysis_complete: bool,
) -> str:
    """How much to trust the verdict itself (not how risky the package is)."""
    if not analysis_complete or correspondence == "NONE" or tarball_verified is False:
        return "LOW"
    level = 2  # 2=HIGH 1=MEDIUM 0=LOW
    if correspondence == "INFERRED":
        level = min(level, 1)
    if source_confidence == "LOW":
        level = 0
    elif source_confidence == "MEDIUM":
        level = min(level, 1)
    if tarball_verified is None:
        level = min(level, 1)
    if uncertain_count:
        level = min(level, 1)
        if changed_count and uncertain_count / changed_count >= 0.25:
            level = 0
    return ("LOW", "MEDIUM", "HIGH")[level]


def _verdict(level: str, *, correspondence: str, tarball_verified: Optional[bool], uncertain_count: int) -> str:
    if tarball_verified is False or level in ("HIGH", "CRITICAL"):
        return "HIGH_RISK"
    if level in ("MEDIUM", "INCONCLUSIVE") or correspondence == "NONE" or tarball_verified is None or uncertain_count:
        return "WARNING"
    return "VERIFIED"


def compute_risk(
    findings: List[Dict[str, Any]],
    *,
    tarball_verified: Optional[bool],
    correspondence: str,
    source_confidence: Optional[str] = None,
    uncertain_count: int = 0,
    changed_count: int = 0,
    analysis_complete: bool = True,
) -> Dict[str, Any]:
    findings = _dedupe_findings(findings)
    rationale: List[str] = []
    severities = [f["severity"] for f in findings]
    has_critical = "CRITICAL" in severities
    has_high = "HIGH" in severities
    score = min(100, sum(_SEVERITY_WEIGHT.get(s, 0) for s in severities))

    def result(level: str, score_value, rationale_lines: List[str]) -> Dict[str, Any]:
        return {
            "level": level, "score": score_value, "rationale": rationale_lines,
            "verdict": _verdict(level, correspondence=correspondence, tarball_verified=tarball_verified, uncertain_count=uncertain_count),
            "confidence": _confidence(
                correspondence=correspondence, tarball_verified=tarball_verified, source_confidence=source_confidence,
                uncertain_count=uncertain_count, changed_count=changed_count, analysis_complete=analysis_complete,
            ),
        }

    if tarball_verified is False:
        level = "CRITICAL" if (has_critical or has_high) else "HIGH"
        rationale.append(
            "Tarball integrity check failed against the registry-published digest; "
            "analyzed content cannot be trusted to match the registry record. This "
            "reflects an inability to trust the downloaded bytes, not a confirmed "
            "finding of malicious modification."
        )
        return result(level, score, rationale)

    if correspondence == "NONE" and not has_critical and not has_high:
        rationale.append(
            "Source correspondence could not be established (no matching gitHead or tag), "
            "so a comparison-based verdict would be misleading. Independent script/pattern "
            "findings, if any, were still evaluated. The absence of comparison evidence does "
            "not itself raise the score."
        )
        return result("INCONCLUSIVE", score if findings else None, rationale)

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
    if uncertain_count:
        rationale.append(
            f"{uncertain_count} file(s) resemble build output but could not be tied to the source; they are "
            "treated as unverified, not as safe."
        )
    rationale.append("Absence of findings is not proof of safety; see the limitations.")
    return result(level, score, rationale)
