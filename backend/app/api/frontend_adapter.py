"""Projects stored reports onto the shapes the React frontend already consumes.

The frontend (src/types/analysis.ts) uses camelCase, three risk statuses and string findings. The
backend's own report is richer; this module is a pure, lossy projection of it — it never recomputes
anything, so the verdict the UI shows is always the deterministic one.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List

_STATUS = {"VERIFIED": "verified", "WARNING": "warning", "HIGH_RISK": "high_risk"}
_FILE_RISK = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
_SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def ecosystem_label(ecosystem: str) -> str:
    return "PyPI" if (ecosystem or "").lower() == "pypi" else "npm"


def status_of(report: Dict[str, Any]) -> str:
    verdict = (report.get("risk") or {}).get("verdict")
    return _STATUS.get(verdict, "warning")


def to_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    package = report.get("package") or {}
    return {
        "id": report["report_id"],
        "package": {"name": package.get("name", ""), "ecosystem": ecosystem_label(package.get("ecosystem", "npm")), "version": package.get("version", "")},
        "sourceRepo": (report.get("source") or {}).get("repository") or "",
        "status": status_of(report),
        "createdAt": _iso(report.get("created_at")),
    }


def _finding_line(finding: Dict[str, Any]) -> str:
    where = f"{finding['file']}: " if finding.get("file") else ""
    text = f"{where}{finding.get('evidence') or finding.get('explanation') or finding.get('rule_id')}"
    return text if len(text) <= 300 else text[:299] + "…"


def _ai_text(report: Dict[str, Any]) -> str:
    ai = report.get("ai_explanation") or {}
    content = ai.get("content")
    if ai.get("status") == "ok" and content:
        parts = [content.get("summary", "")]
        actions = content.get("recommended_actions") or []
        if actions:
            parts.append("Next steps: " + " ".join(f"{i}. {a}" for i, a in enumerate(actions, 1)))
        return "\n\n".join(p for p in parts if p)
    reason = {
        "disabled": "AI explanations are turned off for this server.",
        "unavailable": "The AI explanation service was unavailable for this analysis.",
        "invalid_response": "The AI explanation service returned an unusable response.",
    }.get(ai.get("status", "disabled"), "No AI explanation is available.")
    return f"{reason} The findings above come from TrustPack's deterministic checks and are complete without it."


def _file_changes(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in report.get("findings") or []:
        if f.get("file"):
            by_file.setdefault(f["file"], []).append(f)

    files = []
    for entry in report.get("comparison") or []:
        status = entry.get("status")
        if status == "IDENTICAL":
            continue
        change = {"ADDED": "added", "REMOVED": "removed"}.get(status, "modified")
        related = sorted(by_file.get(entry["path"], []), key=lambda f: -_SEVERITY_ORDER.get(f.get("severity"), 0))
        risk = _FILE_RISK.get(related[0]["severity"], "low") if related else {
            "UNEXPLAINED": "medium", "UNCERTAIN": "medium",
        }.get(status, "low")
        reason = entry.get("reason") or (related[0].get("explanation") if related else None)
        item: Dict[str, Any] = {"path": entry["path"], "changeType": change, "risk": risk}
        if reason:
            item["reason"] = reason
        files.append(item)
    files.sort(key=lambda f: (-_RISK_ORDER[f["risk"]], f["path"]))
    return files


def to_result(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = report.get("summary") or {}
    integrity = report.get("integrity") or {}
    source = report.get("source") or {}
    dist = report.get("distribution") or {}
    findings = sorted(report.get("findings") or [], key=lambda f: -_SEVERITY_ORDER.get(f.get("severity"), 0))
    claims = integrity.get("provenance_claims") or {}
    publishers = [p.get("repository") for p in (claims.get("publishers") or []) if p.get("repository")]
    attested = integrity.get("provenance_status") in ("NOT_VERIFIED", "VERIFIED")

    result = to_summary(report)
    result.update({
        "risk": {
            "status": status_of(report),
            "score": int((report.get("risk") or {}).get("score") or 0),
            "findings": [_finding_line(f) for f in findings[:10]],
        },
        "aiExplanation": _ai_text(report),
        "comparison": {
            "added": summary.get("added", 0),
            "removed": summary.get("removed", 0),
            "modified": sum(summary.get(k, 0) for k in ("modified", "expected_generated", "uncertain", "unexplained")),
            "unchanged": summary.get("identical", 0),
        },
        "files": _file_changes(report),
        "provenance": {
            "sourceRepo": source.get("repository") or "",
            "sourceCommit": source.get("commit"),
            # Falls back to analysis time when the registry does not report a publish time (npm).
            "publishedAt": dist.get("published_at") or result["createdAt"],
            "publisher": publishers[0] if publishers else "Not reported by the registry",
            "registryChecksum": dist.get("sha256") or "",
            "signatureVerified": False,  # TrustPack never verifies signature chains; see limitations
            "buildProvenance": bool(attested),
            "attestation": integrity.get("provenance_detail") or "No provenance information is available.",
        },
        "fromCache": bool((report.get("cache") or {}).get("hit")),
    })
    return result
