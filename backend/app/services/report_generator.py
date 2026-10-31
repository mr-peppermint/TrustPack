"""Assembles the final report payload and persists it (see report_store)."""
import time
import uuid
from typing import Any, Dict, List, Optional

from app.services import report_store


def save_report(report: Dict[str, Any]) -> str:
    """Assign an id + timestamp (once) and persist. Re-saving an existing report keeps its id."""
    report.setdefault("report_id", str(uuid.uuid4()))
    report.setdefault("created_at", time.time())
    report_store.save(report)
    return report["report_id"]


def get_report(report_id: str) -> Dict[str, Any]:
    return report_store.get(report_id)


def list_reports(limit: int = 100) -> List[Dict[str, Any]]:
    return report_store.list_recent(limit)


def build_report(
    *,
    package_name: str,
    version: str,
    ecosystem: str = "npm",
    source_repo_url: Optional[str],
    source_commit: Optional[str],
    resolution_method: Optional[str],
    correspondence: str,
    source_directory: Optional[str],
    tarball_verified: Optional[bool],
    verification_algorithm: Optional[str],
    provenance_status: str,
    registry_signature_present: Optional[bool] = None,
    provenance_detail: Optional[str] = None,
    summary: Dict[str, int],
    comparison_entries: list,
    findings: list,
    risk: Dict[str, Any],
    limitations: list,
    analysis_complete: bool,
    source_confidence: Optional[str] = None,
    source_notes: Optional[List[str]] = None,
    distribution: Optional[Dict[str, Any]] = None,
    provenance_claims: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    for i, finding in enumerate(findings, start=1):
        finding.setdefault("id", "finding-%03d" % i)
    return {
        "package": {"name": package_name, "version": version, "ecosystem": ecosystem},
        "source": {
            "repository": source_repo_url,
            "commit": source_commit,
            "resolution_method": resolution_method,
            "correspondence": correspondence,
            "directory": source_directory,
            "confidence": source_confidence,
            "notes": source_notes or [],
        },
        "distribution": distribution,
        "integrity": {
            "tarball_verified": tarball_verified,
            "verification_algorithm": verification_algorithm,
            "provenance_status": provenance_status,
            "registry_signature_present": registry_signature_present,
            "provenance_detail": provenance_detail,
            "provenance_claims": provenance_claims,
        },
        "summary": summary,
        "risk": risk,
        "findings": findings,
        "comparison": comparison_entries[:500],
        "limitations": limitations,
        "analysis_complete": analysis_complete,
        "ai_explanation": {"status": "disabled"},
    }
