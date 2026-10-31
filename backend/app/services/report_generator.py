"""Assembles the final report payload and maintains a bounded, time-expiring
in-memory report store.

A database is intentionally avoided for this hackathon MVP (see README).
Reports expire after REPORT_TTL_SECONDS and are also capped at
REPORT_RETENTION_LIMIT entries (oldest evicted first) to bound memory use
even under a burst of requests within the TTL window.
"""
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, Optional

from app.config import settings
from app.utils.errors import ReportNotFoundError

_lock = threading.Lock()
_store: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_expires_at: Dict[str, float] = {}


def _purge_expired_locked() -> None:
    now = time.time()
    expired_ids = [rid for rid, exp in _expires_at.items() if exp <= now]
    for rid in expired_ids:
        _store.pop(rid, None)
        _expires_at.pop(rid, None)


def save_report(report: Dict[str, Any]) -> str:
    report_id = str(uuid.uuid4())
    report["report_id"] = report_id
    with _lock:
        _purge_expired_locked()
        _store[report_id] = report
        _expires_at[report_id] = time.time() + settings.REPORT_TTL_SECONDS
        while len(_store) > settings.REPORT_RETENTION_LIMIT:
            oldest_id, _ = _store.popitem(last=False)
            _expires_at.pop(oldest_id, None)
    return report_id


def get_report(report_id: str) -> Dict[str, Any]:
    with _lock:
        _purge_expired_locked()
        report = _store.get(report_id)
    if report is None:
        raise ReportNotFoundError(f"No report found for id '{report_id}' (it may have expired)")
    return report


def build_report(
    *,
    package_name: str,
    version: str,
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
) -> Dict[str, Any]:
    return {
        "package": {"name": package_name, "version": version},
        "source": {
            "repository": source_repo_url,
            "commit": source_commit,
            "resolution_method": resolution_method,
            "correspondence": correspondence,
            "directory": source_directory,
        },
        "integrity": {
            "tarball_verified": tarball_verified,
            "verification_algorithm": verification_algorithm,
            "provenance_status": provenance_status,
            "registry_signature_present": registry_signature_present,
            "provenance_detail": provenance_detail,
        },
        "summary": summary,
        "risk": risk,
        "findings": findings,
        "comparison": comparison_entries[:500],
        "limitations": limitations,
        "analysis_complete": analysis_complete,
    }
