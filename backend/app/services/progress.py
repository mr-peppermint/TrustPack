"""In-memory progress registry for analyses started through the frontend contract.

The backend is a single process, so a plain dict guarded by a lock is enough.
Progress records are keyed by analysis id and exposed through JSON endpoints so
the React frontend can render a real determinate progress bar while a package
is analysed instead of a spinning loader.
"""
import threading
import time
import uuid
from typing import Any, Dict, Optional


class AnalysisProgress:
    """Mutable progress record for a single analysis run."""

    def __init__(self, analysis_id: str) -> None:
        self.id = analysis_id
        self.status: str = "queued"  # queued | running | done | failed
        self.percent = 0
        self.stage = "queued"
        self.message = "Queued"
        self.created_at = time.time()
        self.finished_at: Optional[float] = None
        self.error: Optional[str] = None
        self.error_code: Optional[str] = None

    def update(self, percent: int, stage: str, message: str) -> None:
        self.percent = max(0, min(100, percent))
        self.stage = stage
        self.message = message
        if self.status == "queued":
            self.status = "running"

    def mark_done(self) -> None:
        self.status = "done"
        self.percent = 100
        self.stage = "done"
        self.message = "Analysis complete"
        self.finished_at = time.time()

    def mark_failed(self, error: str, error_code: Optional[str] = None) -> None:
        self.status = "failed"
        self.error = error or "Analysis failed"
        self.error_code = error_code
        self.message = self.error
        self.finished_at = time.time()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "percent": self.percent,
            "stage": self.stage,
            "message": self.message,
            "createdAt": self.created_at,
            "finishedAt": self.finished_at,
            "error": self.error,
            "errorCode": self.error_code,
        }


class AnalysisProgressRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: Dict[str, AnalysisProgress] = {}

    def create(self) -> str:
        analysis_id = str(uuid.uuid4())
        with self._lock:
            self._records[analysis_id] = AnalysisProgress(analysis_id)
        return analysis_id

    def get(self, analysis_id: str) -> Optional[AnalysisProgress]:
        with self._lock:
            return self._records.get(analysis_id)

    def snapshot(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        record = self.get(analysis_id)
        return record.snapshot() if record else None


analysis_progress = AnalysisProgressRegistry()
