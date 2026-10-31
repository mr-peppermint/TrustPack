"""Persistent analysis history backed by SQLite (standard library, no extra dependency).

Each report is stored as a JSON document next to the few columns the history
list needs. Writes are serialized with a lock and use short-lived connections,
so the store is safe to use from FastAPI's request handlers and worker threads.
Reports older than REPORT_TTL_SECONDS (when non-zero) and anything beyond
REPORT_RETENTION_LIMIT (oldest first) are pruned on every save.
"""
import json
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List

from app.config import settings
from app.utils.errors import ReportNotFoundError

_lock = threading.Lock()
_initialized_path = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    ecosystem    TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    verdict      TEXT,
    document     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports (created_at DESC);
"""


def _connect() -> sqlite3.Connection:
    global _initialized_path
    path = settings.DATABASE_PATH
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    if _initialized_path != path:
        conn.executescript(_SCHEMA)
        conn.commit()
        _initialized_path = path
    return conn


def _prune(conn: sqlite3.Connection) -> None:
    if settings.REPORT_TTL_SECONDS > 0:
        conn.execute("DELETE FROM reports WHERE created_at < ?", (time.time() - settings.REPORT_TTL_SECONDS,))
    conn.execute(
        "DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY created_at DESC, rowid DESC LIMIT ?)",
        (max(1, settings.REPORT_RETENTION_LIMIT),),
    )


def save(report: Dict[str, Any]) -> None:
    """Insert or replace a report (it must already carry report_id and created_at)."""
    package = report.get("package") or {}
    verdict = (report.get("risk") or {}).get("verdict")
    with _lock, closing(_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO reports (id, created_at, ecosystem, package_name, version, verdict, document) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                report["report_id"], report["created_at"], package.get("ecosystem", "npm"),
                package.get("name", ""), package.get("version", ""), verdict, json.dumps(report),
            ),
        )
        _prune(conn)
        conn.commit()


def get(report_id: str) -> Dict[str, Any]:
    with _lock, closing(_connect()) as conn:
        _prune(conn)
        row = conn.execute("SELECT document FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        raise ReportNotFoundError(f"No report found for id '{report_id}'")
    return json.loads(row[0])


def list_recent(limit: int = 100) -> List[Dict[str, Any]]:
    """Newest first. Returns the full report documents (callers project what they need)."""
    with _lock, closing(_connect()) as conn:
        _prune(conn)
        rows = conn.execute(
            "SELECT document FROM reports ORDER BY created_at DESC, rowid DESC LIMIT ?", (max(1, limit),)
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


def clear() -> None:
    with _lock, closing(_connect()) as conn:
        conn.execute("DELETE FROM reports")
        conn.commit()
