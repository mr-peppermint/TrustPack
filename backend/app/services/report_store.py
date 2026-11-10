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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.utils.errors import ReportNotFoundError
from app.utils.logging import get_logger

_lock = threading.Lock()
_remote_prune_lock = threading.Lock()
_initialized_path = None
_last_remote_prune = 0.0
_remote_ready: Optional[bool] = None
logger = get_logger(__name__)

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


def durable_history_enabled() -> bool:
    """Whether report history can be mirrored to persistent Supabase storage."""
    if not (settings.SUPABASE_URL and settings.SUPABASE_SERVICE_KEY):
        return False
    parsed = urlparse(settings.SUPABASE_URL)
    return parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})


def history_storage_status() -> str:
    if _remote_ready is True:
        return "supabase"
    if durable_history_enabled():
        return "supabase_configured_unavailable" if _remote_ready is False else "supabase_configured"
    return "local_sqlite"


def check_durable_history() -> bool:
    """Probe the remote table during startup so missing schema/config is visible immediately."""
    global _remote_ready
    if not durable_history_enabled():
        _remote_ready = False
        return False
    try:
        with _remote_client() as client:
            response = client.get(
                _remote_endpoint(), params={"select": "id", "limit": "1"}, headers=_remote_headers(),
            )
        _remote_ready = response.status_code == 200
        if not _remote_ready:
            logger.warning("Durable history table probe returned HTTP %d", response.status_code)
        return _remote_ready
    except httpx.HTTPError as exc:
        _remote_ready = False
        logger.warning("Durable history table probe failed: %s", type(exc).__name__)
        return False


def _remote_endpoint() -> str:
    return f"{settings.SUPABASE_URL}/rest/v1/{settings.SUPABASE_HISTORY_TABLE}"


def _remote_headers(**extra: str) -> Dict[str, str]:
    return {
        "apikey": settings.SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        **extra,
    }


def _remote_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(settings.SUPABASE_TIMEOUT), follow_redirects=False, trust_env=False)


def _persist_remote(report: Dict[str, Any]) -> bool:
    global _remote_ready
    if not durable_history_enabled():
        return False
    package = report.get("package") or {}
    row = {
        "id": report["report_id"],
        "created_at": datetime.fromtimestamp(float(report["created_at"]), tz=timezone.utc).isoformat(),
        "ecosystem": package.get("ecosystem", "npm"),
        "package_name": package.get("name", ""),
        "version": package.get("version", ""),
        "verdict": (report.get("risk") or {}).get("verdict"),
        "document": report,
    }
    try:
        with _remote_client() as client:
            response = client.post(
                _remote_endpoint(), params={"on_conflict": "id"}, json=row,
                headers=_remote_headers(Prefer="resolution=merge-duplicates,return=minimal"),
            )
        if response.status_code not in (200, 201, 204):
            _remote_ready = False
            logger.warning("Durable history write returned HTTP %d", response.status_code)
            return False
        _remote_ready = True
        return True
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        _remote_ready = False
        logger.warning("Durable history write failed: %s", type(exc).__name__)
        return False


def _remote_get(report_id: str) -> Optional[Dict[str, Any]]:
    global _remote_ready
    if not durable_history_enabled():
        return None
    try:
        with _remote_client() as client:
            response = client.get(
                _remote_endpoint(), params={"id": f"eq.{report_id}", "select": "document", "limit": "1"},
                headers=_remote_headers(),
            )
        if response.status_code != 200:
            _remote_ready = False
            logger.warning("Durable history lookup returned HTTP %d", response.status_code)
            return None
        rows = response.json()
        _remote_ready = True
        return rows[0]["document"] if rows and isinstance(rows[0].get("document"), dict) else None
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        _remote_ready = False
        logger.warning("Durable history lookup failed: %s", type(exc).__name__)
        return None


def _remote_list(limit: int) -> Optional[List[Dict[str, Any]]]:
    global _remote_ready
    if not durable_history_enabled():
        return None
    try:
        with _remote_client() as client:
            response = client.get(
                _remote_endpoint(),
                params={"select": "document", "order": "created_at.desc", "limit": str(max(1, limit))},
                headers=_remote_headers(),
            )
        if response.status_code != 200:
            _remote_ready = False
            logger.warning("Durable history list returned HTTP %d", response.status_code)
            return None
        rows = response.json()
        _remote_ready = True
        return [row["document"] for row in rows if isinstance(row.get("document"), dict)]
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        _remote_ready = False
        logger.warning("Durable history list failed: %s", type(exc).__name__)
        return None


def _prune_remote() -> None:
    if not durable_history_enabled():
        return
    try:
        with _remote_client() as client:
            if settings.REPORT_TTL_SECONDS > 0:
                cutoff = datetime.fromtimestamp(time.time() - settings.REPORT_TTL_SECONDS, tz=timezone.utc).isoformat()
                response = client.delete(
                    _remote_endpoint(), params={"created_at": f"lt.{cutoff}"},
                    headers=_remote_headers(Prefer="return=minimal"),
                )
                if response.status_code not in (200, 204):
                    logger.warning("Durable history TTL pruning returned HTTP %d", response.status_code)
            retention = max(1, settings.REPORT_RETENTION_LIMIT)
            response = client.get(
                _remote_endpoint(), params={"select": "id", "order": "created_at.desc", "offset": str(retention), "limit": "10000"},
                headers=_remote_headers(),
            )
            if response.status_code == 200:
                old_ids = [row["id"] for row in response.json() if row.get("id")]
                if old_ids:
                    value = "(" + ",".join('"' + item.replace('"', '\\"') + '"' for item in old_ids) + ")"
                    deleted = client.delete(
                        _remote_endpoint(), params={"id": "in." + value},
                        headers=_remote_headers(Prefer="return=minimal"),
                    )
                    if deleted.status_code not in (200, 204):
                        logger.warning("Durable history retention pruning returned HTTP %d", deleted.status_code)
            else:
                logger.warning("Durable history retention lookup returned HTTP %d", response.status_code)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        logger.warning("Durable history pruning failed: %s", type(exc).__name__)


def _maybe_prune_remote() -> None:
    global _last_remote_prune
    now = time.time()
    with _remote_prune_lock:
        if now - _last_remote_prune < 3600:
            return
        _last_remote_prune = now
    _prune_remote()


def _connect() -> sqlite3.Connection:
    global _initialized_path
    path = settings.DATABASE_PATH
    # "" and ":memory:" give every connection its own throwaway database, so the schema must be
    # created on each one rather than once per path.
    private_db = path in ("", ":memory:")
    if not private_db:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    if private_db or _initialized_path != path:
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
    if _persist_remote(report):
        _maybe_prune_remote()


def get(report_id: str) -> Dict[str, Any]:
    remote = _remote_get(report_id)
    if remote is not None:
        return remote
    with _lock, closing(_connect()) as conn:
        _prune(conn)
        row = conn.execute("SELECT document FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        raise ReportNotFoundError(f"No report found for id '{report_id}'")
    return json.loads(row[0])


def list_recent(limit: int = 100) -> List[Dict[str, Any]]:
    """Newest first. Returns the full report documents (callers project what they need)."""
    remote = _remote_list(limit)
    if remote is not None:
        return remote
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
    if durable_history_enabled():
        try:
            with _remote_client() as client:
                response = client.delete(
                    _remote_endpoint(), params={"id": "not.is.null"},
                    headers=_remote_headers(Prefer="return=minimal"),
                )
            if response.status_code not in (200, 204):
                logger.warning("Durable history clear returned HTTP %d", response.status_code)
        except httpx.HTTPError as exc:
            logger.warning("Durable history clear failed: %s", type(exc).__name__)
