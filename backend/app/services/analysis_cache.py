"""Shared analysis cache backed by Supabase (PostgREST over httpx, no extra dependency).

A published package version is immutable, so one finished analysis can answer every later request for the
same (ecosystem, package, version, supplied repository). Entries are keyed with CACHE_ENGINE_VERSION so a
change to the detection rules can retire old verdicts, and ignored once older than CACHE_TTL_SECONDS.

The cache is strictly best-effort: it is off unless configured, only complete analyses are stored, and
every failure (network, auth, bad row) is logged and treated as a miss. It can never fail or slow an
analysis beyond SUPABASE_TIMEOUT. The service key stays on the server; the table has RLS enabled with no
policies (see supabase/schema.sql).
"""
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_LOCAL_FIELDS = ("report_id", "created_at", "cache")


def is_enabled() -> bool:
    if not (settings.SUPABASE_URL and settings.SUPABASE_SERVICE_KEY):
        return False
    parsed = urlparse(settings.SUPABASE_URL)
    # The key is sent on every request, so plain http is only acceptable for a local Supabase stack.
    return parsed.scheme == "https" or (parsed.scheme == "http" and (parsed.hostname or "") in _LOCAL_HOSTS)


def _normalize_name(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name  # PEP 503 for PyPI


def _normalize_repo(url: Optional[str]) -> str:
    if not url:
        return ""
    url = url.strip().lower().rstrip("/")
    return url[:-4] if url.endswith(".git") else url


def make_key(ecosystem: str, name: str, version: str, repository_url: Optional[str]) -> str:
    return "|".join((
        ecosystem.lower(), _normalize_name(ecosystem.lower(), name), version.strip().lower(),
        _normalize_repo(repository_url), settings.CACHE_ENGINE_VERSION,
    ))


def _endpoint() -> str:
    return f"{settings.SUPABASE_URL}/rest/v1/{settings.SUPABASE_TABLE}"


def _headers(**extra: str) -> Dict[str, str]:
    return {
        "apikey": settings.SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        **extra,
    }


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(settings.SUPABASE_TIMEOUT), follow_redirects=False)


def _to_epoch(value: Any) -> float:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


async def lookup(ecosystem: str, name: str, version: str, repository_url: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return {"document": report, "analyzed_at": epoch} for a fresh cached analysis, else None."""
    if not is_enabled():
        return None
    params = {"cache_key": "eq." + make_key(ecosystem, name, version, repository_url), "select": "document,created_at", "limit": "1"}
    if settings.CACHE_TTL_SECONDS > 0:
        oldest = datetime.fromtimestamp(time.time() - settings.CACHE_TTL_SECONDS, tz=timezone.utc)
        params["created_at"] = "gte." + oldest.isoformat()
    try:
        async with _client() as client:
            resp = await client.get(_endpoint(), params=params, headers=_headers())
        if resp.status_code != 200:
            logger.warning("Supabase cache lookup returned HTTP %d" % resp.status_code)
            return None
        rows = resp.json()
        if not rows or not isinstance(rows[0].get("document"), dict):
            return None
        return {"document": rows[0]["document"], "analyzed_at": _to_epoch(rows[0].get("created_at"))}
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Supabase cache lookup failed: %s" % type(exc).__name__)
        return None


async def store(report: Dict[str, Any], repository_url: Optional[str]) -> bool:
    """Upsert a finished analysis. Incomplete analyses (network errors, integrity failures) are never cached."""
    if not is_enabled() or not report.get("analysis_complete"):
        return False
    package = report.get("package") or {}
    ecosystem = str(package.get("ecosystem", "npm")).lower()
    row = {
        "cache_key": make_key(ecosystem, package.get("name", ""), package.get("version", ""), repository_url),
        "ecosystem": ecosystem,
        "package_name": _normalize_name(ecosystem, package.get("name", "")),
        "version": str(package.get("version", "")),
        "repository": _normalize_repo(repository_url),
        "engine_version": settings.CACHE_ENGINE_VERSION,
        "verdict": (report.get("risk") or {}).get("verdict"),
        # Local identifiers belong to this server's history, not to the shared entry.
        "document": {k: v for k, v in report.items() if k not in _LOCAL_FIELDS},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with _client() as client:
            resp = await client.post(
                _endpoint(), params={"on_conflict": "cache_key"}, json=row,
                headers=_headers(Prefer="resolution=merge-duplicates,return=minimal"),
            )
        if resp.status_code not in (200, 201, 204):
            logger.warning("Supabase cache store returned HTTP %d" % resp.status_code)
            return False
        return True
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Supabase cache store failed: %s" % type(exc).__name__)
        return False
