"""Simple in-memory per-IP sliding-window rate limiter for the analysis-starting endpoints.

This is in-memory and per-process: it fits the single-backend-instance deployment this project targets
(see backend/README.md), not a multi-instance/horizontally-scaled one, where each instance would track
its own counts. It is also NOT a security boundary — the client address is best-effort (see `_client_ip`)
and a determined attacker can rotate addresses. It exists only to blunt casual, automatic abuse of
upstream quotas (GitHub, the AI provider, Supabase) once the API is reachable from the internet.
"""
import time
from typing import Dict, Optional, Tuple

from fastapi import Request

from app.config import settings
from app.utils.errors import RateLimitExceededError

WINDOW_SECONDS = 60.0
_STALE_AFTER = WINDOW_SECONDS * 2

# ip -> (window_start, count). Module-level by design: it must be shared across requests, which each
# get their own Request/dependency instance.
_hits: Dict[str, Tuple[float, int]] = {}
_last_cleanup = 0.0


def _client_ip(request: Request) -> str:
    # Trust the first hop of X-Forwarded-For, which every supported deployment target (see
    # backend/README.md) sets from its own reverse proxy rather than passing through client-supplied
    # values uninspected. Falls back to the direct connection when there's no proxy in front (e.g. local
    # dev, or a LAN deployment reached directly).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _cleanup(now: float) -> None:
    global _last_cleanup
    if now - _last_cleanup < WINDOW_SECONDS:
        return
    _last_cleanup = now
    for ip in [ip for ip, (window_start, _) in _hits.items() if now - window_start > _STALE_AFTER]:
        _hits.pop(ip, None)


def enforce_rate_limit(request: Request, _now: Optional[float] = None) -> None:
    """FastAPI dependency: raises RateLimitExceededError once an address exceeds
    settings.RATE_LIMIT_PER_MINUTE requests to this endpoint within a rolling minute. A limit of 0 (or
    negative) disables the check entirely without touching any state."""
    limit = settings.RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return
    now = _now if _now is not None else time.monotonic()
    _cleanup(now)

    ip = _client_ip(request)
    window_start, count = _hits.get(ip, (now, 0))
    if now - window_start >= WINDOW_SECONDS:
        window_start, count = now, 0
    count += 1
    _hits[ip] = (window_start, count)

    if count > limit:
        retry_after = max(1, int(WINDOW_SECONDS - (now - window_start)))
        raise RateLimitExceededError(
            f"Too many analysis requests from this address; try again in about {retry_after}s.",
            retry_after=retry_after,
        )
