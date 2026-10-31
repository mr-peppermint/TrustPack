"""Shared outbound HTTP helpers with SSRF-safe allow-listing and manual
redirect validation.

httpx's built-in `follow_redirects=True` would happily follow a redirect to
any host, including an attacker-controlled one. Every hop here — the
original request AND every redirect target — is independently validated
(https scheme, allow-listed host, safe resolved IP) before it is requested.
"""
from typing import Iterable, Optional

import httpcore
import httpx

from app.config import settings
from app.utils.errors import DownloadError, UpstreamRateLimitError, UpstreamTimeoutError
from app.utils.logging import get_logger
from app.utils.pinned_transport import SSRFSafeBackend
from app.utils.security import validate_outbound_url

logger = get_logger(__name__)


def make_client(timeout: Optional[httpx.Timeout] = None) -> httpx.AsyncClient:
    """The only way outbound clients are built. DNS results are validated AND pinned at connect time
    (see pinned_transport), environment proxies are ignored (a proxy would resolve names itself and
    bypass the address checks), and redirects are never followed automatically.
    """
    timeout = timeout or httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    transport = httpx.AsyncHTTPTransport(trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(  # swap in the pinned network backend
        ssl_context=httpx.create_ssl_context(trust_env=False),
        max_connections=20,
        max_keepalive_connections=10,
        network_backend=SSRFSafeBackend(),
    )
    return httpx.AsyncClient(transport=transport, timeout=timeout, trust_env=False, follow_redirects=False)


async def _read_capped(resp: httpx.Response, max_bytes: int, url: str) -> bytes:
    declared = resp.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise DownloadError(f"Response exceeds max allowed size ({max_bytes} bytes): {url}")
    chunks = []
    total = 0
    async for chunk in resp.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise DownloadError(f"Response exceeds max allowed size ({max_bytes} bytes): {url}")
        chunks.append(chunk)
    return b"".join(chunks)


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    allowed_hosts: Iterable[str],
    *,
    headers: Optional[dict] = None,
    max_redirects: Optional[int] = None,
) -> httpx.Response:
    """GET with per-hop SSRF validation. Never follows a redirect httpx
    discovers on its own — each Location header is validated before use.
    """
    allowed_hosts = list(allowed_hosts)
    max_redirects = settings.MAX_REDIRECTS if max_redirects is None else max_redirects

    next_url = url
    for _ in range(max_redirects + 1):
        validate_outbound_url(next_url, allowed_hosts)
        async with client.stream("GET", next_url, headers=headers, follow_redirects=False) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    raise DownloadError(f"Redirect response missing Location header for {next_url}")
                next_url = str(httpx.URL(next_url).join(location))
                continue
            if resp.status_code == 429:
                raise UpstreamRateLimitError(f"Rate limited by {next_url}")
            body = await _read_capped(resp, settings.MAX_METADATA_BYTES, next_url)
            # Rebuild a fully-read response (body already decoded, so drop the encoding/length headers).
            headers_out = [(k, v) for k, v in resp.headers.items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
            return httpx.Response(resp.status_code, headers=headers_out, content=body, request=resp.request)
    raise DownloadError(f"Exceeded max redirect count ({max_redirects}) for {url}")


async def safe_stream_download(
    client: httpx.AsyncClient,
    url: str,
    allowed_hosts: Iterable[str],
    *,
    max_size_bytes: int,
    max_redirects: Optional[int] = None,
) -> bytes:
    """Stream a GET body with per-hop SSRF validation and a hard size cap,
    aborting mid-download (not just after) if the cap is exceeded.
    """
    allowed_hosts = list(allowed_hosts)
    max_redirects = settings.MAX_REDIRECTS if max_redirects is None else max_redirects

    next_url = url
    for _ in range(max_redirects + 1):
        validate_outbound_url(next_url, allowed_hosts)
        async with client.stream("GET", next_url, follow_redirects=False) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    raise DownloadError(f"Redirect response missing Location header for {next_url}")
                next_url = str(httpx.URL(next_url).join(location))
                continue
            if resp.status_code == 429:
                raise UpstreamRateLimitError(f"Rate limited while downloading {next_url}")
            if resp.status_code != 200:
                raise DownloadError(f"Download failed with status {resp.status_code} for {next_url}")

            return await _read_capped(resp, max_size_bytes, next_url)
    raise DownloadError(f"Exceeded max redirect count ({max_redirects}) for {url}")


async def request_with_retries(
    client: httpx.AsyncClient,
    url: str,
    allowed_hosts: Iterable[str],
    *,
    headers: Optional[dict] = None,
    max_retries: Optional[int] = None,
) -> httpx.Response:
    max_retries = settings.HTTP_MAX_RETRIES if max_retries is None else max_retries
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return await safe_get(client, url, allowed_hosts, headers=headers)
        except httpx.TimeoutException as exc:
            last_exc = exc
            logger.warning("Request timed out (attempt %d): %s" % (attempt + 1, url))
            continue
        except httpx.TransportError as exc:
            last_exc = exc
            continue
    raise UpstreamTimeoutError(f"Request timed out after retries: {url}") from last_exc
