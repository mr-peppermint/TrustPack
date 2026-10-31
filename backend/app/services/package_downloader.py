"""Downloads the published npm tarball and verifies it against registry integrity metadata."""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from app.config import settings
from app.services.npm_registry import DistMetadata
from app.utils.errors import IntegrityVerificationError, UpstreamTimeoutError
from app.utils.hashing import verify_integrity
from app.utils.http_client import make_client, safe_stream_download
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DownloadResult:
    path: Path
    size: int
    verified: Optional[bool]
    algorithm: Optional[str]


async def download_and_verify_tarball(dist: DistMetadata, dest_dir: Path) -> DownloadResult:
    dest_path = dest_dir / "package.tgz"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)

    last_exc: Optional[Exception] = None
    data: Optional[bytes] = None
    async with make_client(timeout) as client:
        for attempt in range(settings.HTTP_MAX_RETRIES + 1):
            try:
                data = await safe_stream_download(
                    client, dist.tarball, settings.ALLOWED_TARBALL_HOSTS,
                    max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES,
                )
                break
            except httpx.TimeoutException as exc:
                last_exc = exc
                continue
            except httpx.TransportError as exc:
                last_exc = exc
                continue

    if data is None:
        raise UpstreamTimeoutError("Tarball download timed out after retries") from last_exc

    verification = verify_integrity(data, dist.integrity, dist.shasum)
    if verification["verified"] is False:
        raise IntegrityVerificationError(
            "Tarball integrity check failed: downloaded content does not match "
            f"registry-published {verification['algorithm']} digest"
        )

    dest_path.write_bytes(data)
    return DownloadResult(
        path=dest_path,
        size=len(data),
        verified=verification["verified"],
        algorithm=verification["algorithm"],
    )
