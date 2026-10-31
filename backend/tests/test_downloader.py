import hashlib
import base64

import httpx
import pytest
import respx

from app.services.npm_registry import DistMetadata
from app.services.package_downloader import download_and_verify_tarball
from app.utils.errors import DownloadError, IntegrityVerificationError, UpstreamTimeoutError


def _integrity_for(data: bytes) -> str:
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


@respx.mock
async def test_download_with_valid_integrity_succeeds(tmp_path):
    data = b"fake tarball bytes"
    respx.get("https://registry.npmjs.org/pkg.tgz").mock(return_value=httpx.Response(200, content=data))
    dist = DistMetadata(tarball="https://registry.npmjs.org/pkg.tgz", integrity=_integrity_for(data))

    result = await download_and_verify_tarball(dist, tmp_path)
    assert result.verified is True
    assert result.path.read_bytes() == data


@respx.mock
async def test_download_with_invalid_integrity_raises(tmp_path):
    data = b"fake tarball bytes"
    respx.get("https://registry.npmjs.org/pkg.tgz").mock(return_value=httpx.Response(200, content=data))
    dist = DistMetadata(tarball="https://registry.npmjs.org/pkg.tgz", integrity=_integrity_for(b"different bytes"))

    with pytest.raises(IntegrityVerificationError):
        await download_and_verify_tarball(dist, tmp_path)


@respx.mock
async def test_download_oversized_tarball_raises(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "MAX_TARBALL_SIZE_BYTES", 10)
    data = b"x" * 1000
    respx.get("https://registry.npmjs.org/pkg.tgz").mock(return_value=httpx.Response(200, content=data))
    dist = DistMetadata(tarball="https://registry.npmjs.org/pkg.tgz", integrity=_integrity_for(data))

    with pytest.raises(DownloadError):
        await download_and_verify_tarball(dist, tmp_path)


@respx.mock
async def test_download_network_timeout_raises(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "HTTP_MAX_RETRIES", 0)
    respx.get("https://registry.npmjs.org/pkg.tgz").mock(side_effect=httpx.TimeoutException("timed out"))
    dist = DistMetadata(tarball="https://registry.npmjs.org/pkg.tgz", integrity=None)

    with pytest.raises(UpstreamTimeoutError):
        await download_and_verify_tarball(dist, tmp_path)
