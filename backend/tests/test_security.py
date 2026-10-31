import io
import socket
import tarfile

import httpx
import pytest
import respx

from app.utils.errors import ArchiveCorruptionError, ArchiveSecurityError, UnsupportedHostError
from app.utils.http_client import safe_get
from app.utils.security import resolve_safe_addresses, safe_extract_tar_gz, validate_https_url, validate_outbound_url
from tests.conftest import make_malicious_traversal_tar_gz, make_tar_gz


def test_validate_https_url_rejects_non_https():
    with pytest.raises(UnsupportedHostError):
        validate_https_url("http://registry.npmjs.org/pkg.tgz", {"registry.npmjs.org"})


def test_validate_https_url_rejects_disallowed_host():
    with pytest.raises(UnsupportedHostError):
        validate_https_url("https://evil.example.com/pkg.tgz", {"registry.npmjs.org"})


def test_validate_https_url_allows_allowed_host():
    validate_https_url("https://registry.npmjs.org/pkg.tgz", {"registry.npmjs.org"})


def test_safe_extract_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "evil.tgz"
    archive_path.write_bytes(make_malicious_traversal_tar_gz())
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_safe_extract_rejects_absolute_path(tmp_path):
    archive_path = tmp_path / "abs.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"root"))
    archive_path.write_bytes(buf.getvalue())
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_safe_extract_rejects_symlink(tmp_path):
    archive_path = tmp_path / "symlink.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    archive_path.write_bytes(buf.getvalue())
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_safe_extract_rejects_oversized_archive(tmp_path):
    archive_path = tmp_path / "big.tgz"
    archive_path.write_bytes(make_tar_gz({"big.txt": b"x" * 5000}))
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=100, max_single_file_size=100,
        )


def test_safe_extract_rejects_too_many_files(tmp_path):
    archive_path = tmp_path / "many.tgz"
    files = {f"file{i}.txt": b"x" for i in range(10)}
    archive_path.write_bytes(make_tar_gz(files))
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=3, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_safe_extract_handles_corrupted_archive(tmp_path):
    archive_path = tmp_path / "corrupt.tgz"
    archive_path.write_bytes(b"this is not a valid gzip tarball")
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveCorruptionError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_resolve_safe_addresses_rejects_private_ip(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsupportedHostError):
        resolve_safe_addresses("evil.example.com")


def test_resolve_safe_addresses_rejects_loopback(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsupportedHostError):
        resolve_safe_addresses("localhost")


def test_resolve_safe_addresses_rejects_link_local(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsupportedHostError):
        resolve_safe_addresses("metadata.internal")


def test_resolve_safe_addresses_allows_public_ip(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    addrs = resolve_safe_addresses("registry.npmjs.org")
    assert addrs == ["93.184.216.34"]


def test_validate_outbound_url_rejects_rebound_host(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsupportedHostError):
        validate_outbound_url("https://registry.npmjs.org/pkg.tgz", {"registry.npmjs.org"})


@respx.mock
async def test_safe_get_rejects_redirect_to_private_ip(monkeypatch):
    """Even though the redirect Location header points at an allow-listed
    hostname string, if that hostname resolves to a private IP the redirect
    must be rejected rather than followed.
    """
    call_count = {"n": 0}

    def fake_getaddrinfo(host, *args, **kwargs):
        # Simulate DNS rebinding: the first lookup (before the initial
        # request) resolves safely; a later lookup of the SAME hostname
        # (triggered by following the redirect) resolves to a private IP.
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    respx.get("https://registry.npmjs.org/redirecting-pkg/1.0.0").mock(
        return_value=httpx.Response(302, headers={"Location": "https://registry.npmjs.org/-/evil-internal-path"})
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(UnsupportedHostError):
            await safe_get(
                client, "https://registry.npmjs.org/redirecting-pkg/1.0.0", {"registry.npmjs.org"}
            )


def test_safe_extract_rejects_hardlink(tmp_path):
    archive_path = tmp_path / "hardlink.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="hardlink")
        info.type = tarfile.LNKTYPE
        info.linkname = "some_other_file"
        tar.addfile(info)
    archive_path.write_bytes(buf.getvalue())
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
        )


def test_safe_extract_rejects_excessive_nesting_depth(tmp_path):
    archive_path = tmp_path / "deep.tgz"
    deep_path = "/".join(["a"] * 50) + "/file.txt"
    archive_path.write_bytes(make_tar_gz({deep_path: b"x"}))
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
            max_path_depth=10,
        )


def test_safe_extract_rejects_oversized_member_without_decompressing_body(tmp_path):
    """Regression test for the decompression-bomb fix: a single oversized
    member must be rejected based on its declared header size alone, without
    requiring the full (possibly huge) body to be read first.
    """
    archive_path = tmp_path / "bomb.tgz"
    archive_path.write_bytes(make_tar_gz({"huge.bin": b"x" * 100_000}))
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(ArchiveSecurityError):
        safe_extract_tar_gz(
            archive_path, dest,
            max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1000,
        )


def test_safe_extract_succeeds_for_valid_archive(tmp_path):
    archive_path = tmp_path / "ok.tgz"
    archive_path.write_bytes(make_tar_gz({"a.txt": b"hello", "sub/b.txt": b"world"}, root_dir="package"))
    dest = tmp_path / "dest"
    dest.mkdir()

    count = safe_extract_tar_gz(
        archive_path, dest,
        max_file_count=1000, max_total_size=10_000_000, max_single_file_size=1_000_000,
    )
    assert count == 2
    assert (dest / "package" / "a.txt").read_text() == "hello"
    assert (dest / "package" / "sub" / "b.txt").read_text() == "world"


# ======================================================================================
# Hardening added with PyPI support: zip/wheel extraction, URL rules, DNS pinning, caps
# ======================================================================================
import asyncio
import os
import stat
import zipfile

import app.utils.pinned_transport as pinned
from app.utils.errors import DownloadError
from app.utils.security import safe_extract_zip
from tests.conftest import make_zip

_ZIP_LIMITS = dict(max_file_count=100, max_total_size=1_000_000, max_single_file_size=500_000)


def _extract_zip(tmp_path, blob, **overrides):
    archive = tmp_path / "a.zip"
    archive.write_bytes(blob)
    dest = tmp_path / "out"
    dest.mkdir(exist_ok=True)
    return safe_extract_zip(archive, dest, **{**_ZIP_LIMITS, **overrides}), dest


@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "C:/Windows/evil.txt", "a\\..\\evil.txt"])
def test_zip_rejects_traversal_absolute_and_backslash_paths(tmp_path, name):
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({name: b"x"}))
    assert not (tmp_path / "evil.txt").exists()


def test_zip_rejects_symlink_and_special_files(tmp_path):
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({"link": b"/etc/passwd"}, modes={"link": stat.S_IFLNK | 0o777}))
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({"fifo": b""}, modes={"fifo": stat.S_IFIFO | 0o644}))


def test_zip_rejects_duplicate_entries(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("same.txt", b"first")
        with pytest.warns(UserWarning):
            zf.writestr("same.txt", b"second")
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, buf.getvalue())


def test_zip_enforces_size_count_and_depth_limits(tmp_path):
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({"big.bin": b"x" * 2000}), max_single_file_size=1000)
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({"a.bin": b"x" * 600, "b.bin": b"x" * 600}), max_total_size=1000)
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({f"f{i}": b"x" for i in range(10)}), max_file_count=5)
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, make_zip({"/".join(["d"] * 40) + "/f": b"x"}), max_path_depth=10)


def test_zip_rejects_decompression_bomb_by_ratio_without_writing_it(tmp_path):
    blob = make_zip({"zeros.bin": b"\0" * (30 * 1024 * 1024)})  # compresses ~1000:1
    assert len(blob) < 100_000
    with pytest.raises(ArchiveSecurityError):
        _extract_zip(tmp_path, blob, max_single_file_size=50 * 1024 * 1024, max_total_size=50 * 1024 * 1024, max_compression_ratio=200)
    assert not (tmp_path / "out" / "zeros.bin").exists()


def test_zip_corrupted_and_non_zip_inputs_are_corruption_errors(tmp_path):
    with pytest.raises(ArchiveCorruptionError):
        _extract_zip(tmp_path, b"PK\x03\x04 definitely not a real zip")


def test_zip_extracts_valid_wheel_and_keeps_only_safe_permissions(tmp_path):
    blob = make_zip({"pkg/run.py": b"print(1)", "pkg/tool": b"#!/bin/sh\n"}, modes={"pkg/tool": 0o104755})  # setuid + exec
    count, dest = _extract_zip(tmp_path, blob)
    assert count == 2
    mode = os.stat(dest / "pkg" / "tool").st_mode
    assert mode & stat.S_IXUSR and not mode & stat.S_ISUID


def test_tar_extraction_drops_setuid_bits(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("tool")
        info.size, info.mode = 3, 0o4755
        tar.addfile(info, io.BytesIO(b"abc"))
    archive = tmp_path / "t.tgz"
    archive.write_bytes(buf.getvalue())
    dest = tmp_path / "o"
    dest.mkdir()
    safe_extract_tar_gz(archive, dest, max_file_count=10, max_total_size=1000, max_single_file_size=1000)
    mode = os.stat(dest / "tool").st_mode
    assert mode & stat.S_IXUSR and not mode & stat.S_ISUID


def test_archive_format_is_detected_from_content_not_filename(tmp_path):
    from app.services.archive_extractor import detect_format, extract_archive

    sneaky = tmp_path / "package.tgz"  # named like a tarball, actually a zip
    sneaky.write_bytes(make_zip({"a.txt": b"x"}))
    assert detect_format(sneaky) == "zip"
    assert (extract_archive(sneaky, tmp_path / "o1") / "a.txt").exists() or (tmp_path / "o1" / "a.txt").exists()
    junk = tmp_path / "x.zip"
    junk.write_bytes(b"not an archive")
    with pytest.raises(ArchiveCorruptionError):
        extract_archive(junk, tmp_path / "o2")


def test_validate_https_url_rejects_ports_and_credentials():
    for url in ("https://registry.npmjs.org:8443/x", "https://user:pw@registry.npmjs.org/x", "https://user@registry.npmjs.org/x"):
        with pytest.raises(UnsupportedHostError):
            validate_https_url(url, {"registry.npmjs.org"})
    validate_https_url("https://registry.npmjs.org:443/x", {"registry.npmjs.org"})


def test_lookalike_hosts_are_not_allowed():
    for url in ("https://registry.npmjs.org.evil.com/x", "https://evilregistry.npmjs.org/x", "https://github.com.evil.io/a/b"):
        with pytest.raises(UnsupportedHostError):
            validate_https_url(url, {"registry.npmjs.org", "github.com"})


@respx.mock
async def test_redirect_to_a_non_allow_listed_host_is_refused():
    respx.get("https://pypi.org/pypi/x/1/json").mock(return_value=httpx.Response(302, headers={"Location": "https://evil.example/steal"}))
    async with httpx.AsyncClient() as client:
        with pytest.raises(UnsupportedHostError):
            await safe_get(client, "https://pypi.org/pypi/x/1/json", {"pypi.org"})


@respx.mock
async def test_metadata_responses_are_size_capped(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "MAX_METADATA_BYTES", 100)
    respx.get("https://pypi.org/pypi/big/1/json").mock(return_value=httpx.Response(200, content=b"x" * 1000))
    async with httpx.AsyncClient() as client:
        with pytest.raises(DownloadError):
            await safe_get(client, "https://pypi.org/pypi/big/1/json", {"pypi.org"})


class _RecordingBackend:
    def __init__(self):
        self.connected_to = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connected_to.append(host)
        return object()

    async def sleep(self, seconds):
        pass


async def test_pinned_backend_connects_to_the_validated_ip_not_the_hostname():
    inner = _RecordingBackend()
    await pinned.SSRFSafeBackend(inner).connect_tcp("registry.npmjs.org", 443)
    assert inner.connected_to == ["93.184.216.34"]  # conftest resolves every name to this public address


async def test_pinned_backend_blocks_a_host_that_resolves_to_a_private_address(monkeypatch):
    def rebound(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", rebound)
    inner = _RecordingBackend()
    with pytest.raises(UnsupportedHostError):
        await pinned.SSRFSafeBackend(inner).connect_tcp("registry.npmjs.org", 443)
    assert inner.connected_to == []  # no socket was ever opened


async def test_pinned_backend_validates_every_address_of_a_multi_record_answer(monkeypatch):
    def mixed(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", mixed)
    with pytest.raises(UnsupportedHostError):
        await pinned.SSRFSafeBackend(_RecordingBackend()).connect_tcp("registry.npmjs.org", 443)


def test_outbound_client_uses_the_pinned_backend_and_ignores_proxy_env(monkeypatch):
    from app.utils.http_client import make_client

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    client = make_client()
    pool = client._transport._pool
    assert isinstance(pool._network_backend, pinned.SSRFSafeBackend)
    assert client.follow_redirects is False and client.trust_env is False


async def test_temp_directories_are_removed_on_success_and_on_failure(monkeypatch, tmp_path):
    import tempfile
    from app.services import orchestrator

    created = []
    real = tempfile.mkdtemp

    def tracking(*a, **kw):
        d = real(*a, **kw)
        created.append(d)
        return d

    monkeypatch.setattr(tempfile, "mkdtemp", tracking)

    class Boom(Exception):
        pass

    async def explode(*a, **kw):
        raise Boom()

    from app.registries import npm_registry as npm_adapter
    monkeypatch.setattr(npm_adapter.NpmRegistry, "fetch_release", explode)
    with pytest.raises(Boom):
        await orchestrator.analyze_package("anything", "1.0.0")
    assert created and not any(os.path.exists(d) for d in created)
