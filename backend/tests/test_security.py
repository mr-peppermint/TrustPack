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
