"""Security-critical helpers: URL/SSRF allow-listing and safe tar extraction.

Downloaded archives are treated as fully untrusted input. Extraction never
executes code, never follows symlinks out of the sandbox, and is bounded by
strict size/count/depth limits to prevent path traversal, symlink escape,
and decompression-bomb style resource exhaustion.

Outbound HTTP targets are treated as untrusted too: host allow-listing alone
is not sufficient defense against SSRF (DNS rebinding can point an allowed
hostname at a private IP at request time), so every resolved address is
checked against RFC1918/loopback/link-local/reserved ranges before connecting.
"""
import ipaddress
import os
import shutil
import socket
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, List, Union
from urllib.parse import urlparse

from app.utils.errors import ArchiveCorruptionError, ArchiveSecurityError, UnsupportedHostError


def validate_https_url(url: str, allowed_hosts: Iterable[str]) -> None:
    """Validate scheme + host allow-list only. Does not resolve DNS — callers
    that actually connect should use resolve_safe_addresses() too (the shared
    HTTP client in app.utils.http_client does both automatically).
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UnsupportedHostError(f"URL must use https: {url}")
    if parsed.username or parsed.password:
        raise UnsupportedHostError("URLs containing credentials are not permitted")
    try:
        port = parsed.port
    except ValueError:
        raise UnsupportedHostError(f"URL has an invalid port: {url}")
    if port not in (None, 443):
        raise UnsupportedHostError(f"Only the default HTTPS port is permitted (got {port})")
    host = (parsed.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise UnsupportedHostError(f"Host '{host}' is not in the allowed list")


def _is_unsafe_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_safe_addresses(hostname: str) -> List[str]:
    """Resolve a hostname and reject it if ANY resolved address is a private,
    loopback, link-local, multicast, reserved, or unspecified address. This
    defends against SSRF via DNS rebinding even when the hostname itself is
    allow-listed.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsupportedHostError(f"Could not resolve host '{hostname}': {exc}") from exc

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsupportedHostError(f"No addresses resolved for host '{hostname}'")

    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise UnsupportedHostError(f"Host '{hostname}' resolved to an unparseable address '{addr}'")
        if _is_unsafe_ip(ip):
            raise UnsupportedHostError(
                f"Host '{hostname}' resolved to a disallowed address '{addr}' "
                "(private/loopback/link-local/reserved ranges are blocked to prevent SSRF)"
            )
    return addresses


def validate_outbound_url(url: str, allowed_hosts: Iterable[str]) -> None:
    """Full validation for a URL about to be requested: https scheme,
    allow-listed host, AND safe resolved IP addresses. Use this (via
    app.utils.http_client) for every outbound request and every redirect hop.
    """
    validate_https_url(url, allowed_hosts)
    parsed = urlparse(url)
    resolve_safe_addresses(parsed.hostname or "")


def _is_within_directory(directory: Path, target: Path) -> bool:
    try:
        directory_resolved = directory.resolve()
        target_resolved = target.resolve()
    except OSError:
        return False
    return os.path.commonpath([str(directory_resolved)]) == os.path.commonpath(
        [str(directory_resolved), str(target_resolved)]
    )


def safe_extract_tar_gz(
    archive_path: Path,
    dest_dir: Path,
    *,
    max_file_count: int,
    max_total_size: int,
    max_single_file_size: int,
    max_path_depth: int = 32,
    max_path_length: int = 4096,
) -> int:
    """Extract a .tar.gz archive into dest_dir with strict safety checks.

    Members are read one at a time via tar.next() rather than tar.getmembers(),
    and every size/path check happens immediately after reading each header —
    BEFORE tarfile is asked to skip past that member's body to find the next
    one. This matters: tarfile.getmembers() (or iterating with `for m in tar`)
    must decompress and discard every member's body up front just to locate
    subsequent headers, so a single maliciously-oversized member would already
    be fully decompressed before any size check could run. Raising immediately
    on violation here means we never ask the stream to skip past an oversized
    body, which is what actually bounds decompression-bomb resource use.

    Returns the number of files extracted. Raises ArchiveSecurityError for
    any traversal/symlink/oversize/depth violation, ArchiveCorruptionError if
    the archive cannot be parsed.
    """
    dest_dir = dest_dir.resolve()
    file_count = 0
    total_size = 0
    extracted_members = []

    try:
        tar = tarfile.open(archive_path, mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveCorruptionError(f"Could not open archive: {exc}") from exc

    try:
        if hasattr(tarfile, "data_filter"):
            try:
                tar.extraction_filter = tarfile.data_filter  # type: ignore[attr-defined]
            except Exception:
                pass

        while True:
            try:
                member = tar.next()
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise ArchiveCorruptionError(f"Corrupted archive entry: {exc}") from exc
            if member is None:
                break

            name = member.name
            if name in ("", ".", "/"):
                continue

            if len(name) > max_path_length:
                raise ArchiveSecurityError(f"Path exceeds max length limit: {len(name)} chars")
            depth = len([p for p in name.split("/") if p not in ("", ".")])
            if depth > max_path_depth:
                raise ArchiveSecurityError(f"Path exceeds max nesting depth: {name}")

            normalized = os.path.normpath(name)
            if normalized.startswith("..") or os.path.isabs(name) or os.path.isabs(normalized):
                raise ArchiveSecurityError(f"Path traversal attempt detected: {name}")

            target_path = dest_dir / normalized
            if not _is_within_directory(dest_dir, target_path):
                raise ArchiveSecurityError(f"Extraction target escapes sandbox: {name}")

            if member.issym() or member.islnk():
                raise ArchiveSecurityError(f"Symlinks/hardlinks are not permitted: {name}")
            if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                raise ArchiveSecurityError(f"Special device files are not permitted: {name}")

            if member.isfile():
                if member.size > max_single_file_size:
                    raise ArchiveSecurityError(
                        f"File exceeds max single-file size limit: {name} ({member.size} bytes)"
                    )
                file_count += 1
                total_size += member.size
                if file_count > max_file_count:
                    raise ArchiveSecurityError(f"Archive exceeds max file count limit ({max_file_count})")
                if total_size > max_total_size:
                    raise ArchiveSecurityError(f"Archive exceeds max total extracted size ({max_total_size} bytes)")

            if member.isfile() or member.isdir():
                # Keep permission bits (the executable bit is analysis evidence) but never
                # setuid/setgid/sticky, and never chown to archive-supplied ids.
                member.mode = (member.mode & 0o777) | 0o600 | (0o100 if member.isdir() else 0)
                member.uid, member.gid = os.getuid(), os.getgid()
                member.uname = member.gname = ""
                extracted_members.append(member)

        try:
            tar.extractall(path=dest_dir, members=extracted_members)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise ArchiveCorruptionError(f"Failed extracting archive: {exc}") from exc
    finally:
        tar.close()

    return file_count


def _reject_unsafe_zip_name(name: str, max_path_length: int, max_path_depth: int) -> str:
    """Return the normalized relative path for a zip entry, or raise ArchiveSecurityError."""
    if "\x00" in name:
        raise ArchiveSecurityError("Archive entry name contains a NUL byte")
    if "\\" in name:
        raise ArchiveSecurityError(f"Backslashes are not permitted in archive paths: {name!r}")
    if len(name) > max_path_length:
        raise ArchiveSecurityError(f"Path exceeds max length limit: {len(name)} chars")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise ArchiveSecurityError(f"Absolute path in archive: {name}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ArchiveSecurityError(f"Path traversal attempt detected: {name}")
    if len(parts) > max_path_depth:
        raise ArchiveSecurityError(f"Path exceeds max nesting depth: {name}")
    return "/".join(parts)


def safe_extract_zip(
    archive_path: Path,
    dest_dir: Path,
    *,
    max_file_count: int,
    max_total_size: int,
    max_single_file_size: int,
    max_path_depth: int = 32,
    max_path_length: int = 4096,
    max_compression_ratio: int = 1000,
) -> int:
    """Extract a .zip/.whl with the same guarantees as safe_extract_tar_gz.

    Every entry is validated from the central directory BEFORE anything is
    written: traversal / absolute / drive-letter / backslash paths, symlinks
    and special files (from the Unix mode bits), encrypted entries, duplicate
    names, per-file/total size, file count, nesting depth and the
    compression ratio of large entries. Bytes are then copied with a running
    counter, so a lying size field cannot be used to write past the limits.
    Nothing inside the archive is ever executed or imported.
    """
    dest_dir = dest_dir.resolve()
    try:
        zf = zipfile.ZipFile(archive_path)
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError) as exc:
        raise ArchiveCorruptionError(f"Could not open zip archive: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > max_file_count * 2:
            raise ArchiveSecurityError(f"Archive exceeds max entry count limit ({max_file_count * 2})")

        plan = []
        seen = set()
        file_count = 0
        total_size = 0
        for info in infos:
            rel = _reject_unsafe_zip_name(info.filename, max_path_length, max_path_depth)
            if not rel:
                continue
            if rel in seen:
                raise ArchiveSecurityError(f"Duplicate archive entry (possible content smuggling): {rel}")
            seen.add(rel)
            target = dest_dir / rel
            if not _is_within_directory(dest_dir, target):
                raise ArchiveSecurityError(f"Extraction target escapes sandbox: {rel}")
            if info.flag_bits & 0x1:
                raise ArchiveSecurityError(f"Encrypted archive entries are not permitted: {rel}")

            unix_mode = info.external_attr >> 16
            file_type = stat.S_IFMT(unix_mode)
            if file_type == stat.S_IFLNK:
                raise ArchiveSecurityError(f"Symlinks are not permitted: {rel}")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ArchiveSecurityError(f"Special files are not permitted: {rel}")

            if info.is_dir():
                plan.append((info, target, 0o755))
                continue

            if info.file_size > max_single_file_size:
                raise ArchiveSecurityError(f"File exceeds max single-file size limit: {rel} ({info.file_size} bytes)")
            if info.file_size > 1024 * 1024:
                if info.compress_size == 0 or info.file_size / info.compress_size > max_compression_ratio:
                    raise ArchiveSecurityError(f"Suspicious compression ratio (possible zip bomb): {rel}")
            file_count += 1
            total_size += info.file_size
            if file_count > max_file_count:
                raise ArchiveSecurityError(f"Archive exceeds max file count limit ({max_file_count})")
            if total_size > max_total_size:
                raise ArchiveSecurityError(f"Archive exceeds max total extracted size ({max_total_size} bytes)")
            plan.append((info, target, (unix_mode & 0o777) | 0o600))

        written_total = 0
        try:
            for info, target, mode in plan:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        written_total += len(chunk)
                        if written > max_single_file_size or written_total > max_total_size:
                            raise ArchiveSecurityError(f"Entry expanded past the configured size limits: {info.filename}")
                        dst.write(chunk)
                os.chmod(target, mode)
        except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError, shutil.Error) as exc:
            raise ArchiveCorruptionError(f"Failed extracting zip archive: {exc}") from exc

    return file_count
