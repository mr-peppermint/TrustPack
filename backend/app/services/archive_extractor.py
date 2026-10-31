"""Safe extraction of npm tarballs, PyPI sdists/wheels and GitHub source archives.

Never executes any code from the archive. The format is detected from magic bytes (not the file name,
which an attacker controls) and routed to the hardened extractors in app.utils.security, which enforce
path-traversal, symlink, special-file, size, count, depth and (for zip) compression-ratio protections
before any byte is written.
"""
from pathlib import Path

from app.config import settings
from app.utils.errors import ArchiveCorruptionError
from app.utils.security import safe_extract_tar_gz, safe_extract_zip

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
_TAR_MAGICS = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")  # gzip, bzip2, xz


def _find_content_root(dest_dir: Path) -> Path:
    """npm tarballs, sdists and GitHub archives wrap content in a single top-level directory
    ("package/", "{name}-{version}/", "{repo}-{ref}/"). Unwrap it if present so both sides of the
    comparison use comparable relative paths.
    """
    entries = [p for p in dest_dir.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir


def detect_format(archive_path: Path) -> str:
    try:
        with open(archive_path, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        raise ArchiveCorruptionError(f"Could not read archive: {exc}") from exc
    if head.startswith(_ZIP_MAGICS):
        return "zip"
    if head.startswith(_TAR_MAGICS):
        return "tar"
    raise ArchiveCorruptionError("Unsupported or corrupted archive (not a zip, gzip, bzip2 or xz file)")


def extract_archive(archive_path: Path, dest_dir: Path, *, unwrap: bool = True) -> Path:
    """Extract an archive into dest_dir and return the content root.

    `unwrap=False` keeps the archive layout exactly as stored — required for wheels, whose top level
    legitimately contains several directories (package + .dist-info) and may contain just one.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    limits = dict(
        max_file_count=settings.MAX_FILE_COUNT,
        max_total_size=settings.MAX_EXTRACTED_SIZE_BYTES,
        max_single_file_size=settings.MAX_SINGLE_FILE_SIZE_BYTES,
    )
    if detect_format(archive_path) == "zip":
        safe_extract_zip(
            archive_path, dest_dir, max_path_depth=settings.MAX_PATH_DEPTH,
            max_path_length=settings.MAX_PATH_LENGTH, max_compression_ratio=settings.MAX_COMPRESSION_RATIO, **limits,
        )
    else:
        safe_extract_tar_gz(
            archive_path, dest_dir, max_path_depth=settings.MAX_PATH_DEPTH,
            max_path_length=settings.MAX_PATH_LENGTH, **limits,
        )
    return _find_content_root(dest_dir) if unwrap else dest_dir
