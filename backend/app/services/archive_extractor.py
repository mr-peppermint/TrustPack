"""Safe extraction of npm tarballs and GitHub source archives.

Never executes any code from the archive. All extraction goes through
app.utils.security.safe_extract_tar_gz, which enforces path-traversal,
symlink, and size/count protections.
"""
from pathlib import Path

from app.config import settings
from app.utils.security import safe_extract_tar_gz


def _find_content_root(dest_dir: Path) -> Path:
    """npm tarballs and GitHub archives both wrap content in a single top-level
    directory ("package/" or "{repo}-{ref}/"). Unwrap it if present so both
    sides of the comparison use comparable relative paths.
    """
    entries = [p for p in dest_dir.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir


def extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Extract a tar.gz archive into dest_dir and return the unwrapped content root."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_extract_tar_gz(
        archive_path,
        dest_dir,
        max_file_count=settings.MAX_FILE_COUNT,
        max_total_size=settings.MAX_EXTRACTED_SIZE_BYTES,
        max_single_file_size=settings.MAX_SINGLE_FILE_SIZE_BYTES,
    )
    return _find_content_root(dest_dir)
