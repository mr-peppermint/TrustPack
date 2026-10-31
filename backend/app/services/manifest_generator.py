"""Generates deterministic file manifests (path, size, sha256, category) for a directory tree."""
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from app.utils.hashing import sha256_file

_CATEGORY_BY_EXT = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".json": "metadata",
    ".md": "docs", ".markdown": "docs", ".txt": "docs",
    ".yml": "config", ".yaml": "config", ".toml": "config", ".ini": "config", ".cfg": "config",
    ".map": "sourcemap",
    ".py": "script", ".sh": "script", ".rb": "script", ".pl": "script",
    ".png": "asset", ".jpg": "asset", ".jpeg": "asset", ".gif": "asset", ".svg": "asset", ".ico": "asset",
    ".css": "style", ".scss": "style", ".less": "style",
    ".html": "markup",
    ".lock": "metadata",
}

_IGNORED_NAMES = {".DS_Store", "Thumbs.db"}


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    extension: str
    category: str
    is_executable: bool


def _categorize(rel_path: str) -> str:
    lower = rel_path.lower()
    if lower.endswith(".d.ts"):
        return "type_declaration"
    if lower.endswith(".min.js") or lower.endswith(".min.css"):
        return "minified"
    ext = Path(rel_path).suffix.lower()
    return _CATEGORY_BY_EXT.get(ext, "other")


def _is_executable(abs_path: Path) -> bool:
    try:
        st = abs_path.stat()
    except OSError:
        return False
    if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return True
    try:
        with open(abs_path, "rb") as f:
            head = f.read(2)
            if head == b"#!":
                return True
    except OSError:
        pass
    return False


def generate_manifest(root: Path) -> Dict[str, FileRecord]:
    """Walk `root` and build a path->FileRecord map. Paths are POSIX-style,
    relative to root, deterministically generated (sorted walk order).
    Symlinks are never followed.
    """
    manifest: Dict[str, FileRecord] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename in _IGNORED_NAMES:
                continue
            abs_path = Path(dirpath) / filename
            if abs_path.is_symlink():
                continue
            rel_path = abs_path.relative_to(root).as_posix()
            try:
                size = abs_path.stat().st_size
                digest = sha256_file(abs_path)
            except OSError:
                continue
            manifest[rel_path] = FileRecord(
                path=rel_path,
                size=size,
                sha256=digest,
                extension=Path(rel_path).suffix.lower(),
                category=_categorize(rel_path),
                is_executable=_is_executable(abs_path),
            )
    return manifest
