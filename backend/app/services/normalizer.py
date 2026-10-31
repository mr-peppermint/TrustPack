"""Residual classification of differences that are NOT explained as generated output.

Generated-output detection lives in generated_file_detector (evidence-based). What is left here is
deliberately simple: a file only on the published side is ADDED; a source-like file whose content
changed is UNEXPLAINED (it deserves review); anything else that changed is MODIFIED. The one structural
exception is package.json, which npm rewrites at publish time, so it is compared field by field.
"""
import json
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

# Source-like extensions where an unexplained content diff is noteworthy.
SOURCE_LIKE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pyx", ".pxd", ".c", ".cpp", ".h",
    ".sh", ".rb", ".json", ".toml", ".cfg", ".pth", ".ps1", ".bat", ".cmd",
}

# package.json fields that change what gets installed or executed. Everything else (gitHead, _id,
# readme, version stamps, funding...) is publish-time metadata.
PACKAGE_JSON_SECURITY_KEYS = (
    "scripts", "dependencies", "optionalDependencies", "peerDependencies", "bundledDependencies",
    "bundleDependencies", "bin", "main", "module", "exports", "browser", "type", "files", "gypfile",
    "os", "cpu", "directories",
)


def normalize_path(path: str) -> str:
    return PurePosixPath(path.strip().lstrip("./")).as_posix()


def package_json_differences(published: Dict[str, Any], source: Dict[str, Any]) -> List[str]:
    """Names of security-relevant package.json fields whose values differ between the two documents."""
    return [k for k in PACKAGE_JSON_SECURITY_KEYS if published.get(k) != source.get(k)]


def _load_json(root: Optional[Path], rel: str) -> Optional[Dict[str, Any]]:
    if root is None:
        return None
    try:
        data = json.loads((root / rel).read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def classify_residual(
    path: str,
    *,
    in_source: bool,
    in_published: bool,
    hashes_match: bool,
    published_root: Optional[Path] = None,
    source_root: Optional[Path] = None,
    source_path: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """Return (status, reason) for a file that is not identical and not explained as generated."""
    if in_source and in_published and hashes_match:
        return "IDENTICAL", None
    if in_source and not in_published:
        return "REMOVED", None
    if in_published and not in_source:
        return "ADDED", None

    if PurePosixPath(path).name == "package.json":
        pub = _load_json(published_root, path)
        src = _load_json(source_root, source_path or path)
        if pub is not None and src is not None:
            differing = package_json_differences(pub, src)
            if not differing:
                return "MODIFIED", "differs only in publish-time metadata fields (no scripts, dependencies, entry points or file lists changed)"
            return "UNEXPLAINED", "security-relevant package.json fields differ: " + ", ".join(differing)

    ext = PurePosixPath(normalize_path(path)).suffix.lower()
    if ext in SOURCE_LIKE_EXTENSIONS:
        return "UNEXPLAINED", None
    return "MODIFIED", None
