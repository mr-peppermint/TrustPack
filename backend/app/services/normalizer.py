"""Heuristics for distinguishing expected build transformations from
genuine, unexplained differences between source and published content.

This is deliberately conservative and documented: it never claims a file is
safe just because it matches a "generated" pattern, it only changes how the
difference is *labeled* so risk assessment downstream can weigh it correctly.
Every EXPECTED_GENERATED classification records WHY it was classified that
way, so a reviewer can see (and challenge) the specific rule that fired
rather than trusting an opaque verdict.
"""
from pathlib import PurePosixPath
from typing import Any, Dict, Optional, Tuple

_GENERATED_DIR_PREFIXES = ("dist/", "build/", "out/", "umd/", "cjs/", "esm/", "lib-es/")
_GENERATED_SUFFIXES = (".min.js", ".min.css", ".map")

# Source-like extensions where an unexplained content diff is noteworthy.
_SOURCE_LIKE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".sh", ".rb", ".json",
}


def normalize_path(path: str) -> str:
    return PurePosixPath(path.strip().lstrip("./")).as_posix()


def _declared_build_outputs(package_json: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Map normalized path -> the package.json field that declared it."""
    if not package_json:
        return {}
    outputs: Dict[str, str] = {}
    for key in ("main", "module", "types", "typings", "browser"):
        val = package_json.get(key)
        if isinstance(val, str):
            outputs[normalize_path(val)] = key
    exports = package_json.get("exports")
    if isinstance(exports, str):
        outputs[normalize_path(exports)] = "exports"
    elif isinstance(exports, dict):
        for v in exports.values():
            if isinstance(v, str):
                outputs[normalize_path(v)] = "exports"
    return outputs


def generated_reason(path: str, package_json: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Return a human-readable reason this path matches a known
    build-generated pattern, or None if it doesn't match any rule.
    """
    norm = normalize_path(path)
    lower = norm.lower()

    if norm.endswith(".d.ts"):
        return "matches *.d.ts (TypeScript declaration files are compiler-generated)"
    for prefix in _GENERATED_DIR_PREFIXES:
        if lower.startswith(prefix):
            return f"path starts with '{prefix}' (conventional build-output directory)"
    for suffix in _GENERATED_SUFFIXES:
        if lower.endswith(suffix):
            return f"matches '*{suffix}' (conventional build-output/minified/source-map suffix)"
    declared = _declared_build_outputs(package_json)
    if norm in declared:
        return f"declared as package.json '{declared[norm]}' entry point"
    return None


def is_expected_generated(path: str, package_json: Optional[Dict[str, Any]] = None) -> bool:
    return generated_reason(path, package_json) is not None


def classify_difference(
    path: str,
    *,
    in_source: bool,
    in_published: bool,
    hashes_match: bool,
    package_json: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Optional[str]]:
    """Return (status, reason). status is one of: IDENTICAL, REMOVED, ADDED,
    MODIFIED, EXPECTED_GENERATED, UNEXPLAINED. reason is populated only for
    EXPECTED_GENERATED (explaining which rule matched) so normalization never
    silently erases why a security-relevant difference was downgraded.
    """
    if in_source and in_published and hashes_match:
        return "IDENTICAL", None
    if in_source and not in_published:
        return "REMOVED", None

    reason = generated_reason(path, package_json)
    if reason:
        return "EXPECTED_GENERATED", reason

    if in_published and not in_source:
        return "ADDED", None

    # Present on both sides, content differs, not a recognized build pattern.
    ext = PurePosixPath(normalize_path(path)).suffix.lower()
    if ext in _SOURCE_LIKE_EXTENSIONS:
        return "UNEXPLAINED", None
    return "MODIFIED", None
