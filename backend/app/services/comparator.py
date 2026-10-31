"""Compares source and published manifests and classifies every file difference."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.services.manifest_generator import FileRecord
from app.services.normalizer import classify_difference


@dataclass
class ComparisonResult:
    entries: List[Dict[str, Any]]
    summary: Dict[str, int]


def compare_manifests(
    source_manifest: Dict[str, FileRecord],
    published_manifest: Dict[str, FileRecord],
    package_json: Optional[Dict[str, Any]] = None,
) -> ComparisonResult:
    all_paths = sorted(set(source_manifest.keys()) | set(published_manifest.keys()))
    entries: List[Dict[str, Any]] = []
    summary = {
        "identical": 0, "modified": 0, "added": 0,
        "removed": 0, "expected_generated": 0, "unexplained": 0,
    }

    for path in all_paths:
        src = source_manifest.get(path)
        pub = published_manifest.get(path)
        hashes_match = bool(src and pub and src.sha256 == pub.sha256)

        status, reason = classify_difference(
            path,
            in_source=src is not None,
            in_published=pub is not None,
            hashes_match=hashes_match,
            package_json=package_json,
        )
        summary[status.lower()] += 1

        entries.append({
            "path": path,
            "status": status,
            "source_sha256": src.sha256 if src else None,
            "published_sha256": pub.sha256 if pub else None,
            "source_size": src.size if src else None,
            "published_size": pub.size if pub else None,
            "reason": reason,
        })

    return ComparisonResult(entries=entries, summary=summary)
