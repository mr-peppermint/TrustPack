"""Compares source and published manifests and classifies every file difference.

The same engine serves npm and PyPI: both ecosystems are reduced to {relative path: FileRecord}
manifests of the published artifact and of the resolved source tree, and everything below is
ecosystem-neutral. Ecosystem differences only enter through (a) path alignment — wheels ship
`pkg/x.py` while the repository keeps `src/pkg/x.py` — and (b) the generated-file detector's rules.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.generated_file_detector import EXPECTED, UNCERTAIN, GeneratedFileDetector
from app.services.manifest_generator import FileRecord
from app.services.normalizer import classify_residual


@dataclass
class ComparisonResult:
    entries: List[Dict[str, Any]]
    summary: Dict[str, int]
    alignment_note: Optional[str] = None
    source_path_for: Dict[str, str] = field(default_factory=dict)


def align_paths(
    source_manifest: Dict[str, FileRecord], published_manifest: Dict[str, FileRecord]
) -> Tuple[Dict[str, str], Optional[str]]:
    """Map published paths to source paths when the artifact is laid out under a different root
    (wheel `pkg/x.py` <-> repository `src/pkg/x.py`). Conservative: a single directory prefix must be
    supported by at least two files whose path suffix is unique in the repository, and be supported by
    more files than already match exactly. Returns ({published: source}, human-readable note).
    """
    unmapped = [p for p in published_manifest if p not in source_manifest]
    exact = len(published_manifest) - len(unmapped)
    if not unmapped or not source_manifest:
        return {}, None

    tails: Dict[str, List[str]] = defaultdict(list)
    for sp in source_manifest:
        parts = sp.split("/")
        for i in range(1, len(parts)):
            tails["/".join(parts[i:])].append(sp)

    votes: Counter = Counter()
    for p in unmapped:
        candidates = tails.get(p, [])
        if len(candidates) == 1:
            votes[candidates[0][: -len(p)]] += 1
    if not votes:
        return {}, None

    prefix, count = votes.most_common(1)[0]
    if count < 2 or count <= exact / 2:
        return {}, None

    mapping = {p: prefix + p for p in unmapped if (prefix + p) in source_manifest}
    return mapping, f"Published paths were matched to the repository under '{prefix}' ({len(mapping)} files)."


def compare_manifests(
    source_manifest: Dict[str, FileRecord],
    published_manifest: Dict[str, FileRecord],
    package_json: Optional[Dict[str, Any]] = None,
    *,
    detector: Optional[GeneratedFileDetector] = None,
    ecosystem: str = "npm",
    align: bool = False,
    published_root: Optional[Path] = None,
    source_root: Optional[Path] = None,
) -> ComparisonResult:
    mapping: Dict[str, str] = {}
    note = None
    if align:
        mapping, note = align_paths(source_manifest, published_manifest)

    if detector is None:
        detector = GeneratedFileDetector(
            ecosystem=ecosystem,
            source_manifest=source_manifest,
            published_manifest=published_manifest,
            published_root=published_root,
            source_root=source_root,
            published_package_json=package_json,
            source_path_for=mapping,
        )
    else:
        detector.source_path_for = mapping

    consumed_source = {mapping.get(p, p) for p in published_manifest}
    keys = sorted(set(published_manifest) | {sp for sp in source_manifest if sp not in consumed_source})

    entries: List[Dict[str, Any]] = []
    summary = {
        "identical": 0, "modified": 0, "added": 0, "removed": 0,
        "expected_generated": 0, "uncertain": 0, "unexplained": 0,
    }

    for path in keys:
        pub = published_manifest.get(path)
        source_key = mapping.get(path, path)
        src = source_manifest.get(source_key)
        hashes_match = bool(src and pub and src.sha256 == pub.sha256)
        evidence: List[str] = []

        if src and pub and hashes_match:
            status, reason = "IDENTICAL", None
        elif src and not pub:
            status, reason = "REMOVED", None
        else:
            verdict = detector.classify(path, in_source=src is not None)
            if verdict.status == EXPECTED:
                status, reason, evidence = "EXPECTED_GENERATED", verdict.reason, verdict.evidence
            elif verdict.status == UNCERTAIN:
                status, reason, evidence = "UNCERTAIN", verdict.reason, verdict.evidence
            else:
                status, reason = classify_residual(
                    path,
                    in_source=src is not None,
                    in_published=pub is not None,
                    hashes_match=hashes_match,
                    published_root=published_root,
                    source_root=source_root,
                    source_path=source_key,
                )
                if verdict.reason and not reason:
                    reason = verdict.reason
        summary[status.lower()] += 1

        entries.append({
            "path": path,
            "status": status,
            "source_sha256": src.sha256 if src else None,
            "published_sha256": pub.sha256 if pub else None,
            "source_size": src.size if src else None,
            "published_size": pub.size if pub else None,
            "reason": reason,
            "evidence": evidence,
        })

    return ComparisonResult(entries=entries, summary=summary, alignment_note=note, source_path_for=mapping)
