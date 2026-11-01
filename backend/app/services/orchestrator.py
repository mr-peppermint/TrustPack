"""Orchestrates the full analysis pipeline for a single package+version request.

One pipeline serves every ecosystem. The registry adapter (npm / PyPI) supplies a verified release
artifact and normalized metadata; from there on the same code extracts, hashes, resolves the source,
compares, classifies generated files, reports provenance and scores risk.

Fatal errors (package/version not found, registry unreachable) propagate to the API layer as HTTP
errors. Everything else degrades gracefully into a report with `analysis_complete=False` and explicit
`limitations`, rather than raising — we never leave the caller with nothing. The risk verdict is
computed here, deterministically; the AI explanation (ai_explainer) is attached afterwards and can
neither change it nor block it.
"""
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.registries import Release, get_registry
from app.services import (
    ai_explainer,
    comparator,
    manifest_generator,
    provenance_checker,  # noqa: F401  (kept importable for callers patching it)
    report_generator,
    risk_engine,
    source_resolver,
)
from app.services.archive_extractor import extract_archive
from app.services.generated_file_detector import GeneratedFileDetector
from app.utils.errors import (
    ArchiveCorruptionError,
    ArchiveSecurityError,
    DownloadError,
    IntegrityVerificationError,
    SourceResolutionError,
    UpstreamRateLimitError,
)
from app.utils.logging import get_logger

logger = get_logger(__name__)

_EMPTY_SUMMARY = {
    "identical": 0, "modified": 0, "added": 0, "removed": 0,
    "expected_generated": 0, "uncertain": 0, "unexplained": 0,
}
_PLACEHOLDER_VERSIONS = {"", "0.0.0", "0.0.0-development", "0.0.0-semantic-release", "0.0.0-dev", "1.0.0-dev"}


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _declared_source_version(ecosystem: str, root: Path) -> Optional[str]:
    """A literal version the repository declares at the resolved ref (None when dynamic or unknown)."""
    if ecosystem == "npm":
        version = (_read_json(root / "package.json") or {}).get("version")
        return version if isinstance(version, str) and version not in _PLACEHOLDER_VERSIONS else None
    for name, pattern in (
        ("pyproject.toml", r"(?m)^version\s*=\s*[\"']([^\"']+)[\"']"),
        ("setup.py", r"version\s*=\s*[\"']([0-9][^\"']*)[\"']"),
        ("setup.cfg", r"(?m)^version\s*=\s*([0-9][^\s#]*)"),
    ):
        try:
            text = (root / name).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = re.search(pattern, text)
        if m:
            return m.group(1).strip()
    return None


def _distribution_info(release: Release) -> Dict[str, Any]:
    a = release.artifact
    return {
        "kind": a.kind, "filename": a.filename, "url": a.url, "sha256": a.sha256, "size": a.size,
        "selection_reason": a.selection_reason, "alternatives": a.alternatives, "published_at": a.published_at,
    }


def _failure_report(
    package_name: str, version: str, ecosystem: str, *, findings: List[Dict[str, Any]], limitations: List[str],
    tarball_verified: Optional[bool], risk: Dict[str, Any], release: Optional[Release] = None,
) -> Dict[str, Any]:
    report = report_generator.build_report(
        package_name=package_name, version=version, ecosystem=ecosystem,
        source_repo_url=None, source_commit=None, resolution_method=None,
        correspondence="NONE", source_directory=None,
        tarball_verified=tarball_verified, verification_algorithm=None,
        provenance_status="UNKNOWN",
        summary=dict(_EMPTY_SUMMARY), comparison_entries=[], findings=findings, risk=risk,
        limitations=limitations, analysis_complete=False,
        distribution=_distribution_info(release) if release else None,
    )
    report_generator.save_report(report)
    return report


async def analyze_package(
    package_name: str,
    version: str,
    ecosystem: str = "npm",
    repository_url: Optional[str] = None,
) -> Dict[str, Any]:
    registry = get_registry(ecosystem)
    ecosystem = registry.ecosystem
    tmp_root = Path(tempfile.mkdtemp(prefix="trustpack_"))
    limitations: List[str] = []
    try:
        try:
            release = await registry.fetch_release(package_name, version, tmp_root / "download")
        except IntegrityVerificationError as exc:
            logger.warning("Integrity verification failed for %s@%s: %s" % (package_name, version, exc))
            risk = risk_engine.compute_risk([], tarball_verified=False, correspondence="NONE", analysis_complete=False)
            return _failure_report(
                package_name, version, ecosystem, findings=[], limitations=[str(exc)],
                tarball_verified=False, risk=risk,
            )

        artifact = release.artifact
        limitations.extend(release.notes)

        # ---- extract + inventory the published artifact -----------------------------------------
        try:
            published_root = extract_archive(artifact.path, tmp_root / "published", unwrap=release.unwrap_archive)
        except ArchiveSecurityError as exc:
            logger.warning("Published artifact for %s@%s rejected by extraction guard: %s" % (package_name, version, exc))
            findings = [{
                "rule_id": "UNSAFE_ARCHIVE", "file": artifact.filename, "category": "unsafe_archive",
                "severity": "HIGH", "confidence": "HIGH",
                "evidence": f"The published archive was refused by the extraction safety checks: {exc}",
                "explanation": "A package archive that tries to escape its directory, contains links or special files, or expands beyond size limits is not something a legitimate build produces.",
                "recommendation": "Do not install this release.",
            }]
            risk = risk_engine.compute_risk(findings, tarball_verified=artifact.verified, correspondence="NONE", analysis_complete=False)
            return _failure_report(
                package_name, version, ecosystem, findings=findings,
                limitations=limitations + ["The archive was not extracted, so no file comparison was performed."],
                tarball_verified=artifact.verified, risk=risk, release=release,
            )
        except ArchiveCorruptionError as exc:
            risk = risk_engine.compute_risk([], tarball_verified=artifact.verified, correspondence="NONE", analysis_complete=False)
            return _failure_report(
                package_name, version, ecosystem, findings=[],
                limitations=limitations + [f"The published archive could not be read: {exc}"],
                tarball_verified=artifact.verified, risk=risk, release=release,
            )

        published_manifest = manifest_generator.generate_manifest(published_root)
        published_package_json = registry.published_package_json(release, published_root)
        findings: List[Dict[str, Any]] = registry.static_findings(release, published_root, published_manifest)

        # ---- source resolution + comparison ------------------------------------------------------
        source_repo_url = None
        source_commit = None
        resolution_method = None
        correspondence = "NONE"
        source_directory = None
        source_confidence: Optional[str] = None
        source_notes: List[str] = []
        summary = dict(_EMPTY_SUMMARY)
        comparison_entries: List[Dict[str, Any]] = []
        source_resolution_rate_limited = False

        try:
            resolution = await source_resolver.resolve_source(
                release.repository_field, release.git_head, version,
                explicit_repo_url=repository_url,
                extra_candidates=release.extra_repo_candidates,
                package_name=package_name,
                tag_names=release.tag_names,
            )
            source_repo_url = resolution.repo.url
            source_commit = resolution.commit
            resolution_method = resolution.resolution_method
            correspondence = resolution.correspondence
            source_directory = resolution.repo.directory
            source_confidence = resolution.confidence
            source_notes = list(resolution.notes)

            source_archive_dir = tmp_root / "source"
            source_archive_dir.mkdir(parents=True, exist_ok=True)
            archive_path = await source_resolver.download_source_archive(resolution, source_archive_dir)
            source_links: list = []
            source_extracted_root = extract_archive(archive_path, tmp_root / "source_extracted", skipped_links=source_links)
            if source_links:
                shown = ", ".join(source_links[:3]) + (f" and {len(source_links) - 3} more" if len(source_links) > 3 else "")
                limitations.append(
                    f"{len(source_links)} symlink(s) in the repository were not extracted and not compared: {shown}."
                )

            source_content_root = source_extracted_root
            if source_directory:
                candidate = (source_extracted_root / source_directory).resolve()
                if str(candidate).startswith(str(source_extracted_root.resolve())) and candidate.is_dir():
                    source_content_root = candidate
                else:
                    limitations.append(
                        f"repository.directory '{source_directory}' was invalid or not found; "
                        "compared against the repository root instead."
                    )

            source_manifest = manifest_generator.generate_manifest(source_content_root)
            source_package_json = _read_json(source_content_root / "package.json") if ecosystem == "npm" else None

            declared = _declared_source_version(ecosystem, source_content_root)
            if declared and declared.lower() != version.lower():
                source_notes.append(
                    f"The repository declares version '{declared}' at the resolved ref, but the release is "
                    f"'{version}'; the tag or commit may not be the one this release was built from."
                )
                source_confidence = "LOW"

            detector = GeneratedFileDetector(
                ecosystem=ecosystem,
                source_manifest=source_manifest,
                published_manifest=published_manifest,
                published_root=published_root,
                source_root=source_content_root,
                published_package_json=published_package_json,
                source_package_json=source_package_json,
                artifact_kind=artifact.kind,
                package_name=package_name,
                package_version=version,
            )
            comparison = comparator.compare_manifests(
                source_manifest, published_manifest, published_package_json,
                detector=detector, ecosystem=ecosystem, align=(ecosystem == "pypi"),
                published_root=published_root, source_root=source_content_root,
            )
            summary = comparison.summary
            comparison_entries = comparison.entries
            if comparison.alignment_note:
                source_notes.append(comparison.alignment_note)

            findings.extend(risk_engine.build_unexplained_findings(comparison_entries, published_manifest))
            findings.extend(risk_engine.build_unexpected_executable_findings(comparison_entries, published_manifest))
            findings.extend(risk_engine.build_added_file_findings(comparison_entries, published_manifest))
            findings.extend(risk_engine.build_uncertain_findings(comparison_entries))
            findings.extend(risk_engine.build_suspicious_content_findings(comparison_entries, published_root))
            findings.extend(registry.source_findings(release, source_content_root, source_manifest))

        except UpstreamRateLimitError as exc:
            logger.warning("Source resolution rate-limited for %s@%s: %s" % (package_name, version, exc))
            limitations.append(str(exc))
            source_resolution_rate_limited = True
        except SourceResolutionError as exc:
            logger.info("Source resolution inconclusive for %s@%s: %s" % (package_name, version, exc))
            limitations.append(str(exc))
        except (ArchiveSecurityError, ArchiveCorruptionError, DownloadError) as exc:
            logger.warning("Source archive handling failed for %s@%s: %s" % (package_name, version, exc))
            correspondence = "NONE"
            limitations.append(f"Source archive could not be safely processed: {exc}")

        # ---- provenance --------------------------------------------------------------------------
        try:
            provenance = await registry.verify_provenance(release, source_repo_url, source_commit)
        except Exception as exc:  # noqa: BLE001 - provenance is best-effort, never fatal
            logger.warning("Provenance verification failed unexpectedly for %s@%s: %s" % (package_name, version, exc))
            provenance = {
                "provenance_status": "UNKNOWN",
                "registry_signature_present": None,
                "detail": "Provenance verification could not be completed due to an unexpected error.",
                "findings": [],
            }
        findings.extend(provenance.get("findings", []))

        # ---- deterministic verdict ---------------------------------------------------------------
        changed = sum(v for k, v in summary.items() if k != "identical")
        risk = risk_engine.compute_risk(
            findings,
            tarball_verified=artifact.verified,
            correspondence=correspondence,
            source_confidence=source_confidence,
            uncertain_count=summary.get("uncertain", 0),
            changed_count=changed,
        )

        # ---- limitations -------------------------------------------------------------------------
        if correspondence == "NONE":
            limitations.append(
                "File-level comparison was skipped because exact source correspondence could not be established."
            )
        if resolution_method == "tag":
            limitations.append("Source match is inferred from a version tag, not an exact commit recorded by the registry.")
        if source_confidence == "LOW":
            limitations.append("Confidence in the resolved source revision is low; see the source notes.")
        if summary.get("uncertain"):
            limitations.append(
                f"{summary['uncertain']} file(s) resemble build output but could not be tied to the source; they are "
                "reported as uncertain rather than assumed safe."
            )
        if provenance["provenance_status"] in ("NOT_VERIFIED", "UNKNOWN"):
            limitations.append(
                "The provenance attestation's cryptographic signature chain (certificate + transparency log) "
                "was not verified; only the attestation's claims were checked against this analysis."
            )
        if provenance["provenance_status"] == "NOT_AVAILABLE":
            limitations.append("No provenance attestation is available for this release, so who built it, and from what source, is unverified.")
        limitations.append(
            "Static pattern scanning cannot prove intent; absence of findings does not guarantee safety."
        )
        limitations.append(
            "No reproducible build was attempted; comparison is direct file-hash matching against the "
            "resolved source, not a verified rebuild."
        )
        if ecosystem == "pypi":
            limitations.append(
                "PyPI dependency declarations and console-script entry points were not compared with the repository."
            )

        report = report_generator.build_report(
            package_name=package_name, version=version, ecosystem=ecosystem,
            source_repo_url=source_repo_url, source_commit=source_commit,
            resolution_method=resolution_method, correspondence=correspondence,
            source_directory=source_directory,
            tarball_verified=artifact.verified,
            verification_algorithm=artifact.verification_algorithm,
            provenance_status=provenance["provenance_status"],
            registry_signature_present=provenance.get("registry_signature_present"),
            provenance_detail=provenance.get("detail"),
            provenance_claims=provenance.get("claims"),
            summary=summary, comparison_entries=comparison_entries,
            findings=findings, risk=risk, limitations=limitations,
            analysis_complete=True,
            source_confidence=source_confidence, source_notes=source_notes,
            distribution=_distribution_info(release),
        )
        if source_resolution_rate_limited:
            # A transient infrastructure condition, not a real analysis outcome: never let it sit in the
            # shared cache and get served to other requests for the same package version.
            report["cacheable"] = False
        report_generator.save_report(report)  # the deterministic result is durable before any AI call

        if settings.AI_ENABLED:
            report["ai_explanation"] = await ai_explainer.explain(report)
            report_generator.save_report(report)
        return report
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
