"""Orchestrates the full analysis pipeline for a single package+version request.

Fatal errors (package/version not found, registry unreachable) propagate to
the API layer as HTTP errors. Everything else degrades gracefully into a
report with `analysis_complete=False` and explicit `limitations`, rather
than raising — per spec, we never leave the caller with nothing.
"""
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services import (
    comparator,
    manifest_generator,
    metadata_analyzer,
    npm_registry,
    package_downloader,
    provenance_checker,
    report_generator,
    risk_engine,
    source_resolver,
)
from app.services.archive_extractor import extract_archive
from app.utils.errors import (
    ArchiveCorruptionError,
    ArchiveSecurityError,
    DownloadError,
    IntegrityVerificationError,
    SourceResolutionError,
)
from app.utils.logging import get_logger

logger = get_logger(__name__)

_EMPTY_SUMMARY = {"identical": 0, "modified": 0, "added": 0, "removed": 0, "expected_generated": 0, "unexplained": 0}


def _read_package_json(root: Path, subdir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    base = root / subdir if subdir else root
    path = base / "package.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (ValueError, OSError):
        return None


async def analyze_package(package_name: str, version: str) -> Dict[str, Any]:
    tmp_root = Path(tempfile.mkdtemp(prefix="trustpack_"))
    limitations: List[str] = []
    try:
        registry_meta = await npm_registry.fetch_version_metadata(package_name, version)

        download_dir = tmp_root / "download"
        download_dir.mkdir(parents=True, exist_ok=True)

        try:
            download_result = await package_downloader.download_and_verify_tarball(
                registry_meta.dist, download_dir
            )
        except IntegrityVerificationError as exc:
            logger.warning("Integrity verification failed for %s@%s: %s" % (package_name, version, exc))
            risk = risk_engine.compute_risk([], tarball_verified=False, correspondence="NONE")
            report = report_generator.build_report(
                package_name=package_name, version=version,
                source_repo_url=None, source_commit=None, resolution_method=None,
                correspondence="NONE", source_directory=None,
                tarball_verified=False, verification_algorithm=None,
                provenance_status="UNKNOWN",
                summary=dict(_EMPTY_SUMMARY),
                comparison_entries=[], findings=[], risk=risk,
                limitations=[str(exc)],
                analysis_complete=False,
            )
            report_generator.save_report(report)
            return report

        published_root = extract_archive(download_result.path, tmp_root / "published")
        published_manifest = manifest_generator.generate_manifest(published_root)
        published_package_json = _read_package_json(published_root) or registry_meta.raw_package_json
        tarball_sha512_hex = hashlib.sha512(download_result.path.read_bytes()).hexdigest()

        findings: List[Dict[str, Any]] = []
        findings.extend(metadata_analyzer.analyze_lifecycle_scripts(registry_meta.scripts))
        findings.extend(
            metadata_analyzer.analyze_declared_entrypoints(published_package_json, set(published_manifest.keys()))
        )
        findings.extend(
            metadata_analyzer.scan_code_patterns(published_root, list(published_manifest.keys()))
        )

        source_repo_url = None
        source_commit = None
        resolution_method = None
        correspondence = "NONE"
        source_directory = None
        source_package_json: Optional[Dict[str, Any]] = None
        summary = dict(_EMPTY_SUMMARY)
        comparison_entries: List[Dict[str, Any]] = []

        try:
            resolution = await source_resolver.resolve_source(
                registry_meta.repository, registry_meta.git_head, version
            )
            source_repo_url = resolution.repo.url
            source_commit = resolution.commit
            resolution_method = resolution.resolution_method
            correspondence = resolution.correspondence
            source_directory = resolution.repo.directory

            source_archive_dir = tmp_root / "source"
            source_archive_dir.mkdir(parents=True, exist_ok=True)
            archive_path = await source_resolver.download_source_archive(resolution, source_archive_dir)
            source_extracted_root = extract_archive(archive_path, tmp_root / "source_extracted")

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
            source_package_json = _read_package_json(source_content_root)

            comparison = comparator.compare_manifests(source_manifest, published_manifest, published_package_json)
            summary = comparison.summary
            comparison_entries = comparison.entries

            findings.extend(risk_engine.build_unexplained_findings(comparison_entries, published_manifest))
            findings.extend(risk_engine.build_unexpected_executable_findings(comparison_entries, published_manifest))
            findings.extend(
                metadata_analyzer.analyze_dependency_changes(
                    registry_meta.dependencies,
                    (source_package_json or {}).get("dependencies") if source_package_json else None,
                )
            )
            findings.extend(
                metadata_analyzer.analyze_lifecycle_script_changes(
                    registry_meta.scripts,
                    (source_package_json or {}).get("scripts") if source_package_json else None,
                )
            )

        except SourceResolutionError as exc:
            logger.info("Source resolution inconclusive for %s@%s: %s" % (package_name, version, exc))
            limitations.append(str(exc))
        except (ArchiveSecurityError, ArchiveCorruptionError, DownloadError) as exc:
            logger.warning("Source archive handling failed for %s@%s: %s" % (package_name, version, exc))
            correspondence = "NONE"
            limitations.append(f"Source archive could not be safely processed: {exc}")

        try:
            provenance = await provenance_checker.verify_provenance(
                attestations_meta=registry_meta.dist.attestations,
                signatures=registry_meta.dist.signatures,
                tarball_sha512_hex=tarball_sha512_hex,
                resolved_repo_url=source_repo_url,
                resolved_commit=source_commit,
            )
        except Exception as exc:  # noqa: BLE001 - provenance is best-effort, never fatal
            logger.warning("Provenance verification failed unexpectedly for %s@%s: %s" % (package_name, version, exc))
            provenance = {
                "provenance_status": "UNKNOWN",
                "registry_signature_present": bool(registry_meta.dist.signatures),
                "detail": "Provenance verification could not be completed due to an unexpected error.",
                "findings": [],
            }
        findings.extend(provenance.get("findings", []))

        risk = risk_engine.compute_risk(
            findings, tarball_verified=download_result.verified, correspondence=correspondence
        )

        if correspondence == "NONE":
            limitations.append(
                "File-level comparison was skipped because exact source correspondence could not be established."
            )
        if registry_meta.dist.integrity is None and registry_meta.dist.shasum:
            limitations.append("Only legacy SHA-1 shasum was available for tarball verification (no SRI integrity field).")
        if resolution_method == "tag":
            limitations.append("Source match is inferred from a version tag, not an exact gitHead commit.")
        if provenance["provenance_status"] in ("NOT_VERIFIED", "UNKNOWN"):
            limitations.append(
                "Provenance cryptographic signature chain (Fulcio certificate + Rekor transparency "
                "log) was not verified in this MVP; only attestation claims consistency was checked."
            )
        limitations.append(
            "Static pattern scanning cannot prove intent; absence of findings does not guarantee safety."
        )
        limitations.append(
            "No reproducible build was attempted; comparison is direct file-hash matching against the "
            "resolved source, not a verified rebuild."
        )

        report = report_generator.build_report(
            package_name=package_name, version=version,
            source_repo_url=source_repo_url, source_commit=source_commit,
            resolution_method=resolution_method, correspondence=correspondence,
            source_directory=source_directory,
            tarball_verified=download_result.verified,
            verification_algorithm=download_result.algorithm,
            provenance_status=provenance["provenance_status"],
            registry_signature_present=provenance["registry_signature_present"],
            provenance_detail=provenance.get("detail"),
            summary=summary, comparison_entries=comparison_entries,
            findings=findings, risk=risk, limitations=limitations,
            analysis_complete=True,
        )
        report_generator.save_report(report)
        return report
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
