"""npm adapter: wraps the existing npm metadata fetch + tarball verification + provenance check."""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.registries.base import Registry, Release, ReleaseArtifact
from app.services import metadata_analyzer, npm_registry, package_downloader, provenance_checker
from app.services.manifest_generator import FileRecord


class NpmRegistry(Registry):
    ecosystem = "npm"

    async def fetch_release(self, name: str, version: str, dest_dir: Path) -> Release:
        meta = await npm_registry.fetch_version_metadata(name, version)
        dest_dir.mkdir(parents=True, exist_ok=True)
        download = await package_downloader.download_and_verify_tarball(meta.dist, dest_dir)
        data = download.path.read_bytes()
        artifact = ReleaseArtifact(
            kind="tarball",
            filename=meta.dist.tarball.rsplit("/", 1)[-1] or "package.tgz",
            path=download.path,
            url=meta.dist.tarball,
            size=download.size,
            sha256=hashlib.sha256(data).hexdigest(),
            verified=download.verified,
            verification_algorithm=download.algorithm,
            selection_reason="npm publishes exactly one tarball per version.",
        )
        release = Release(
            ecosystem="npm", name=name, version=version, artifact=artifact,
            repository_field=meta.repository, git_head=meta.git_head,
            scripts=meta.scripts, dependencies=meta.dependencies,
            package_json=meta.raw_package_json, raw=meta,
        )
        release.extras["sha512_hex"] = hashlib.sha512(data).hexdigest()
        if meta.dist.integrity is None and meta.dist.shasum:
            release.notes.append("Only legacy SHA-1 shasum was available for tarball verification (no SRI integrity field).")
        return release

    def published_package_json(self, release: Release, published_root: Path) -> Optional[Dict[str, Any]]:
        path = published_root / "package.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict):
                    return data
            except (ValueError, OSError):
                pass
        return release.package_json

    def static_findings(self, release: Release, published_root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        package_json = self.published_package_json(release, published_root) or {}
        findings: List[Dict[str, Any]] = []
        # npm runs the scripts in the package.json INSIDE the tarball, not the ones shown by the registry API.
        scripts = package_json.get("scripts") if isinstance(package_json.get("scripts"), dict) else release.scripts
        findings.extend(self._manifest_confusion(release, published_root))
        findings.extend(metadata_analyzer.analyze_lifecycle_scripts(scripts))
        findings.extend(metadata_analyzer.analyze_declared_entrypoints(package_json, set(manifest.keys())))
        findings.extend(metadata_analyzer.scan_code_patterns(published_root, list(manifest.keys())))
        return findings

    @staticmethod
    def _manifest_confusion(release: Release, published_root: Path) -> List[Dict[str, Any]]:
        """The registry API and the tarball's own package.json can disagree ("manifest confusion"): tools
        that read the API see one set of scripts/dependencies while installation uses the other."""
        path = published_root / "package.json"
        if not path.is_file():
            return []
        try:
            tarball_json = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (ValueError, OSError):
            return []
        registry_json = release.package_json or {}
        if not isinstance(tarball_json, dict):
            return []
        differing = [
            key for key in ("scripts", "dependencies", "optionalDependencies", "bin")
            if (registry_json.get(key) or {}) != (tarball_json.get(key) or {})
        ]
        if not differing:
            return []
        return [{
            "rule_id": "MANIFEST_CONFUSION", "file": "package.json", "category": "manifest_confusion",
            "severity": "HIGH", "confidence": "HIGH",
            "evidence": "The registry metadata and the tarball's package.json disagree on: " + ", ".join(differing) + ".",
            "explanation": "npm shows and resolves one manifest but installs from another. Differences in scripts, dependencies or bin entries are a known technique for hiding install-time behaviour from tools that read only the registry API.",
            "recommendation": "Compare the registry's version document with the package.json inside the tarball before installing.",
        }]

    def source_findings(self, release: Release, source_root: Path, source_manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        source_pkg = None
        path = source_root / "package.json"
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                source_pkg = loaded if isinstance(loaded, dict) else None
            except (ValueError, OSError):
                source_pkg = None
        findings: List[Dict[str, Any]] = []
        findings.extend(metadata_analyzer.analyze_dependency_changes(release.dependencies, (source_pkg or {}).get("dependencies") if source_pkg else None))
        findings.extend(metadata_analyzer.analyze_lifecycle_script_changes(release.scripts, (source_pkg or {}).get("scripts") if source_pkg else None))
        return findings

    async def verify_provenance(self, release, resolved_repo_url, resolved_commit):
        meta = release.raw
        result = await provenance_checker.verify_provenance(
            attestations_meta=meta.dist.attestations,
            signatures=meta.dist.signatures,
            tarball_sha512_hex=release.extras["sha512_hex"],
            resolved_repo_url=resolved_repo_url,
            resolved_commit=resolved_commit,
        )
        return result
