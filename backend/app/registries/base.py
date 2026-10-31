"""The ecosystem-neutral contract between registries and the shared analysis pipeline.

A registry's job ends at "here is the verified release artifact on disk plus normalized metadata".
Everything after that — extraction, hashing, source resolution, comparison, generated-file detection,
provenance reporting and risk scoring — is shared, so npm and PyPI cannot drift apart.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.manifest_generator import FileRecord
from app.services.source_resolver import RepoRef


@dataclass
class ReleaseArtifact:
    kind: str  # tarball | sdist | wheel
    filename: str
    path: Path
    url: str
    size: int
    sha256: str  # always computed locally from the downloaded bytes
    verified: Optional[bool]  # None = the registry published no digest to check against
    verification_algorithm: Optional[str]
    selection_reason: str
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    published_at: Optional[str] = None  # ISO-8601, when the registry reports it


@dataclass
class Release:
    ecosystem: str
    name: str
    version: str
    artifact: ReleaseArtifact
    repository_field: Any = None  # package.json-style `repository` value (npm)
    git_head: Optional[str] = None
    extra_repo_candidates: List[RepoRef] = field(default_factory=list)  # e.g. PyPI project URLs
    tag_names: Optional[List[str]] = None
    scripts: Dict[str, str] = field(default_factory=dict)
    dependencies: Dict[str, str] = field(default_factory=dict)
    package_json: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)  # limitations discovered while fetching
    raw: Any = None  # registry-specific metadata object, only read by the owning registry
    extras: Dict[str, Any] = field(default_factory=dict)  # registry-private values (e.g. extra digests)

    @property
    def unwrap_archive(self) -> bool:
        """Wheels keep their stored layout; everything else is unwrapped from its single root directory."""
        return self.artifact.kind != "wheel"


class Registry(ABC):
    ecosystem: str

    @abstractmethod
    async def fetch_release(self, name: str, version: str, dest_dir: Path) -> Release:
        """Fetch exact-version metadata and the artifact, verifying the registry's checksum.
        Raises PackageNotFoundError / VersionNotFoundError / RegistryError / DownloadError /
        IntegrityVerificationError."""

    @abstractmethod
    def published_package_json(self, release: Release, published_root: Path) -> Optional[Dict[str, Any]]:
        """package.json-like metadata used by the generated-file detector (None when not applicable)."""

    @abstractmethod
    def static_findings(self, release: Release, published_root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        """Ecosystem-specific checks that need only the published artifact (install scripts, .pth, ...)."""

    @abstractmethod
    def source_findings(
        self, release: Release, source_root: Path, source_manifest: Dict[str, FileRecord]
    ) -> List[Dict[str, Any]]:
        """Ecosystem-specific checks that compare release metadata with the resolved source tree."""

    @abstractmethod
    async def verify_provenance(
        self, release: Release, resolved_repo_url: Optional[str], resolved_commit: Optional[str]
    ) -> Dict[str, Any]:
        """Return {provenance_status, registry_signature_present, detail, findings, claims}."""
