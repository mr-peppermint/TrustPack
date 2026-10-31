"""npm registry integration: fetch version-exact metadata for a package."""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

from app.config import settings
from app.utils.errors import (
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)
from app.utils.http_client import request_with_retries
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DistMetadata:
    tarball: str
    integrity: Optional[str] = None
    shasum: Optional[str] = None
    attestations: Optional[dict] = None
    signatures: Optional[list] = None


@dataclass
class RegistryMetadata:
    name: str
    version: str
    dist: DistMetadata
    repository: Optional[Any] = None
    git_head: Optional[str] = None
    scripts: Dict[str, str] = field(default_factory=dict)
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    optional_dependencies: Dict[str, str] = field(default_factory=dict)
    bundled_dependencies: Any = None
    raw_package_json: Dict[str, Any] = field(default_factory=dict)


def _encode_name(name: str) -> str:
    # Keep '@' and '/' unescaped so scoped packages hit the registry's native route.
    return quote(name, safe="@/")


async def fetch_version_metadata(package_name: str, version: str) -> RegistryMetadata:
    """Fetch exact-version metadata. Never substitutes a different version."""
    url = f"{settings.NPM_REGISTRY_URL}/{_encode_name(package_name)}/{quote(version, safe='')}"

    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await request_with_retries(client, url, settings.ALLOWED_TARBALL_HOSTS)

        if resp.status_code == 404:
            # Disambiguate "package doesn't exist" from "version doesn't exist".
            pkg_url = f"{settings.NPM_REGISTRY_URL}/{_encode_name(package_name)}"
            pkg_resp = await request_with_retries(client, pkg_url, settings.ALLOWED_TARBALL_HOSTS)
            if pkg_resp.status_code == 404:
                raise PackageNotFoundError(f"Package '{package_name}' was not found on the npm registry")
            raise VersionNotFoundError(
                f"Version '{version}' was not found for package '{package_name}'"
            )
        if resp.status_code >= 500:
            raise RegistryError(f"npm registry returned {resp.status_code} for {url}")
        if resp.status_code != 200:
            raise RegistryError(f"Unexpected npm registry response {resp.status_code} for {url}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise RegistryError("npm registry returned malformed JSON") from exc

    if data.get("name") != package_name or data.get("version") != version:
        # Defense in depth: never silently accept a mismatched document.
        raise RegistryError("npm registry returned metadata for a different package/version")

    dist_raw = data.get("dist") or {}
    if not dist_raw.get("tarball"):
        raise RegistryError("npm registry metadata is missing dist.tarball")

    dist = DistMetadata(
        tarball=dist_raw["tarball"],
        integrity=dist_raw.get("integrity"),
        shasum=dist_raw.get("shasum"),
        attestations=dist_raw.get("attestations"),
        signatures=dist_raw.get("signatures"),
    )

    return RegistryMetadata(
        name=data["name"],
        version=data["version"],
        dist=dist,
        repository=data.get("repository"),
        git_head=data.get("gitHead"),
        scripts=data.get("scripts") or {},
        dependencies=data.get("dependencies") or {},
        dev_dependencies=data.get("devDependencies") or {},
        optional_dependencies=data.get("optionalDependencies") or {},
        bundled_dependencies=data.get("bundledDependencies"),
        raw_package_json=data,
    )
