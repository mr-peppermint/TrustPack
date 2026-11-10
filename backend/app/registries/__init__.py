"""Registry integrations, selected by normalized ecosystem identifier."""
from app.registries.base import Registry, Release, ReleaseArtifact
from app.utils.errors import UnsupportedEcosystemError


def get_registry(ecosystem: str) -> Registry:
    key = (ecosystem or "").lower()
    if key == "npm":
        from app.registries.npm_registry import NpmRegistry

        return NpmRegistry()
    if key == "pypi":
        from app.registries.pypi_registry import PyPIRegistry

        return PyPIRegistry()
    if key in {"maven", "nuget", "cargo", "go", "rubygems", "packagist", "pub", "hex", "cocoapods", "swiftpm", "conda", "linux", "oci"}:
        from app.registries.extended_registry import ExtendedRegistry

        return ExtendedRegistry(key)
    raise UnsupportedEcosystemError(f"Unsupported ecosystem '{ecosystem}'. Supported: npm, pypi, maven, nuget, cargo, go, rubygems, packagist, pub, hex, cocoapods, swiftpm, conda, linux, oci")


__all__ = ["Registry", "Release", "ReleaseArtifact", "get_registry"]
