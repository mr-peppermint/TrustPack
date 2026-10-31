"""Registry integrations. `get_registry("npm" | "pypi")` returns the matching Registry."""
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
    raise UnsupportedEcosystemError(f"Unsupported ecosystem '{ecosystem}'. Supported: npm, pypi")


__all__ = ["Registry", "Release", "ReleaseArtifact", "get_registry"]
