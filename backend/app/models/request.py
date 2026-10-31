import re
from typing import Optional

from pydantic import BaseModel, field_validator, model_validator

SUPPORTED_ECOSYSTEMS = ("npm", "pypi")

# npm package name rules: optional @scope/, lowercase, no leading dot/underscore,
# url-safe characters only, max 214 chars total.
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$")
# Semver (simplified SemVer 2.0 pattern: core + optional prerelease/build).
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
# PEP 508 / PEP 503 project names.
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
# PEP 440 public versions (epoch, release, pre, post, dev, local), in normalized or common spellings.
_PEP440_RE = re.compile(
    r"^(?:\d+!)?\d+(?:\.\d+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?"
    r"(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?"
    r"(?:[-_.]?dev[-_.]?\d*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
    re.IGNORECASE,
)


class AnalyzeRequest(BaseModel):
    package_name: str
    version: str
    ecosystem: str = "npm"
    repository_url: Optional[str] = None

    @field_validator("package_name", "version", mode="before")
    @classmethod
    def _strip(cls, v):
        return v.strip() if isinstance(v, str) else v

    @field_validator("ecosystem", mode="before")
    @classmethod
    def _normalize_ecosystem(cls, v):
        value = (v or "npm").strip().lower() if isinstance(v, str) or v is None else v
        if value not in SUPPORTED_ECOSYSTEMS:
            raise ValueError("ecosystem must be one of: %s" % ", ".join(SUPPORTED_ECOSYSTEMS))
        return value

    @field_validator("repository_url", mode="before")
    @classmethod
    def _validate_repository_url(cls, v):
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("repository_url must be a string")
        v = v.strip()
        if not v:
            return None
        # Imported lazily: services depend on utils, never the reverse.
        from app.services.source_resolver import parse_github_repository

        if len(v) > 300 or parse_github_repository(v, allow_shorthand=False) is None:
            raise ValueError("repository_url must be a GitHub repository URL such as https://github.com/owner/repo")
        return v

    @model_validator(mode="after")
    def _validate_name_and_version(self):
        if self.ecosystem == "npm":
            if not (0 < len(self.package_name) <= 214 and _NPM_NAME_RE.match(self.package_name)):
                raise ValueError(
                    "package_name must be a valid npm package name "
                    "(optionally scoped, e.g. 'lodash' or '@babel/core')"
                )
            if not _SEMVER_RE.match(self.version):
                raise ValueError("version must be an exact semantic version, e.g. '1.2.3'")
        else:
            if not (0 < len(self.package_name) <= 214 and _PYPI_NAME_RE.match(self.package_name)):
                raise ValueError("package_name must be a valid PyPI project name, e.g. 'requests'")
            if len(self.version) > 64 or not _PEP440_RE.match(self.version):
                raise ValueError("version must be an exact PEP 440 version, e.g. '2.32.0'")
        return self
