import re

from pydantic import BaseModel, field_validator

# npm package name rules: optional @scope/, lowercase, no leading dot/underscore,
# url-safe characters only, max 214 chars total.
_NAME_RE = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$"
)
# Semver (simplified SemVer 2.0 pattern: core + optional prerelease/build).
_VERSION_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class AnalyzeRequest(BaseModel):
    package_name: str
    version: str

    @field_validator("package_name")
    @classmethod
    def validate_package_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) == 0 or len(v) > 214 or not _NAME_RE.match(v):
            raise ValueError(
                "package_name must be a valid npm package name "
                "(optionally scoped, e.g. 'lodash' or '@babel/core')"
            )
        return v

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        v = v.strip()
        if not _VERSION_RE.match(v):
            raise ValueError(
                "version must be an exact semantic version, e.g. '1.2.3'"
            )
        return v
