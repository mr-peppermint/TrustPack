"""Domain exceptions for TrustPack.

Each exception carries an `http_status` so the API layer can translate it
into a consistent JSON error response without string-matching messages.
"""
from typing import Optional


class TrustPackError(Exception):
    http_status: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, *, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidPackageNameError(TrustPackError):
    http_status = 422
    code = "invalid_package_name"


class InvalidVersionError(TrustPackError):
    http_status = 422
    code = "invalid_version"


class UnsupportedEcosystemError(TrustPackError):
    http_status = 422
    code = "unsupported_ecosystem"


class PackageNotFoundError(TrustPackError):
    http_status = 404
    code = "package_not_found"


class VersionNotFoundError(TrustPackError):
    http_status = 404
    code = "version_not_found"


class RegistryError(TrustPackError):
    http_status = 502
    code = "registry_error"


class UpstreamTimeoutError(TrustPackError):
    http_status = 504
    code = "upstream_timeout"


class AnalysisTimeoutError(TrustPackError):
    http_status = 504
    code = "analysis_timeout"


class UpstreamRateLimitError(TrustPackError):
    http_status = 429
    code = "upstream_rate_limited"


class DownloadError(TrustPackError):
    http_status = 502
    code = "download_error"


class IntegrityVerificationError(TrustPackError):
    http_status = 502
    code = "integrity_verification_failed"


class ArchiveSecurityError(TrustPackError):
    http_status = 502
    code = "archive_security_violation"


class ArchiveCorruptionError(TrustPackError):
    http_status = 502
    code = "archive_corrupted"


class SourceResolutionError(TrustPackError):
    """Non-fatal: callers should catch this and degrade to INCONCLUSIVE."""
    http_status = 502
    code = "source_resolution_failed"


class ReportNotFoundError(TrustPackError):
    http_status = 404
    code = "report_not_found"


class UnsupportedHostError(TrustPackError):
    http_status = 422
    code = "unsupported_host"
