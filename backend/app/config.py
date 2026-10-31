"""Centralized application configuration, loaded from environment variables."""
import os
from typing import List


def _env_list(name: str, default: str) -> List[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings:
    # Upstream services
    NPM_REGISTRY_URL: str = os.getenv("NPM_REGISTRY_URL", "https://registry.npmjs.org")
    GITHUB_API_URL: str = os.getenv("GITHUB_API_URL", "https://api.github.com")
    GITHUB_CODELOAD_URL: str = os.getenv("GITHUB_CODELOAD_URL", "https://codeload.github.com")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    ALLOWED_TARBALL_HOSTS: List[str] = _env_list(
        "ALLOWED_TARBALL_HOSTS", "registry.npmjs.org"
    )
    ALLOWED_SOURCE_HOSTS: List[str] = _env_list(
        "ALLOWED_SOURCE_HOSTS", "github.com,codeload.github.com,api.github.com"
    )

    # HTTP behavior
    HTTP_TIMEOUT_SECONDS: float = float(os.getenv("HTTP_TIMEOUT_SECONDS", "15"))
    HTTP_MAX_RETRIES: int = int(os.getenv("HTTP_MAX_RETRIES", "2"))
    MAX_REDIRECTS: int = int(os.getenv("MAX_REDIRECTS", "5"))

    # Archive / resource limits
    MAX_TARBALL_SIZE_BYTES: int = int(os.getenv("MAX_TARBALL_SIZE_BYTES", str(50 * 1024 * 1024)))
    MAX_EXTRACTED_SIZE_BYTES: int = int(os.getenv("MAX_EXTRACTED_SIZE_BYTES", str(200 * 1024 * 1024)))
    MAX_SINGLE_FILE_SIZE_BYTES: int = int(os.getenv("MAX_SINGLE_FILE_SIZE_BYTES", str(20 * 1024 * 1024)))
    MAX_FILE_COUNT: int = int(os.getenv("MAX_FILE_COUNT", "20000"))
    MAX_PATH_DEPTH: int = int(os.getenv("MAX_PATH_DEPTH", "32"))
    MAX_PATH_LENGTH: int = int(os.getenv("MAX_PATH_LENGTH", "4096"))

    # Report store
    REPORT_RETENTION_LIMIT: int = int(os.getenv("REPORT_RETENTION_LIMIT", "200"))
    REPORT_TTL_SECONDS: int = int(os.getenv("REPORT_TTL_SECONDS", str(60 * 60)))

    # Concurrency / timeouts
    MAX_CONCURRENT_ANALYSES: int = int(os.getenv("MAX_CONCURRENT_ANALYSES", "3"))
    ANALYSIS_TIMEOUT_SECONDS: float = float(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "90"))

    # CORS
    CORS_ORIGINS: List[str] = _env_list(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    )

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
