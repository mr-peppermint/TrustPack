"""Centralized application configuration, loaded from environment variables."""
import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv

_BACKEND_DIR = Path(__file__).resolve().parent.parent
# Real environment variables win over .env (override=False).
load_dotenv(_BACKEND_DIR / ".env", override=False)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: str) -> List[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings:
    # Upstream services
    NPM_REGISTRY_URL: str = os.getenv("NPM_REGISTRY_URL", "https://registry.npmjs.org")
    GITHUB_API_URL: str = os.getenv("GITHUB_API_URL", "https://api.github.com")
    GITHUB_CODELOAD_URL: str = os.getenv("GITHUB_CODELOAD_URL", "https://codeload.github.com")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    PYPI_URL: str = os.getenv("PYPI_URL", "https://pypi.org")

    ALLOWED_TARBALL_HOSTS: List[str] = _env_list(
        "ALLOWED_TARBALL_HOSTS", "registry.npmjs.org"
    )
    ALLOWED_PYPI_HOSTS: List[str] = _env_list(
        "ALLOWED_PYPI_HOSTS", "pypi.org,files.pythonhosted.org"
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
    MAX_METADATA_BYTES: int = int(os.getenv("MAX_METADATA_BYTES", str(20 * 1024 * 1024)))
    # Zip entries larger than 1 MiB whose uncompressed/compressed ratio exceeds this are rejected as bombs.
    MAX_COMPRESSION_RATIO: int = int(os.getenv("MAX_COMPRESSION_RATIO", "1000"))
    MAX_PATH_DEPTH: int = int(os.getenv("MAX_PATH_DEPTH", "32"))
    MAX_PATH_LENGTH: int = int(os.getenv("MAX_PATH_LENGTH", "4096"))

    # Persistent analysis history (SQLite). Oldest reports beyond the retention limit are pruned;
    # REPORT_TTL_SECONDS=0 (default) means reports never expire by age.
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", str(_BACKEND_DIR / "data" / "trustpack.db"))
    REPORT_RETENTION_LIMIT: int = int(os.getenv("REPORT_RETENTION_LIMIT", "1000"))
    REPORT_TTL_SECONDS: int = int(os.getenv("REPORT_TTL_SECONDS", "0"))

    # Concurrency / timeouts
    MAX_CONCURRENT_ANALYSES: int = int(os.getenv("MAX_CONCURRENT_ANALYSES", "3"))
    ANALYSIS_TIMEOUT_SECONDS: float = float(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "90"))

    # AI explanations (optional; the deterministic analysis never depends on them)
    AI_ENABLED: bool = _env_bool("AI_ENABLED", False)
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "groq")
    AI_MODEL: str = os.getenv("AI_MODEL", "openai/gpt-oss-120b")
    AI_API_KEY: str = os.getenv("AI_API_KEY", "")
    AI_BASE_URL: str = os.getenv("AI_BASE_URL", "")
    AI_TIMEOUT: float = float(os.getenv("AI_TIMEOUT", "60"))
    AI_MAX_FINDINGS: int = int(os.getenv("AI_MAX_FINDINGS", "25"))

    # CORS
    CORS_ORIGINS: List[str] = _env_list(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    )

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
