"""Resolves the source repository and exact commit/tag corresponding to a
published npm version, following strict priority: gitHead > version tag >
unresolved. Only GitHub is supported for the MVP; other hosts are rejected
rather than guessed at.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from app.config import settings
from app.utils.errors import DownloadError, SourceResolutionError, UpstreamRateLimitError
from app.utils.http_client import safe_get, safe_stream_download
from app.utils.logging import get_logger
from app.utils.security import validate_outbound_url

logger = get_logger(__name__)

_GITHUB_HTTP_RE = re.compile(
    r"^(?:git\+)?https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"
)
_GITHUB_GIT_RE = re.compile(r"^git://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
_GITHUB_SHORTHAND_RE = re.compile(r"^github:([^/]+)/([^/]+?)(?:\.git)?/?$")
_GITHUB_SSH_RE = re.compile(r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?/?$")
_BARE_SHORTHAND_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_GIT_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class RepoRef:
    owner: str
    repo: str
    directory: Optional[str] = None

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


@dataclass
class SourceResolution:
    repo: RepoRef
    ref: str
    commit: Optional[str]
    resolution_method: str  # "gitHead" | "tag" | "unresolved"
    correspondence: str  # "EXACT" | "INFERRED" | "NONE"


def parse_github_repository(repository_field: Any) -> Optional[RepoRef]:
    """Parse package.json's `repository` field. Returns None for anything
    that isn't a recognizable GitHub reference (never guesses at other hosts).
    """
    if repository_field is None:
        return None

    directory = None
    if isinstance(repository_field, dict):
        directory = repository_field.get("directory")
        url = repository_field.get("url")
    else:
        url = repository_field

    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()

    for pattern in (_GITHUB_HTTP_RE, _GITHUB_GIT_RE, _GITHUB_SHORTHAND_RE, _GITHUB_SSH_RE):
        m = pattern.match(url)
        if m:
            return RepoRef(owner=m.group(1), repo=m.group(2), directory=directory)

    m = _BARE_SHORTHAND_RE.match(url)
    if m:
        return RepoRef(owner=m.group(1), repo=m.group(2), directory=directory)

    return None


def _github_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "TrustPack-Analyzer"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    return headers


async def _commit_exists(client: httpx.AsyncClient, repo: RepoRef, sha: str) -> bool:
    url = f"{settings.GITHUB_API_URL}/repos/{repo.owner}/{repo.repo}/commits/{sha}"
    resp = await safe_get(client, url, settings.ALLOWED_SOURCE_HOSTS, headers=_github_headers())
    if resp.status_code == 403 or resp.status_code == 429:
        raise UpstreamRateLimitError("GitHub API rate limit exceeded while verifying commit")
    return resp.status_code == 200


async def _tag_exists(client: httpx.AsyncClient, repo: RepoRef, tag: str) -> bool:
    url = f"{settings.GITHUB_API_URL}/repos/{repo.owner}/{repo.repo}/git/refs/tags/{tag}"
    resp = await safe_get(client, url, settings.ALLOWED_SOURCE_HOSTS, headers=_github_headers())
    if resp.status_code == 403 or resp.status_code == 429:
        raise UpstreamRateLimitError("GitHub API rate limit exceeded while verifying tag")
    return resp.status_code == 200


async def resolve_source(
    repository_field: Any, git_head: Optional[str], version: str
) -> SourceResolution:
    """Resolve the exact source ref for `version`. Raises SourceResolutionError
    (callers should treat this as non-fatal and degrade to an INCONCLUSIVE report)
    when no repository can be identified or reached.
    """
    repo = parse_github_repository(repository_field)
    if repo is None:
        raise SourceResolutionError(
            "No supported (GitHub) repository could be identified from package metadata"
        )

    validate_outbound_url(repo.url, settings.ALLOWED_SOURCE_HOSTS)

    was_rate_limited = False
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if git_head and _GIT_HEAD_RE.match(git_head):
            try:
                if await _commit_exists(client, repo, git_head):
                    return SourceResolution(
                        repo=repo, ref=git_head, commit=git_head,
                        resolution_method="gitHead", correspondence="EXACT",
                    )
            except UpstreamRateLimitError:
                was_rate_limited = True
                logger.warning("GitHub rate limited while checking gitHead; falling back to tag match")

        if not was_rate_limited:
            for candidate_tag in (f"v{version}", version):
                try:
                    if await _tag_exists(client, repo, candidate_tag):
                        return SourceResolution(
                            repo=repo, ref=candidate_tag, commit=None,
                            resolution_method="tag", correspondence="INFERRED",
                        )
                except UpstreamRateLimitError:
                    was_rate_limited = True
                    logger.warning("GitHub rate limited while checking tags")
                    break

    if was_rate_limited:
        raise SourceResolutionError(
            f"GitHub API rate limit was hit while resolving {repo.owner}/{repo.repo}@{version}; "
            "source correspondence could not be verified (this is a rate-limit condition, not "
            "evidence that the tag/commit is absent). Set GITHUB_TOKEN to raise the rate limit."
        )

    raise SourceResolutionError(
        f"Could not establish exact source correspondence for {repo.owner}/{repo.repo}@{version} "
        "(no matching gitHead commit or version tag found)"
    )


async def download_source_archive(resolution: SourceResolution, dest_dir: Path) -> Path:
    """Download the GitHub codeload tarball for the resolved ref."""
    ref = resolution.commit or resolution.ref
    url = f"{settings.GITHUB_CODELOAD_URL}/{resolution.repo.owner}/{resolution.repo.repo}/tar.gz/{ref}"

    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    dest_path = dest_dir / "source.tar.gz"
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            data = await safe_stream_download(
                client, url, settings.ALLOWED_SOURCE_HOSTS,
                max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES,
            )
        except DownloadError as exc:
            raise SourceResolutionError(f"Failed to download source archive from GitHub: {exc}") from exc
        dest_path.write_bytes(data)
    return dest_path
