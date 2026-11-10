"""Resolves the source repository and exact commit/tag corresponding to a
published npm version, following strict priority: gitHead > version tag >
unresolved. Only GitHub is supported for the MVP; other hosts are rejected
rather than guessed at.
"""
import asyncio
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse

import httpx

from app.config import settings
from app.utils.errors import DownloadError, SourceResolutionError, UpstreamRateLimitError
from app.utils.http_client import make_client, safe_get, safe_stream_download
from app.utils.logging import get_logger
from app.utils.security import validate_outbound_url

logger = get_logger(__name__)

# GitHub owner/repo character sets (owners: alphanumerics + single hyphens; repos: also '_' and '.').
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_REPO = r"[A-Za-z0-9_.-]{1,100}?"
_GITHUB_HTTP_RE = re.compile(rf"^(?:git\+)?https?://(?:www\.)?github\.com/({_OWNER})/({_REPO})(?:\.git)?/?$")
_GITHUB_GIT_RE = re.compile(rf"^git://github\.com/({_OWNER})/({_REPO})(?:\.git)?/?$")
_GITHUB_SHORTHAND_RE = re.compile(rf"^github:({_OWNER})/({_REPO})(?:\.git)?/?$")
_GITHUB_SSH_RE = re.compile(rf"^git@github\.com:({_OWNER})/({_REPO})(?:\.git)?/?$")
_BARE_SHORTHAND_RE = re.compile(rf"^({_OWNER})/({_REPO})$")
_GIT_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
_LOOSE_PATH_RE = re.compile(rf"^/({_OWNER})/({_REPO})(?:\.git)?(?:/.*)?$")

# Origins, strongest first. Used to explain how much to trust a resolved repository.
ORIGIN_USER = "user_supplied"
ORIGIN_METADATA = "registry_metadata"
ORIGIN_PROJECT_URL = "registry_project_url"
ORIGIN_HOMEPAGE = "registry_homepage"


@dataclass
class RepoRef:
    owner: str
    repo: str
    directory: Optional[str] = None
    origin: str = ORIGIN_METADATA

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def key(self) -> Tuple[str, str]:
        return (self.owner.lower(), self.repo.lower())


@dataclass
class SourceResolution:
    repo: RepoRef
    ref: str
    commit: Optional[str]
    resolution_method: str  # "gitHead" | "tag" | "unresolved"
    correspondence: str  # "EXACT" | "INFERRED" | "NONE"
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    notes: List[str] = field(default_factory=list)


def _valid_ref_part(owner: str, repo: str) -> bool:
    return repo not in (".", "..") and not repo.endswith(".lock")


def parse_github_repository(repository_field: Any, *, allow_shorthand: bool = True) -> Optional[RepoRef]:
    """Parse a package.json-style `repository` value, or a plain URL. Returns None for anything that
    isn't a recognizable GitHub reference (never guesses at other hosts). Owner/repo are restricted to
    GitHub's own character sets, so the result is always safe to interpolate into API URLs.
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

    patterns = [_GITHUB_HTTP_RE, _GITHUB_GIT_RE]
    if allow_shorthand:
        patterns += [_GITHUB_SHORTHAND_RE, _GITHUB_SSH_RE, _BARE_SHORTHAND_RE]
    for pattern in patterns:
        m = pattern.match(url)
        if m and _valid_ref_part(m.group(1), m.group(2)):
            return RepoRef(owner=m.group(1), repo=m.group(2), directory=directory if isinstance(directory, str) else None)
    # Explicit GitHub folder/file URLs are useful when a monorepo contains several packages.
    # Keep only the repository-relative directory; resolution still chooses the release's exact tag/commit.
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("https", "http") or (parsed.hostname or "").lower() not in ("github.com", "www.github.com"):
        return None
    parts = [unquote(part) for part in (parsed.path or "").split("/") if part]
    if len(parts) < 2 or not _valid_ref_part(parts[0], parts[1]):
        return None
    repo_name = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    folder = None
    if len(parts) > 2:
        if parts[2] == "tree" and len(parts) >= 4:
            folder = "/".join(parts[4:]) or None
        elif parts[2] == "blob" and len(parts) >= 5:
            folder = "/".join(parts[4:-1]) or None
        else:
            return None
    return RepoRef(owner=parts[0], repo=repo_name, directory=folder)


def extract_github_repo(url: Any) -> Optional[RepoRef]:
    """Find the owner/repo in any github.com URL (including /tree/main, /issues, /releases...), as found
    in PyPI project URLs. Non-GitHub hosts return None.
    """
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "").lower() not in ("github.com", "www.github.com"):
        return None
    m = _LOOSE_PATH_RE.match(parsed.path or "")
    if not m or not _valid_ref_part(m.group(1), m.group(2)):
        return None
    return RepoRef(owner=m.group(1), repo=m.group(2))


def _github_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "TrustPack-Analyzer"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    return headers


# Waiting longer than this for a rate limit to clear would blow the analysis time budget anyway, so a
# wait beyond it is treated as "not worth retrying" rather than slept through.
_MAX_RATE_LIMIT_WAIT_SECONDS = 10.0
_MAX_GITHUB_ATTEMPTS = 3


def _rate_limit_wait(resp: httpx.Response) -> Optional[float]:
    """Seconds to wait before retrying `resp`, if it shows GitHub is actually rate-limiting us —
    either the primary hourly quota or a short-lived secondary/abuse throttle. None for everything
    else, including a plain 403: GitHub also returns 403 when the token has no access to a repository
    (a fine-grained PAT scoped to other repos, SSO enforcement, a blocked app, ...), and retrying —
    or telling the user to raise GITHUB_TOKEN's limit — would never fix that.
    """
    if resp.status_code == 429:
        is_rate_limit = True
    elif resp.status_code == 403:
        if resp.headers.get("x-ratelimit-remaining") == "0":
            is_rate_limit = True
        else:
            try:
                message = str((resp.json() or {}).get("message", "")).lower()
            except ValueError:
                message = ""
            is_rate_limit = "rate limit" in message or "abuse" in message
    else:
        return None
    if not is_rate_limit:
        return None

    retry_after = (resp.headers.get("retry-after") or "").strip()
    if retry_after.isdigit():
        return float(retry_after)
    reset = (resp.headers.get("x-ratelimit-reset") or "").strip()
    if reset.isdigit():
        return max(1.0, float(reset) - time.time())
    return 2.0  # secondary/abuse limits rarely carry either header; a short default is enough


async def _github_get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET a GitHub API URL. A short-lived rate limit (secondary/abuse throttling, or the primary
    quota with a near-term reset) is waited out and retried automatically; only an exhausted primary
    quota with a far-off reset raises UpstreamRateLimitError, immediately rather than after a long
    sleep. A non-rate-limit response (including a plain 403) is returned as-is for the caller to
    interpret — see _rate_limit_wait.
    """
    resp = await safe_get(client, url, settings.ALLOWED_SOURCE_HOSTS, headers=_github_headers())
    for attempt in range(1, _MAX_GITHUB_ATTEMPTS):
        wait = _rate_limit_wait(resp)
        if wait is None:
            return resp  # not rate limited at all - whatever the status, it's final
        if wait > _MAX_RATE_LIMIT_WAIT_SECONDS:
            break  # rate limited, but waiting that long would blow the analysis budget - raise below
        logger.warning(
            "GitHub rate limited (attempt %d/%d), retrying in %.1fs: %s" % (attempt, _MAX_GITHUB_ATTEMPTS, wait, url)
        )
        await asyncio.sleep(wait)
        resp = await safe_get(client, url, settings.ALLOWED_SOURCE_HOSTS, headers=_github_headers())
    if _rate_limit_wait(resp) is not None:
        raise UpstreamRateLimitError(f"GitHub API rate limit exceeded for {url}")
    return resp


async def _commit_exists(client: httpx.AsyncClient, repo: RepoRef, sha: str) -> bool:
    url = f"{settings.GITHUB_API_URL}/repos/{repo.owner}/{repo.repo}/commits/{sha}"
    resp = await _github_get(client, url)
    if resp.status_code == 403:
        logger.info("GitHub returned 403 (not rate limiting) for %s/%s; GITHUB_TOKEN may lack access to this repository." % (repo.owner, repo.repo))
    return resp.status_code == 200


async def _lookup_tag(client: httpx.AsyncClient, repo: RepoRef, tag: str) -> Optional[Dict[str, Any]]:
    """Return the ref object for EXACTLY `tag`, else None. GitHub's refs endpoint answers 200 with a
    list of prefix matches when the exact tag is absent (v1.2 would 'match' v1.2.3), so a 200 alone
    is not evidence the tag exists.
    """
    url = f"{settings.GITHUB_API_URL}/repos/{repo.owner}/{repo.repo}/git/refs/tags/{quote(tag, safe='/@+')}"
    resp = await _github_get(client, url)
    if resp.status_code == 403:
        logger.info("GitHub returned 403 (not rate limiting) for %s/%s; GITHUB_TOKEN may lack access to this repository." % (repo.owner, repo.repo))
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    wanted = f"refs/tags/{tag}"
    if isinstance(data, list):
        return next((r for r in data if isinstance(r, dict) and r.get("ref") == wanted), None)
    if isinstance(data, dict) and data.get("ref") == wanted:
        return data
    return None


async def _peel_to_commit(client: httpx.AsyncClient, repo: RepoRef, ref_obj: Dict[str, Any]) -> Optional[str]:
    """Best effort: the commit SHA a tag ref points at (following one annotated-tag hop)."""
    obj = ref_obj.get("object") or {}
    sha, kind = obj.get("sha"), obj.get("type")
    if not isinstance(sha, str) or not _GIT_HEAD_RE.match(sha):
        return None
    if kind == "commit":
        return sha
    if kind == "tag":
        url = f"{settings.GITHUB_API_URL}/repos/{repo.owner}/{repo.repo}/git/tags/{sha}"
        resp = await _github_get(client, url)
        if resp.status_code == 200:
            try:
                target = (resp.json().get("object") or {})
            except ValueError:
                return None
            if target.get("type") == "commit" and isinstance(target.get("sha"), str) and _GIT_HEAD_RE.match(target["sha"]):
                return target["sha"]
    return None


def default_tag_candidates(version: str, package_name: Optional[str] = None) -> List[str]:
    tags = [f"v{version}", version]
    if package_name:
        tags += [f"{package_name}@{version}", f"{package_name}-{version}", f"release-{version}"]
    return list(dict.fromkeys(tags))


async def _resolve_in_repo(
    client: httpx.AsyncClient, repo: RepoRef, git_head: Optional[str], tags: List[str]
) -> Tuple[Optional[SourceResolution], bool]:
    """Try gitHead, then tags, in one repository. Returns (resolution_or_None, was_rate_limited)."""
    if git_head and _GIT_HEAD_RE.match(git_head):
        try:
            if await _commit_exists(client, repo, git_head):
                return SourceResolution(
                    repo=repo, ref=git_head, commit=git_head,
                    resolution_method="gitHead", correspondence="EXACT", confidence="HIGH",
                    notes=["gitHead commit published in the registry metadata exists in the repository."],
                ), False
        except UpstreamRateLimitError:
            logger.warning("GitHub rate limited while checking gitHead")
            return None, True

    for candidate_tag in tags:
        try:
            ref_obj = await _lookup_tag(client, repo, candidate_tag)
            if ref_obj is None:
                continue
            commit = await _peel_to_commit(client, repo, ref_obj)
        except UpstreamRateLimitError:
            logger.warning("GitHub rate limited while checking tags")
            return None, True
        return SourceResolution(
            repo=repo, ref=candidate_tag, commit=commit,
            resolution_method="tag", correspondence="INFERRED", confidence="MEDIUM",
            notes=[f"Matched version tag '{candidate_tag}'. A tag name is a convention, not proof that "
                   "the published artifact was built from it."],
        ), False
    return None, False


async def resolve_source(
    repository_field: Any,
    git_head: Optional[str],
    version: str,
    *,
    explicit_repo_url: Optional[str] = None,
    extra_candidates: Optional[Iterable[RepoRef]] = None,
    package_name: Optional[str] = None,
    tag_names: Optional[List[str]] = None,
) -> SourceResolution:
    """Resolve the source ref for `version`. Never guesses: a repository must be named by the user or by
    registry metadata, and a commit/tag must actually exist in it. Raises SourceResolutionError (callers
    treat it as non-fatal and degrade to an inconclusive report) when nothing can be established.

    Priority: (1) repository supplied by the user — used exclusively; (2) repository declared in package
    metadata; (3) other repository URLs found in registry metadata (PyPI project URLs, homepage).
    """
    tags = tag_names or default_tag_candidates(version, package_name)
    declared = parse_github_repository(repository_field)
    explicit = parse_github_repository(explicit_repo_url, allow_shorthand=False) if explicit_repo_url else None
    if explicit_repo_url and explicit is None:
        raise SourceResolutionError("The supplied repository URL is not a supported GitHub repository URL")

    notes: List[str] = []
    candidates: List[RepoRef] = []
    if explicit is not None:
        explicit.origin = ORIGIN_USER
        if declared is not None and declared.key != explicit.key:
            notes.append(
                f"The supplied repository ({explicit.owner}/{explicit.repo}) differs from the one declared in "
                f"package metadata ({declared.owner}/{declared.repo})."
            )
        candidates = [explicit]
    else:
        if declared is not None:
            declared.origin = ORIGIN_METADATA
            candidates.append(declared)
        for extra in extra_candidates or []:
            if all(extra.key != c.key for c in candidates):
                candidates.append(extra)
        candidates = candidates[:3]  # bound GitHub API usage

    if not candidates:
        raise SourceResolutionError(
            "No supported (GitHub) repository could be identified from package metadata"
        )

    was_rate_limited = False
    tried: List[str] = []
    async with make_client(httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)) as client:
        for repo in candidates:
            validate_outbound_url(repo.url, settings.ALLOWED_SOURCE_HOSTS)
            tried.append(f"{repo.owner}/{repo.repo}")
            resolution, limited = await _resolve_in_repo(client, repo, git_head, tags)
            was_rate_limited = was_rate_limited or limited
            if resolution is not None:
                resolution.notes = notes + resolution.notes
                if repo.origin == ORIGIN_USER:
                    resolution.notes.append("Repository was supplied by the user rather than verified from package metadata.")
                    if declared is None:
                        resolution.notes.append("Package metadata declares no repository to cross-check the supplied one against.")
                    elif declared.key != repo.key and resolution.confidence != "LOW":
                        resolution.confidence = "LOW"
                elif repo.origin == ORIGIN_HOMEPAGE and resolution.confidence != "HIGH":
                    resolution.confidence = "LOW"
                    resolution.notes.append("Repository was inferred from the package homepage, not a source-code link.")
                return resolution
            if limited:
                break

    where = ", ".join(tried)
    if was_rate_limited:
        raise UpstreamRateLimitError(
            f"GitHub API rate limit was hit while resolving {where}@{version}; "
            "source correspondence could not be verified (this is a rate-limit condition, not "
            "evidence that the tag/commit is absent). Set GITHUB_TOKEN to raise the rate limit."
        )

    raise SourceResolutionError(
        f"Could not establish exact source correspondence for {where}@{version} "
        "(no matching gitHead commit or version tag found)"
    )


async def download_source_archive(resolution: SourceResolution, dest_dir: Path) -> Path:
    """Download the GitHub codeload tarball for the resolved ref."""
    ref = resolution.commit or resolution.ref
    url = f"{settings.GITHUB_CODELOAD_URL}/{resolution.repo.owner}/{resolution.repo.repo}/tar.gz/{quote(ref, safe='/@+')}"

    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    dest_path = dest_dir / "source.tar.gz"
    async with make_client(timeout) as client:
        try:
            data = await safe_stream_download(
                client, url, settings.ALLOWED_SOURCE_HOSTS,
                max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES,
            )
        except DownloadError as exc:
            raise SourceResolutionError(f"Failed to download source archive from GitHub: {exc}") from exc
        dest_path.write_bytes(data)
    return dest_path
