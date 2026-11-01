import httpx
import pytest
import respx

from app.services.source_resolver import parse_github_repository, resolve_source
from app.utils.errors import SourceResolutionError, UpstreamRateLimitError

GIT_HEAD = "a" * 40


def test_parse_github_repository_https_form():
    repo = parse_github_repository({"type": "git", "url": "git+https://github.com/owner/repo.git"})
    assert repo.owner == "owner"
    assert repo.repo == "repo"


def test_parse_github_repository_shorthand():
    repo = parse_github_repository("github:owner/repo")
    assert repo.owner == "owner"
    assert repo.repo == "repo"


def test_parse_github_repository_bare_shorthand():
    repo = parse_github_repository("owner/repo")
    assert repo.owner == "owner"
    assert repo.repo == "repo"


def test_parse_github_repository_with_directory():
    repo = parse_github_repository({
        "type": "git", "url": "https://github.com/owner/monorepo", "directory": "packages/foo",
    })
    assert repo.directory == "packages/foo"


def test_parse_github_repository_rejects_non_github_host():
    repo = parse_github_repository("https://gitlab.com/owner/repo.git")
    assert repo is None


def test_parse_github_repository_none_for_missing_field():
    assert parse_github_repository(None) is None


@respx.mock
async def test_resolve_source_with_valid_gitHead_is_exact():
    respx.get(f"https://api.github.com/repos/owner/repo/commits/{GIT_HEAD}").mock(
        return_value=httpx.Response(200, json={"sha": GIT_HEAD})
    )
    resolution = await resolve_source({"url": "https://github.com/owner/repo"}, GIT_HEAD, "1.0.0")
    assert resolution.correspondence == "EXACT"
    assert resolution.resolution_method == "gitHead"
    assert resolution.commit == GIT_HEAD


@respx.mock
async def test_resolve_source_with_incorrect_gitHead_falls_back_to_tag():
    """gitHead in the registry metadata doesn't correspond to a real commit
    (e.g. a stale/incorrect value) — must not be trusted blindly; falls back
    to tag matching rather than reporting a false EXACT match.
    """
    respx.get(f"https://api.github.com/repos/owner/repo/commits/{GIT_HEAD}").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(200, json={"ref": "refs/tags/v1.0.0"})
    )
    resolution = await resolve_source({"url": "https://github.com/owner/repo"}, GIT_HEAD, "1.0.0")
    assert resolution.correspondence == "INFERRED"
    assert resolution.resolution_method == "tag"


@respx.mock
async def test_resolve_source_with_no_repository_raises():
    with pytest.raises(SourceResolutionError):
        await resolve_source(None, None, "1.0.0")


@respx.mock
async def test_resolve_source_with_no_match_raises():
    respx.get(f"https://api.github.com/repos/owner/repo/commits/{GIT_HEAD}").mock(return_value=httpx.Response(404))
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/v1.0.0").mock(return_value=httpx.Response(404))
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/1.0.0").mock(return_value=httpx.Response(404))
    with pytest.raises(SourceResolutionError):
        await resolve_source({"url": "https://github.com/owner/repo"}, GIT_HEAD, "1.0.0")


@respx.mock
async def test_resolve_source_github_rate_limit_is_reported_distinctly():
    """A 403/429 from GitHub must be reported as a rate-limit condition (its own exception type), not
    misreported as 'no matching tag/commit found' (SourceResolutionError) — callers rely on the
    distinction to avoid caching a result that only looks empty because of a transient rate limit.
    """
    respx.get(f"https://api.github.com/repos/owner/repo/commits/{GIT_HEAD}").mock(return_value=httpx.Response(403))
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/v1.0.0").mock(return_value=httpx.Response(403))
    with pytest.raises(UpstreamRateLimitError) as exc_info:
        await resolve_source({"url": "https://github.com/owner/repo"}, GIT_HEAD, "1.0.0")
    assert "rate limit" in str(exc_info.value).lower()
