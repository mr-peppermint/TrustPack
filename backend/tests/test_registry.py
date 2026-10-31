import httpx
import pytest
import respx

from app.config import settings
from app.services import npm_registry
from app.utils.errors import PackageNotFoundError, RegistryError, UpstreamRateLimitError, VersionNotFoundError


@respx.mock
async def test_fetch_valid_package_metadata():
    url = f"{settings.NPM_REGISTRY_URL}/left-pad/1.3.0"
    respx.get(url).mock(return_value=httpx.Response(200, json={
        "name": "left-pad", "version": "1.3.0",
        "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                 "integrity": "sha512-abc==", "shasum": "deadbeef"},
        "repository": {"type": "git", "url": "git+https://github.com/stevemao/left-pad.git"},
        "gitHead": "a" * 40,
    }))

    meta = await npm_registry.fetch_version_metadata("left-pad", "1.3.0")
    assert meta.name == "left-pad"
    assert meta.version == "1.3.0"
    assert meta.dist.tarball.endswith(".tgz")
    assert meta.git_head == "a" * 40


@respx.mock
async def test_fetch_scoped_package_metadata():
    url = f"{settings.NPM_REGISTRY_URL}/@babel%2Fcore/7.22.0"
    respx.get(url).mock(return_value=httpx.Response(200, json={
        "name": "@babel/core", "version": "7.22.0",
        "dist": {"tarball": "https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz", "shasum": "cafebabe"},
    }))

    meta = await npm_registry.fetch_version_metadata("@babel/core", "7.22.0")
    assert meta.name == "@babel/core"


@respx.mock
async def test_nonexistent_package_raises_package_not_found():
    pkg_url = f"{settings.NPM_REGISTRY_URL}/totally-fake-pkg-xyz/1.0.0"
    full_url = f"{settings.NPM_REGISTRY_URL}/totally-fake-pkg-xyz"
    respx.get(pkg_url).mock(return_value=httpx.Response(404))
    respx.get(full_url).mock(return_value=httpx.Response(404))

    with pytest.raises(PackageNotFoundError):
        await npm_registry.fetch_version_metadata("totally-fake-pkg-xyz", "1.0.0")


@respx.mock
async def test_nonexistent_version_raises_version_not_found():
    version_url = f"{settings.NPM_REGISTRY_URL}/left-pad/99.99.99"
    full_url = f"{settings.NPM_REGISTRY_URL}/left-pad"
    respx.get(version_url).mock(return_value=httpx.Response(404))
    respx.get(full_url).mock(return_value=httpx.Response(200, json={"name": "left-pad", "versions": {"1.3.0": {}}}))

    with pytest.raises(VersionNotFoundError):
        await npm_registry.fetch_version_metadata("left-pad", "99.99.99")


@respx.mock
async def test_missing_repository_metadata_is_tolerated():
    url = f"{settings.NPM_REGISTRY_URL}/no-repo-pkg/1.0.0"
    respx.get(url).mock(return_value=httpx.Response(200, json={
        "name": "no-repo-pkg", "version": "1.0.0",
        "dist": {"tarball": "https://registry.npmjs.org/no-repo-pkg/-/no-repo-pkg-1.0.0.tgz"},
    }))

    meta = await npm_registry.fetch_version_metadata("no-repo-pkg", "1.0.0")
    assert meta.repository is None
    assert meta.git_head is None


@respx.mock
async def test_malformed_json_raises_registry_error():
    url = f"{settings.NPM_REGISTRY_URL}/broken-pkg/1.0.0"
    respx.get(url).mock(return_value=httpx.Response(200, content=b"not json"))

    with pytest.raises(RegistryError):
        await npm_registry.fetch_version_metadata("broken-pkg", "1.0.0")


@respx.mock
async def test_rate_limit_raises_upstream_rate_limit_error():
    url = f"{settings.NPM_REGISTRY_URL}/rate-limited-pkg/1.0.0"
    respx.get(url).mock(return_value=httpx.Response(429))

    with pytest.raises(UpstreamRateLimitError):
        await npm_registry.fetch_version_metadata("rate-limited-pkg", "1.0.0")


@respx.mock
async def test_missing_dist_tarball_raises_registry_error():
    url = f"{settings.NPM_REGISTRY_URL}/weird-pkg/1.0.0"
    respx.get(url).mock(return_value=httpx.Response(200, json={
        "name": "weird-pkg", "version": "1.0.0", "dist": {},
    }))

    with pytest.raises(RegistryError):
        await npm_registry.fetch_version_metadata("weird-pkg", "1.0.0")
