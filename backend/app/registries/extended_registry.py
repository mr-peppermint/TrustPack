"""Adapters for additional public package ecosystems.

These adapters normalize release metadata and use the shared SSRF-safe HTTP helpers. Registry-specific
checksums are verified where the registry exposes a portable digest; where it does not, the report
records that the artifact could not be registry-verified.
"""
import base64
import hashlib
import json
import re
import shutil
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from app.config import settings
from app.registries.base import Registry, Release, ReleaseArtifact
from app.services.manifest_generator import FileRecord
from app.services.source_resolver import extract_github_repo
from app.utils.errors import DownloadError, PackageNotFoundError, RegistryError, VersionNotFoundError
from app.utils.http_client import make_client, request_with_retries, safe_stream_download


_HOSTS = {
    "maven": ["search.maven.org", "repo.maven.apache.org"],
    "nuget": ["api.nuget.org"],
    "cargo": ["crates.io", "static.crates.io"],
    "go": ["proxy.golang.org", "sum.golang.org"],
    "rubygems": ["rubygems.org", "rubygems.global.ssl.fastly.net"],
    "packagist": ["packagist.org", "codeload.github.com", "github.com"],
    "pub": ["pub.dev", "storage.googleapis.com"],
    "hex": ["hex.pm", "repo.hex.pm"],
    "cocoapods": ["trunk.cocoapods.org", "api.github.com", "github.com", "codeload.github.com"],
    "swiftpm": ["api.github.com", "github.com", "codeload.github.com"],
    "conda": ["api.anaconda.org", "conda.anaconda.org", "repo.anaconda.com"],
    "linux": ["snapshot.debian.org", "deb.debian.org", "archive.ubuntu.com", "dl-cdn.alpinelinux.org"],
    "oci": ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"],
}


async def _json(client: httpx.AsyncClient, url: str, hosts: List[str]) -> Tuple[httpx.Response, Any]:
    response = await request_with_retries(client, url, hosts)
    if response.status_code == 404:
        raise PackageNotFoundError("The package or release was not found in its registry")
    if response.status_code >= 500:
        raise RegistryError(f"Package registry returned HTTP {response.status_code}")
    if response.status_code != 200:
        raise RegistryError(f"Package registry returned HTTP {response.status_code}")
    try:
        return response, response.json()
    except ValueError as exc:
        raise RegistryError("Package registry returned invalid JSON") from exc


async def _download(client: httpx.AsyncClient, url: str, hosts: List[str]) -> bytes:
    return await safe_stream_download(client, url, hosts, max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES)


def _safe_filename(value: str, fallback: str) -> str:
    filename = value.rsplit("/", 1)[-1].split("?", 1)[0]
    return filename if filename and filename not in (".", "..") else fallback


def _gem_payload(blob: bytes) -> bytes:
    """Unwrap the data.tar.gz member from a RubyGems tar container without extracting its paths."""
    try:
        with tarfile.open(fileobj=BytesIO(blob), mode="r:*") as container:
            member = container.getmember("data.tar.gz")
            stream = container.extractfile(member)
            if stream is None:
                raise ValueError("missing package data")
            return stream.read(settings.MAX_TARBALL_SIZE_BYTES + 1)
    except (tarfile.TarError, KeyError, ValueError) as exc:
        raise RegistryError("RubyGems artifact has an unsupported container format") from exc


def _hex_payload(blob: bytes) -> bytes:
    """Hex tarballs contain a nested contents.tar.gz source archive."""
    try:
        with tarfile.open(fileobj=BytesIO(blob), mode="r:*") as container:
            member = container.getmember("contents.tar.gz")
            stream = container.extractfile(member)
            if stream is None:
                raise ValueError("missing package contents")
            return stream.read(settings.MAX_TARBALL_SIZE_BYTES + 1)
    except (tarfile.TarError, KeyError, ValueError) as exc:
        raise RegistryError("Hex artifact has an unsupported container format") from exc


def _apk_payload(blob: bytes) -> bytes:
    try:
        with tarfile.open(fileobj=BytesIO(blob), mode="r:*") as container:
            member = container.getmember("data.tar.gz")
            stream = container.extractfile(member)
            if stream is None:
                raise ValueError("missing package data")
            return stream.read(settings.MAX_TARBALL_SIZE_BYTES + 1)
    except (tarfile.TarError, KeyError, ValueError) as exc:
        raise RegistryError("Alpine package has an unsupported container format") from exc


def _deb_payload(blob: bytes) -> bytes:
    """Read a Debian ar container and return its data.tar.* member for safe extraction."""
    if not blob.startswith(b"!<arch>\n"):
        raise RegistryError("Debian package is not a valid ar archive")
    offset = 8
    while offset + 60 <= len(blob):
        header = blob[offset:offset + 60]
        if header[58:60] != b"`\n":
            break
        name = header[:16].decode("ascii", "ignore").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break
        start, end = offset + 60, offset + 60 + size
        if end > len(blob):
            break
        if name.startswith("data.tar."):
            return blob[start:end]
        offset = end + (size % 2)
    raise RegistryError("Debian package does not contain a readable data.tar archive")


async def _json_with_headers(client: httpx.AsyncClient, url: str, hosts: List[str], headers: Dict[str, str]):
    response = await request_with_retries(client, url, hosts, headers=headers)
    if response.status_code == 404:
        raise PackageNotFoundError("OCI image or tag was not found on Docker Hub")
    if response.status_code >= 400:
        raise RegistryError(f"Docker Hub returned HTTP {response.status_code} while resolving the image")
    try:
        return response, response.json()
    except ValueError as exc:
        raise RegistryError("Docker Hub returned an invalid image manifest") from exc


class ExtendedRegistry(Registry):
    """Shared fetch wrapper for ecosystems beyond npm and PyPI."""

    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    async def fetch_release(self, name: str, version: str, dest_dir: Path) -> Release:
        hosts = _HOSTS[self.ecosystem]
        timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
        async with make_client(timeout) as client:
            if self.ecosystem == "oci":
                blob, url, raw = await self._oci_archive(client, name, version)
                filename, kind, expected, algorithm, repository = "image-filesystem.tar.gz", "sdist", None, None, None
            else:
                url, filename, kind, expected, algorithm, repository, raw = await self._metadata(client, name, version)
                blob = await _download(client, url, hosts)
        if len(blob) > settings.MAX_TARBALL_SIZE_BYTES:
            raise DownloadError("Package artifact exceeds the configured download size limit")
        original_blob = blob
        sha256 = hashlib.sha256(original_blob).hexdigest()
        verified: Optional[bool] = None
        if expected:
            if algorithm == "sha512-base64":
                actual = base64.b64encode(hashlib.sha512(original_blob).digest()).decode("ascii")
            else:
                digest = hashlib.new(algorithm or "sha256", original_blob).hexdigest()
                actual = digest.lower()
                expected = str(expected).lower()
            if actual != expected:
                from app.utils.errors import IntegrityVerificationError
                raise IntegrityVerificationError(f"{self.ecosystem} artifact checksum did not match registry metadata")
            verified = True
        if self.ecosystem == "rubygems":
            blob, filename, kind = _gem_payload(original_blob), f"{name}-{version}.tar.gz", "sdist"
        elif self.ecosystem == "hex":
            blob, filename, kind = _hex_payload(original_blob), f"{name}-{version}.tar.gz", "sdist"
        elif self.ecosystem == "linux" and name.startswith("debian:"):
            blob, filename, kind = _deb_payload(original_blob), f"{name.split(':', 1)[1]}-{version}.tar.xz", "sdist"
        elif self.ecosystem == "linux" and name.startswith("alpine:"):
            blob, filename, kind = _apk_payload(original_blob), f"{name.split(':', 1)[1]}-{version}.tar.gz", "sdist"
        if len(blob) > settings.MAX_TARBALL_SIZE_BYTES:
            raise DownloadError("Unwrapped package artifact exceeds the configured download size limit")
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / _safe_filename(filename, "package.archive")
        path.write_bytes(blob)
        artifact = ReleaseArtifact(
            kind=kind, filename=path.name, path=path, url=url, size=len(original_blob), sha256=sha256,
            verified=verified, verification_algorithm=algorithm if verified else None,
            selection_reason=f"Fetched the exact {self.ecosystem} release artifact.",
        )
        release = Release(
            ecosystem=self.ecosystem, name=name, version=version, artifact=artifact,
            repository_field=repository, tag_names=[version, f"v{version}"], raw=raw,
        )
        if not verified:
            release.notes.append(f"{self.ecosystem} did not provide a checksum TrustPack could verify for this artifact.")
        if self.ecosystem in ("cocoapods", "swiftpm"):
            release.notes.append("This ecosystem publishes source through Git tags; the downloaded source archive is not an independent build artifact.")
        if self.ecosystem in ("oci", "linux"):
            release.notes.append("This package uses a platform/container artifact; only files supported by the safe archive reader can be compared.")
        return release

    async def _oci_archive(self, client: httpx.AsyncClient, name: str, tag: str) -> Tuple[bytes, str, Any]:
        """Pull a public Docker Hub image and merge its verified layers into a safe tar archive."""
        repo = name.lower()
        if ":" in repo or "@" in repo or not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repo):
            raise RegistryError("OCI image name must be a Docker Hub repository path; put the tag in the version field")
        if "/" not in repo:
            repo = f"library/{repo}"
        scope = quote(f"repository:{repo}:pull", safe=":/")
        token_resp, token_data = await _json(client, f"https://auth.docker.io/token?service=registry.docker.io&scope={scope}", _HOSTS["oci"])
        token = token_data.get("token") or token_data.get("access_token")
        if not token:
            raise RegistryError("Docker Hub did not issue a public image pull token")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": ", ".join((
                "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
            )),
        }
        manifest_url = f"https://registry-1.docker.io/v2/{repo}/manifests/{quote(tag, safe='') }"
        response, manifest = await _json_with_headers(client, manifest_url, _HOSTS["oci"], headers)
        if "manifests" in manifest:
            selected = next((m for m in manifest["manifests"] if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"), None)
            if selected is None:
                raise RegistryError("OCI image has no linux/amd64 manifest")
            response, manifest = await _json_with_headers(client, f"https://registry-1.docker.io/v2/{repo}/manifests/{selected['digest']}", _HOSTS["oci"], headers)
        layers = manifest.get("layers", [])
        if not layers:
            raise RegistryError("OCI image manifest contains no filesystem layers")
        manifest_digest = response.headers.get("Docker-Content-Digest")
        with tempfile.TemporaryDirectory(prefix="trustpack_oci_") as tmp:
            root = Path(tmp)
            merged = root / "merged"
            merged.mkdir()
            total_layer_bytes = 0
            for index, layer in enumerate(layers):
                media = layer.get("mediaType", "")
                if "zstd" in media:
                    raise RegistryError("This OCI image uses zstd layers, which are not supported by the current safe archive reader")
                digest = str(layer.get("digest", ""))
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    raise RegistryError("OCI layer has an unsupported digest format")
                layer_url = f"https://registry-1.docker.io/v2/{repo}/blobs/{digest}"
                body = await safe_stream_download(client, layer_url, _HOSTS["oci"], headers={"Authorization": f"Bearer {token}"}, max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES)
                total_layer_bytes += len(body)
                if total_layer_bytes > settings.MAX_TARBALL_SIZE_BYTES:
                    raise DownloadError("OCI image layers exceed the configured aggregate download size limit")
                if hashlib.sha256(body).hexdigest() != digest.split(":", 1)[1]:
                    from app.utils.errors import IntegrityVerificationError
                    raise IntegrityVerificationError("OCI layer checksum did not match its manifest digest")
                archive = root / f"layer-{index}.tar.gz"
                archive.write_bytes(body)
                from app.services.archive_extractor import extract_archive
                layer_root = extract_archive(archive, root / f"unpacked-{index}", unwrap=False, skipped_links=[])
                # Apply OCI whiteouts before overlaying this layer.
                for marker in list(layer_root.rglob(".wh.*")):
                    relative = marker.relative_to(layer_root)
                    if marker.name == ".wh..wh..opq":
                        target = merged / relative.parent
                        if target.exists():
                            for child in target.iterdir():
                                shutil.rmtree(child) if child.is_dir() else child.unlink()
                    else:
                        victim = merged / relative.parent / marker.name[4:]
                        if victim.exists():
                            shutil.rmtree(victim) if victim.is_dir() else victim.unlink()
                for item in layer_root.rglob("*"):
                    if item.name.startswith(".wh.") or item.is_symlink():
                        continue
                    target = merged / item.relative_to(layer_root)
                    if item.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif item.is_file():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(item, target)
            files = [item for item in merged.rglob("*") if item.is_file()]
            if len(files) > settings.MAX_FILE_COUNT or sum(item.stat().st_size for item in files) > settings.MAX_EXTRACTED_SIZE_BYTES:
                raise DownloadError("OCI image filesystem exceeds the configured extraction limits")
            output = root / "image.tar.gz"
            with tarfile.open(output, "w:gz") as tar:
                for item in merged.rglob("*"):
                    if item.is_file() and not item.is_symlink():
                        tar.add(item, arcname=item.relative_to(merged).as_posix(), recursive=False)
            raw = {"manifestDigest": manifest_digest, "layerCount": len(layers), "platform": "linux/amd64"}
            return output.read_bytes(), manifest_url, raw


    async def _metadata(self, client: httpx.AsyncClient, name: str, version: str):
        eco = self.ecosystem
        encoded = quote(name, safe="")
        repository = None
        raw: Any = None
        if eco == "maven":
            if ":" not in name:
                raise RegistryError("Maven coordinates must use group:artifact format")
            group, artifact = name.split(":", 1)
            gpath = group.replace(".", "/")
            q = quote(f"g:{group} AND a:{artifact} AND v:{version}")
            _, raw = await _json(client, f"https://search.maven.org/solrsearch/select?q={q}&rows=1&wt=json", _HOSTS[eco])
            docs = raw.get("response", {}).get("docs", [])
            if not docs:
                raise VersionNotFoundError(f"Maven release {name}:{version} was not found")
            base = f"https://repo.maven.apache.org/maven2/{gpath}/{artifact}/{version}/{artifact}-{version}"
            url = base + ".jar"
            sha_resp = await request_with_retries(client, url + ".sha1", _HOSTS[eco])
            checksum = sha_resp.text.strip().split()[0] if sha_resp.status_code == 200 else None
            repository = raw
            return url, _safe_filename(url, "package.jar"), "wheel", checksum, "sha1", repository, raw
        if eco == "nuget":
            key = name.lower()
            _, raw = await _json(client, f"https://api.nuget.org/v3-flatcontainer/{quote(key)}/index.json", _HOSTS[eco])
            versions = [str(v).lower() for v in raw.get("versions", [])]
            match = next((v for v in versions if v == version.lower()), None)
            if not match:
                raise VersionNotFoundError(f"NuGet version {version} was not found for {name}")
            url = f"https://api.nuget.org/v3-flatcontainer/{quote(key)}/{quote(match)}/{quote(key)}.{quote(match)}.nupkg"
            check = await request_with_retries(client, url + ".sha512", _HOSTS[eco])
            checksum = check.text.strip() if check.status_code == 200 else None
            return url, _safe_filename(url, "package.nupkg"), "wheel", checksum, "sha512-base64", repository, raw
        if eco == "cargo":
            _, raw = await _json(client, f"https://crates.io/api/v1/crates/{encoded}/{quote(version)}", _HOSTS[eco])
            crate = raw.get("version", {})
            repository = raw.get("crate", {}).get("repository")
            return f"https://static.crates.io/crates/{encoded}/{name}-{version}.crate", f"{name}-{version}.crate", "sdist", crate.get("checksum"), "sha256", repository, raw
        if eco == "go":
            module = re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), name)
            ver = re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), version)
            url = f"https://proxy.golang.org/{quote(module, safe='!/@')}/@v/{quote(ver, safe='!+')}.zip"
            check = await request_with_retries(client, f"https://sum.golang.org/lookup/{quote(module, safe='!/@')}@{quote(ver, safe='!+')}", _HOSTS[eco])
            raw = {"sumdb": check.text[:2000] if check.status_code == 200 else None}
            return url, f"{name.rsplit('/', 1)[-1]}-{version}.zip", "sdist", None, None, repository, raw
        if eco == "rubygems":
            _, raw = await _json(client, f"https://rubygems.org/api/v2/rubygems/{encoded}/versions/{quote(version)}.json", _HOSTS[eco])
            repository = raw.get("source_code_uri") or raw.get("homepage_uri")
            return raw.get("gem_uri") or f"https://rubygems.org/downloads/{name}-{version}.gem", f"{name}-{version}.gem", "sdist", raw.get("sha"), "sha256", repository, raw
        if eco == "packagist":
            parts = name.split("/", 1)
            if len(parts) != 2:
                raise RegistryError("Packagist package names must use vendor/package format")
            _, raw = await _json(client, f"https://packagist.org/p/{quote(parts[0], safe='')}/{quote(parts[1], safe='')}.json", _HOSTS[eco])
            versions = raw.get("packages", {}).get(name, [])
            release = next((v for v in versions if str(v.get("version", "")).lstrip("v") == version.lstrip("v")), None)
            if not release:
                raise VersionNotFoundError(f"Packagist version {version} was not found for {name}")
            dist = release.get("dist") or {}
            repository = release.get("source", {}).get("url")
            dist_url = dist.get("url")
            if not dist_url:
                raise RegistryError("Packagist release does not have a downloadable source archive")
            return dist_url, _safe_filename(dist_url, "package.zip"), "sdist", dist.get("shasum") or None, "sha1", repository, release
        if eco == "pub":
            _, raw = await _json(client, f"https://pub.dev/api/packages/{encoded}/versions/{quote(version)}", _HOSTS[eco])
            repository = raw.get("pubspec", {}).get("repository") or raw.get("pubspec", {}).get("homepage")
            return raw.get("archive_url") or f"https://pub.dev/packages/{encoded}/versions/{quote(version)}.tar.gz", f"{name}-{version}.tar.gz", "sdist", raw.get("archive_sha256"), "sha256", repository, raw
        if eco == "hex":
            _, raw = await _json(client, f"https://hex.pm/api/packages/{encoded}/releases/{quote(version)}", _HOSTS[eco])
            package, _ = await _json(client, f"https://hex.pm/api/packages/{encoded}", _HOSTS[eco])
            repository = package.get("meta", {}).get("links", {}).get("GitHub")
            return f"https://repo.hex.pm/tarballs/{encoded}-{quote(version)}.tar", f"{name}-{version}.tar", "sdist", raw.get("checksum"), "sha256", repository, raw
        if eco in ("cocoapods", "swiftpm"):
            if eco == "cocoapods":
                _, raw = await _json(client, f"https://trunk.cocoapods.org/api/v1/pods/{encoded}/specs/{quote(version)}", _HOSTS[eco])
                source = raw.get("source") or {}
                repo_url = source.get("git")
                tag = source.get("tag") or source.get("commit") or version
                repo = extract_github_repo(repo_url)
                if not repo:
                    raise RegistryError("This CocoaPod does not point to a supported GitHub source repository")
            else:
                repo = extract_github_repo(f"https://github.com/{name}")
                raw = {}
                tag = version
            if not repo:
                raise RegistryError(f"{eco} package must resolve to a GitHub owner/repository")
            repository = repo.url
            archive_url = f"https://codeload.github.com/{repo.owner}/{repo.repo}/tar.gz/{quote(tag, safe='') }"
            return archive_url, f"{repo.repo}-{version}.tar.gz", "sdist", None, None, repository, raw
        if eco == "conda":
            _, raw = await _json(client, f"https://api.anaconda.org/package/conda-forge/{encoded}", _HOSTS[eco])
            matches = [f for f in raw.get("files", []) if str(f.get("version")) == version and f.get("attrs", {}).get("subdir") in ("noarch", "linux-64")]
            entry = next((f for f in matches if str(f.get("basename", "")).endswith(".tar.bz2")), None)
            if not entry:
                if matches:
                    raise RegistryError("This Conda release is available only as a .conda zstd package; select a release with a .tar.bz2 artifact")
                raise VersionNotFoundError(f"Conda-forge version {version} was not found for {name}")
            download_url = entry.get("download_url")
            if not download_url:
                raise RegistryError("Conda package metadata did not include a download URL")
            return "https:" + download_url if download_url.startswith("//") else download_url, _safe_filename(entry.get("basename", ""), "package.tar.bz2"), "sdist", entry.get("sha256"), "sha256", raw.get("home") or raw.get("dev_url"), entry
        if eco == "linux":
            if ":" not in name:
                raise RegistryError("Linux package names must include a distribution, for example debian:curl or alpine:curl")
            distro, package = name.split(":", 1)
            if distro == "debian":
                _, raw = await _json(client, f"https://snapshot.debian.org/mr/package/{quote(package)}/{quote(version)}/binfiles?architecture=amd64&fileinfo=1", _HOSTS[eco])
                files = raw.get("result", [])
                entry = next((item for item in files if str(item.get("name", "")).endswith("_amd64.deb")), None)
                if not entry:
                    raise VersionNotFoundError(f"Debian package {package} {version} was not found for amd64")
                digest = entry.get("hash") or entry.get("sha256")
                digest_algorithm = "sha256" if digest and len(digest) == 64 else "sha1" if digest else None
                return f"https://snapshot.debian.org/file/{digest}", entry["name"], "deb", digest, digest_algorithm, None, entry
            if distro == "alpine":
                index_url = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz"
                index_blob = await _download(client, index_url, _HOSTS[eco])
                try:
                    with tarfile.open(fileobj=BytesIO(index_blob), mode="r:gz") as archive:
                        index_member = archive.extractfile("APKINDEX")
                        index_text = index_member.read().decode("utf-8", "replace") if index_member else ""
                except (tarfile.TarError, OSError) as exc:
                    raise RegistryError("Could not read Alpine package index") from exc
                for record in index_text.split("\n\n"):
                    fields = dict(line.split(":", 1) for line in record.splitlines() if ":" in line)
                    if fields.get("P") == package and fields.get("V") == version:
                        filename = fields.get("F")
                        if not filename:
                            break
                        return f"https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/{filename}", filename, "apk", None, None, None, fields
                raise VersionNotFoundError(f"Alpine package {package} {version} was not found in latest-stable/main")
            raise RegistryError("Linux package support currently covers Debian/Ubuntu snapshots and Alpine latest-stable/main; Fedora/RPM is not yet available")
        if eco == "oci":
            raise RegistryError("OCI image analysis needs registry credentials and a platform-specific manifest; this image could not be resolved as a safe archive")
        raise RegistryError(f"No release adapter is configured for {eco}")

    def published_package_json(self, release: Release, published_root: Path) -> Optional[Dict[str, Any]]:
        return None

    def static_findings(self, release: Release, published_root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        return []

    def source_findings(self, release: Release, source_root: Path, source_manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        return []

    async def verify_provenance(self, release, resolved_repo_url, resolved_commit):
        return {"provenance_status": "NOT_AVAILABLE", "registry_signature_present": None,
                "detail": f"Cryptographic provenance verification is not implemented for {self.ecosystem}.", "findings": [], "claims": None}
