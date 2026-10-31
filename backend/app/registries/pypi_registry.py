"""PyPI adapter built on the official JSON API (https://pypi.org/pypi/{project}/{version}/json).

Fetches exact-version metadata, chooses a distribution (and records why), downloads it from the
allow-listed file host, and verifies it against the SHA-256 digest PyPI publishes. Nothing from the
artifact is ever built, installed or imported.
"""
import base64
import csv
import hashlib
import io
import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from app.config import settings
from app.registries.base import Registry, Release, ReleaseArtifact
from app.services import provenance_checker
from app.services.manifest_generator import FileRecord
from app.services.source_resolver import (
    ORIGIN_HOMEPAGE, ORIGIN_PROJECT_URL, RepoRef, default_tag_candidates, extract_github_repo,
)
from app.services.suspicious_code import find_suspicious_content, pth_executes_code
from app.utils.errors import (
    DownloadError, IntegrityVerificationError, PackageNotFoundError, RegistryError, UpstreamTimeoutError,
    VersionNotFoundError,
)
from app.utils.http_client import make_client, request_with_retries, safe_stream_download
from app.utils.logging import get_logger

logger = get_logger(__name__)

_SDIST_PREFERENCE = (".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz")
_SOURCE_LABELS = {"source", "sourcecode", "repository", "repo", "code", "github", "git", "gitrepository", "sourcerepository", "gitrepo"}
_HOME_LABELS = {"homepage", "home", "website", "url", "project", "projecthomepage"}
_NETWORK_IN_SETUP = re.compile(r"\b(?:urlopen|urlretrieve|requests\.(?:get|post)|socket\.|http\.client|httpx\.)", re.IGNORECASE)
_EXEC_IN_SETUP = re.compile(r"\b(?:os\.system|subprocess\.\w+|os\.popen|exec\s*\(|eval\s*\()")


def normalize_name(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _ext_rank(filename: str) -> int:
    lower = filename.lower()
    for i, ext in enumerate(_SDIST_PREFERENCE):
        if lower.endswith(ext):
            return i
    return len(_SDIST_PREFERENCE)


def _summary(entry: Dict[str, Any]) -> Dict[str, Any]:
    kind = {"sdist": "sdist", "bdist_wheel": "wheel"}.get(entry.get("packagetype"), entry.get("packagetype") or "other")
    return {
        "filename": entry.get("filename"), "kind": kind, "size": entry.get("size"),
        "sha256": (entry.get("digests") or {}).get("sha256"), "yanked": bool(entry.get("yanked")),
    }


def select_distribution(urls: List[Dict[str, Any]], max_size: int) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    """Pick the artifact to analyse and return (entry, reason, alternatives).

    Order: source distribution (closest to the repository) > pure-Python wheel > any other wheel;
    yanked files only if nothing else exists. Eggs and unknown package types are never analysed. Files
    larger than the download cap are skipped.
    """
    usable = [u for u in urls if u.get("packagetype") in ("sdist", "bdist_wheel") and u.get("url") and u.get("filename")]
    sdists = sorted((u for u in usable if u["packagetype"] == "sdist" and _ext_rank(u["filename"]) < len(_SDIST_PREFERENCE)),
                    key=lambda u: (_ext_rank(u["filename"]), u["filename"]))
    wheels = [u for u in usable if u["packagetype"] == "bdist_wheel"]
    pure = sorted((w for w in wheels if w["filename"].endswith("-none-any.whl")), key=lambda w: (not w["filename"].count("py3-none-any"), w["filename"]))
    compiled = sorted((w for w in wheels if w not in pure),
                      key=lambda w: (not ("manylinux" in w["filename"] and "x86_64" in w["filename"]), w["filename"]))

    ordered: List[Tuple[Dict[str, Any], str]] = []
    for u in sdists:
        ordered.append((u, "Selected the source distribution: it is the artifact closest to the repository contents, so it gives the most reliable file-by-file comparison."))
    for u in pure:
        why = "No source distribution is available; selected the pure-Python wheel (platform independent, its Python files can be compared with the repository)."
        ordered.append((u, why))
    for u in compiled:
        ordered.append((u, "Only platform-specific wheels are available; selected one. Compiled extension modules in it cannot be compared with source."))
    live = [(u, r) for u, r in ordered if not u.get("yanked")]
    yanked = [(u, r + " (This file has been yanked by the maintainers.)") for u, r in ordered if u.get("yanked")]

    for entry, reason in live + yanked:
        size = entry.get("size")
        if isinstance(size, int) and size > max_size:
            continue
        alternatives = [_summary(u) for u in urls if u is not entry][:20]
        return entry, reason, alternatives
    if not usable:
        raise RegistryError("This release has no source distribution or wheel that TrustPack can analyse")
    raise DownloadError(f"Every distribution of this release exceeds the {max_size}-byte download limit")


def _repo_candidates(info: Dict[str, Any]) -> List[RepoRef]:
    """GitHub repositories named in PyPI metadata, most trustworthy label first."""
    project_urls = info.get("project_urls") or {}
    ranked: List[Tuple[int, RepoRef]] = []
    for label, url in project_urls.items():
        repo = extract_github_repo(url)
        if repo is None:
            continue
        key = re.sub(r"[^a-z0-9]", "", str(label).lower())
        if key in _SOURCE_LABELS:
            repo.origin = ORIGIN_PROJECT_URL
            ranked.append((0, repo))
        elif key in _HOME_LABELS:
            repo.origin = ORIGIN_HOMEPAGE
            ranked.append((1, repo))
        else:  # bug tracker, changelog, docs ... still point at the repo, but say less about it
            repo.origin = ORIGIN_HOMEPAGE
            ranked.append((2, repo))
    for field_name in ("home_page", "download_url"):
        repo = extract_github_repo(info.get(field_name))
        if repo is not None:
            repo.origin = ORIGIN_HOMEPAGE
            ranked.append((1, repo))
    ranked.sort(key=lambda t: t[0])
    unique: List[RepoRef] = []
    for _, repo in ranked:
        if all(repo.key != u.key for u in unique):
            unique.append(repo)
    return unique


def _requires_dist(info: Dict[str, Any]) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for line in info.get("requires_dist") or []:
        if not isinstance(line, str) or "extra ==" in line:
            continue
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*?)\s*(?:;.*)?$", line)
        if m:
            deps[normalize_name(m.group(1))] = m.group(2)
    return deps


class PyPIRegistry(Registry):
    ecosystem = "pypi"

    async def fetch_release(self, name: str, version: str, dest_dir: Path) -> Release:
        base = settings.PYPI_URL.rstrip("/")
        url = f"{base}/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
        hosts = settings.ALLOWED_PYPI_HOSTS
        timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)

        async with make_client(timeout) as client:
            resp = await request_with_retries(client, url, hosts)
            if resp.status_code == 404:
                pkg_resp = await request_with_retries(client, f"{base}/pypi/{quote(name, safe='')}/json", hosts)
                if pkg_resp.status_code == 404:
                    raise PackageNotFoundError(f"Package '{name}' was not found on PyPI")
                raise VersionNotFoundError(f"Version '{version}' was not found for package '{name}'")
            if resp.status_code >= 500:
                raise RegistryError(f"PyPI returned {resp.status_code} for {url}")
            if resp.status_code != 200:
                raise RegistryError(f"Unexpected PyPI response {resp.status_code} for {url}")
            try:
                data = resp.json()
            except ValueError as exc:
                raise RegistryError("PyPI returned malformed JSON") from exc

            info = data.get("info") if isinstance(data, dict) else None
            if not isinstance(info, dict):
                raise RegistryError("PyPI metadata is missing the 'info' section")
            # Defense in depth: never accept a document for a different project or release.
            if normalize_name(str(info.get("name", ""))) != normalize_name(name) or str(info.get("version", "")).lower() != version.lower():
                raise RegistryError("PyPI returned metadata for a different package/version")

            urls = [u for u in (data.get("urls") or []) if isinstance(u, dict)]
            chosen, reason, alternatives = select_distribution(urls, settings.MAX_TARBALL_SIZE_BYTES)

            dest_dir.mkdir(parents=True, exist_ok=True)
            filename = PurePosixPath(str(chosen["filename"])).name
            dest_path = dest_dir / "artifact.bin"
            blob = await self._download(client, chosen["url"], hosts)

        sha256_hex = hashlib.sha256(blob).hexdigest()
        expected = ((chosen.get("digests") or {}).get("sha256") or "").lower()
        if expected:
            if sha256_hex != expected:
                raise IntegrityVerificationError(
                    "Artifact integrity check failed: downloaded content does not match "
                    "the sha256 digest published by PyPI"
                )
            verified: Optional[bool] = True
            algorithm: Optional[str] = "sha256"
        else:
            verified, algorithm = None, None
        dest_path.write_bytes(blob)

        kind = "wheel" if chosen["packagetype"] == "bdist_wheel" else "sdist"
        artifact = ReleaseArtifact(
            kind=kind, filename=filename, path=dest_path, url=chosen["url"], size=len(blob), sha256=sha256_hex,
            verified=verified, verification_algorithm=algorithm, selection_reason=reason, alternatives=alternatives,
            published_at=chosen.get("upload_time_iso_8601") or None,
        )
        release = Release(
            ecosystem="pypi", name=name, version=version, artifact=artifact,
            extra_repo_candidates=_repo_candidates(info),
            tag_names=default_tag_candidates(version, name),
            dependencies=_requires_dist(info), raw=data,
        )
        if verified is None:
            release.notes.append("PyPI published no sha256 digest for this file, so the download could not be verified.")
        if chosen.get("yanked"):
            release.notes.append("This release file has been yanked by the maintainers.")
        if kind == "wheel":
            release.notes.append(
                "Analysed a wheel, not a source distribution: build output is compared with the repository, "
                "and compiled extensions cannot be compared with source."
            )
        return release

    @staticmethod
    async def _download(client: httpx.AsyncClient, url: str, hosts: List[str]) -> bytes:
        last_exc: Optional[Exception] = None
        for _ in range(settings.HTTP_MAX_RETRIES + 1):
            try:
                return await safe_stream_download(client, url, hosts, max_size_bytes=settings.MAX_TARBALL_SIZE_BYTES)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
        raise UpstreamTimeoutError("Artifact download timed out after retries") from last_exc

    # ------------------------------------------------------------------ analysis hooks

    def published_package_json(self, release: Release, published_root: Path) -> Optional[Dict[str, Any]]:
        return None

    def static_findings(self, release: Release, published_root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        findings.extend(self._pth_findings(published_root, manifest))
        findings.extend(self._setup_py_findings(published_root, manifest))
        findings.extend(self._metadata_findings(release, published_root, manifest))
        if release.artifact.kind == "wheel":
            findings.extend(self._wheel_record_findings(published_root, manifest))
        return findings

    def source_findings(self, release: Release, source_root: Path, source_manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        return []

    async def verify_provenance(self, release: Release, resolved_repo_url, resolved_commit):
        return await provenance_checker.verify_pypi_provenance(
            project=normalize_name(release.name), version=release.version, filename=release.artifact.filename,
            sha256_hex=release.artifact.sha256, resolved_repo_url=resolved_repo_url,
        )

    # ------------------------------------------------------------------ individual checks

    @staticmethod
    def _read(root: Path, rel: str, limit: int = 1_000_000) -> str:
        try:
            with open(root / rel, "rb") as fh:
                return fh.read(limit).decode("utf-8", errors="ignore")
        except OSError:
            return ""

    def _pth_findings(self, root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        findings = []
        for path in sorted(p for p in manifest if p.lower().endswith(".pth")):
            text = self._read(root, path)
            if not pth_executes_code(text):
                continue
            hostile = bool(find_suspicious_content(path, text)) or bool(re.search(r"exec|eval|base64|subprocess|os\.system|popen|urllib|__import__|socket|curl|wget", text))
            findings.append({
                "rule_id": "PTH_FILE_EXECUTES_CODE", "file": path, "category": "install_time_code",
                "severity": "HIGH" if hostile else "MEDIUM", "confidence": "HIGH" if hostile else "MEDIUM",
                "evidence": f"{path} contains an 'import' line, which the Python interpreter executes at every start-up.",
                "explanation": ".pth files are meant to list paths; a line starting with 'import' runs arbitrary code in every Python process that uses this environment. A few legitimate packages do this deliberately.",
                "recommendation": f"Read {path} before installing; it runs without being imported.",
            })
        return findings

    def _setup_py_findings(self, root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        if "setup.py" not in manifest:
            return []
        text = self._read(root, "setup.py")
        has_net, has_exec = bool(_NETWORK_IN_SETUP.search(text)), bool(_EXEC_IN_SETUP.search(text))
        if not (has_net or (has_exec and "cmdclass" in text)):
            return []
        what = "network access" if has_net else "process execution inside custom install commands"
        return [{
            "rule_id": "SETUP_PY_RUNS_CODE_AT_INSTALL", "file": "setup.py", "category": "install_time_code",
            "severity": "MEDIUM", "confidence": "LOW",
            "evidence": f"setup.py contains {what}. Static pattern match only.",
            "explanation": "setup.py runs when a source distribution is installed. Network access or command execution there is unusual and worth reading, though some build scripts legitimately download or compile things.",
            "recommendation": "Read setup.py before installing this sdist, or prefer a wheel.",
        }]

    def _metadata_findings(self, release: Release, root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        candidates = [p for p in manifest if p.endswith(".dist-info/METADATA")] or (["PKG-INFO"] if "PKG-INFO" in manifest else [])
        if not candidates:
            return []
        name = version = None
        for line in self._read(root, candidates[0]).splitlines():
            if line.startswith("Name:") and name is None:
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:") and version is None:
                version = line.split(":", 1)[1].strip()
            elif not line.strip():
                break
        problems = []
        if name and normalize_name(name) != normalize_name(release.name):
            problems.append(f"Name is '{name}', expected '{release.name}'")
        if version and version.lower() != release.version.lower():
            problems.append(f"Version is '{version}', expected '{release.version}'")
        if not problems:
            return []
        return [{
            "rule_id": "PACKAGE_METADATA_MISMATCH", "file": candidates[0], "category": "metadata_discrepancy",
            "severity": "MEDIUM", "confidence": "HIGH",
            "evidence": f"{candidates[0]}: " + "; ".join(problems) + ".",
            "explanation": "The metadata embedded in the artifact disagrees with the release it was published as, which indicates a repackaged or mislabeled file.",
            "recommendation": "Treat the artifact as suspect until the maintainers explain the mismatch.",
        }]

    def _wheel_record_findings(self, root: Path, manifest: Dict[str, FileRecord]) -> List[Dict[str, Any]]:
        record_paths = [p for p in manifest if p.endswith(".dist-info/RECORD")]
        if not record_paths:
            return [{
                "rule_id": "WHEEL_RECORD_MISSING", "file": None, "category": "metadata_discrepancy",
                "severity": "LOW", "confidence": "HIGH", "evidence": "The wheel contains no *.dist-info/RECORD file.",
                "explanation": "RECORD lists every file in a wheel with its hash; without it the wheel's internal consistency cannot be checked.",
                "recommendation": "Compare the wheel with the source distribution.",
            }]
        record_path = record_paths[0]
        listed: Dict[str, str] = {}
        for row in csv.reader(io.StringIO(self._read(root, record_path, 5_000_000))):
            if len(row) >= 2 and row[0]:
                listed[PurePosixPath(row[0]).as_posix()] = row[1]

        mismatched: List[str] = []
        for path, hash_field in listed.items():
            record = manifest.get(path)
            if record is None or not hash_field.startswith("sha256="):
                continue
            actual = base64.urlsafe_b64encode(bytes.fromhex(record.sha256)).rstrip(b"=").decode("ascii")
            if actual != hash_field[len("sha256="):].rstrip("="):
                mismatched.append(path)
        record_dir = record_path.rsplit("/", 1)[0]
        ignorable = {record_path, record_dir + "/RECORD.jws", record_dir + "/RECORD.p7s"}
        unlisted = sorted(p for p in manifest if p not in listed and p not in ignorable)

        findings = []
        if mismatched:
            shown = ", ".join(mismatched[:10]) + (f" and {len(mismatched) - 10} more" if len(mismatched) > 10 else "")
            findings.append({
                "rule_id": "WHEEL_RECORD_HASH_MISMATCH", "file": mismatched[0] if len(mismatched) == 1 else None,
                "category": "wheel_integrity", "severity": "HIGH", "confidence": "HIGH",
                "evidence": f"{len(mismatched)} file(s) do not match the sha256 hash listed in {record_path}: {shown}.",
                "explanation": "A wheel's RECORD is written at build time. Files whose contents differ from it were changed after the wheel was built.",
                "recommendation": "Do not install this wheel; fetch the sdist and compare.",
            })
        if unlisted:
            shown = ", ".join(unlisted[:10]) + (f" and {len(unlisted) - 10} more" if len(unlisted) > 10 else "")
            findings.append({
                "rule_id": "WHEEL_FILE_NOT_IN_RECORD", "file": unlisted[0] if len(unlisted) == 1 else None,
                "category": "wheel_integrity", "severity": "MEDIUM", "confidence": "HIGH",
                "evidence": f"{len(unlisted)} file(s) are in the wheel but not listed in {record_path}: {shown}.",
                "explanation": "Every file in a correctly built wheel is listed in RECORD. Unlisted files were added afterwards.",
                "recommendation": "Inspect the unlisted files.",
            })
        return findings
