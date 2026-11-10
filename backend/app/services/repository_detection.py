"""Discover publishable package manifests in a public GitHub repository."""
import asyncio
import base64
import json
import re
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from app.config import settings
from app.services.source_resolver import _github_get, extract_github_repo
from app.utils.errors import DownloadError, SourceResolutionError
from app.utils.http_client import make_client

_MANIFESTS = {
    "package.json", "pyproject.toml", "setup.cfg", "pom.xml", "cargo.toml", "go.mod",
    "composer.json", "pubspec.yaml", "mix.exs", "package.swift", "meta.yaml", "recipe.yaml",
    "control", "apkbuild", "dockerfile", "setup.py",
}
_MAX_MANIFESTS = 40


def _text(blob: Dict[str, Any]) -> str:
    if blob.get("encoding") == "base64" and isinstance(blob.get("content"), str):
        try:
            return base64.b64decode(blob["content"], validate=False).decode("utf-8", "replace")
        except (ValueError, UnicodeError):
            return ""
    return ""


def _toml_value(text: str, section: str, key: str) -> Optional[str]:
    section_match = re.search(rf"(?ms)^\[{re.escape(section)}\][^\n]*\n(.*?)(?=^\[|\Z)", text)
    source = section_match.group(1) if section_match else text
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]", source)
    return match.group(1).strip() if match else None


def _candidate(ecosystem: str, name: Optional[str], version: Optional[str], path: str) -> Optional[dict]:
    if not name:
        return None
    return {"ecosystem": ecosystem, "name": name.strip(), "version": (version or "").strip(), "manifest": path}


def _parse(path: str, text: str, owner: str, repository: str) -> List[dict]:
    basename = PurePosixPath(path).name.lower()
    found: List[dict] = []
    try:
        if basename == "package.json":
            data = json.loads(text)
            item = _candidate("npm", data.get("name"), data.get("version"), path)
            if item: found.append(item)
        elif basename == "pyproject.toml":
            name = _toml_value(text, "project", "name") or _toml_value(text, "tool.poetry", "name")
            version = _toml_value(text, "project", "version") or _toml_value(text, "tool.poetry", "version")
            item = _candidate("pypi", name, version, path)
            if item: found.append(item)
        elif basename == "setup.cfg":
            name = re.search(r"(?im)^\s*name\s*=\s*([^\s#]+)", text)
            version = re.search(r"(?im)^\s*version\s*=\s*([^\s#]+)", text)
            item = _candidate("pypi", name.group(1) if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "setup.py":
            name = re.search(r"(?m)\bname\s*=\s*['\"]([^'\"]+)['\"]", text)
            version = re.search(r"(?m)\bversion\s*=\s*['\"]([^'\"]+)['\"]", text)
            item = _candidate("pypi", name.group(1) if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "pom.xml":
            root = ET.fromstring(text)
            def xml_value(tag: str) -> Optional[str]:
                node = next((n for n in root.iter() if n.tag.rsplit("}", 1)[-1] == tag), None)
                return node.text.strip() if node is not None and node.text else None
            group, artifact, version = xml_value("groupId"), xml_value("artifactId"), xml_value("version")
            if artifact:
                if not group:
                    parent = next((n for n in root.iter() if n.tag.rsplit("}", 1)[-1] == "parent"), None)
                    group = next((n.text.strip() for n in parent or [] if n.tag.rsplit("}", 1)[-1] == "groupId" and n.text), None)
                item = _candidate("maven", f"{group}:{artifact}" if group else artifact, version, path)
                if item: found.append(item)
        elif basename.endswith(".csproj"):
            root = ET.fromstring(text)
            values = {node.tag.rsplit("}", 1)[-1]: (node.text or "").strip() for node in root.iter()}
            item = _candidate("nuget", values.get("PackageId") or values.get("AssemblyName"), values.get("PackageVersion") or values.get("Version"), path)
            if item: found.append(item)
        elif basename == "cargo.toml":
            item = _candidate("cargo", _toml_value(text, "package", "name"), _toml_value(text, "package", "version"), path)
            if item: found.append(item)
        elif basename == "go.mod":
            module = re.search(r"(?m)^\s*module\s+([^\s]+)", text)
            item = _candidate("go", module.group(1) if module else None, None, path)
            if item: found.append(item)
        elif basename.endswith(".gemspec"):
            name = re.search(r"\.name\s*=\s*['\"]([^'\"]+)", text)
            version = re.search(r"\.version\s*=\s*['\"]([^'\"]+)", text)
            item = _candidate("rubygems", name.group(1) if name else basename[:-8], version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "composer.json":
            data = json.loads(text)
            item = _candidate("packagist", data.get("name"), data.get("version"), path)
            if item: found.append(item)
        elif basename == "pubspec.yaml":
            name = re.search(r"(?m)^name:\s*['\"]?([^\s#'\"]+)", text)
            version = re.search(r"(?m)^version:\s*['\"]?([^\s#'\"]+)", text)
            item = _candidate("pub", name.group(1) if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "mix.exs":
            name = re.search(r"(?m)\bapp:\s*:(\w+)", text)
            version = re.search(r"(?m)\bversion:\s*\"([^\"]+)\"", text)
            item = _candidate("hex", name.group(1) if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "package.swift":
            name = re.search(r"Package\s*\(\s*name:\s*\"([^\"]+)\"", text)
            item = _candidate("swiftpm", f"{owner}/{name.group(1)}" if name else f"{owner}/{repository}", None, path)
            if item: found.append(item)
        elif basename in ("meta.yaml", "recipe.yaml"):
            name = re.search(r"(?m)^\s*name:\s*['\"]?([^\s#'\"]+)", text)
            version = re.search(r"(?m)^\s*version:\s*['\"]?([^\s#'\"]+)", text)
            item = _candidate("conda", name.group(1) if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename.endswith(".podspec"):
            name = re.search(r"\.name\s*=\s*['\"]([^'\"]+)", text) or re.search(r"\.name\s*=\s*\"([^\"]+)\"", text)
            version = re.search(r"\.version\s*=\s*['\"]([^'\"]+)", text)
            item = _candidate("cocoapods", name.group(1) if name else basename[:-8], version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "dockerfile":
            # A GitHub repo can publish under GHCR/<owner>/<repo>; tag is not inferable here.
            found.append({"ecosystem": "oci", "name": f"{owner}/{repository}", "version": "", "manifest": path})
        elif basename == "control":
            name = re.search(r"(?im)^Package:\s*(\S+)", text)
            version = re.search(r"(?im)^Version:\s*(\S+)", text)
            item = _candidate("linux", f"debian:{name.group(1)}" if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
        elif basename == "apkbuild":
            name = re.search(r"(?m)^pkgname=(?:['\"])?([^'\"\n]+)", text)
            version = re.search(r"(?m)^pkgver=(?:['\"])?([^'\"\n]+)", text)
            item = _candidate("linux", f"alpine:{name.group(1)}" if name else None, version.group(1) if version else None, path)
            if item: found.append(item)
    except (ValueError, TypeError, ET.ParseError):
        return []
    return found


async def detect_repository(url: str) -> dict:
    if len(url) > 500:
        raise SourceResolutionError("GitHub URL is too long to inspect.")
    repo = extract_github_repo(url)
    if repo is None:
        raise SourceResolutionError("Enter a public GitHub repository or directory URL to detect package manifests.")
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    branch = None
    directory = ""
    if len(parts) >= 4 and parts[2] in ("tree", "blob"):
        branch = parts[3]
        scope = "/".join(parts[4:])
        directory = scope.rsplit("/", 1)[0] if parts[2] == "blob" else scope
    base = settings.GITHUB_API_URL.rstrip("/")
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    async with make_client(timeout) as client:
        repo_resp = await _github_get(client, f"{base}/repos/{repo.owner}/{repo.repo}")
        if repo_resp.status_code == 404:
            raise SourceResolutionError("The GitHub repository was not found or is private.")
        if repo_resp.status_code != 200:
            raise DownloadError(f"GitHub repository lookup failed with status {repo_resp.status_code}.")
        default_branch = repo_resp.json().get("default_branch")
        if not default_branch:
            raise SourceResolutionError("GitHub did not report a default branch for this repository.")
        ref = branch or default_branch
        tree_resp = await _github_get(client, f"{base}/repos/{repo.owner}/{repo.repo}/git/trees/{quote(ref, safe='')}?recursive=1")
        if tree_resp.status_code != 200:
            raise DownloadError(f"Could not list files in the GitHub repository (status {tree_resp.status_code}).")
        tree = tree_resp.json()
        paths = [entry for entry in tree.get("tree", []) if entry.get("type") == "blob"]
        if directory:
            prefix = directory.strip("/") + "/"
            paths = [entry for entry in paths if entry.get("path", "").startswith(prefix)]
        paths = [entry for entry in paths if PurePosixPath(entry.get("path", "")).name.lower() in _MANIFESTS
                 or PurePosixPath(entry.get("path", "")).name.lower().endswith((".gemspec", ".podspec", ".csproj"))]
        async def read_entry(entry: Dict[str, Any]) -> List[dict]:
            if entry.get("size", 0) > 1_000_000:
                return []
            blob_resp = await _github_get(client, f"{base}/repos/{repo.owner}/{repo.repo}/git/blobs/{entry['sha']}")
            if blob_resp.status_code == 200:
                return _parse(entry["path"], _text(blob_resp.json()), repo.owner, repo.repo)
            return []

        parsed: List[dict] = []
        batches = [paths[i:i + 5] for i in range(0, min(len(paths), _MAX_MANIFESTS), 5)]
        for batch in batches:
            results = await asyncio.gather(*(read_entry(entry) for entry in batch))
            for result in results:
                parsed.extend(result)
    unique = {(c["ecosystem"], c["name"], c["version"], c["manifest"]): c for c in parsed}
    return {
        "repository": repo.url, "defaultBranch": ref, "directory": directory,
        "truncated": bool(tree.get("truncated")) or len(paths) > _MAX_MANIFESTS,
        "packages": list(unique.values()),
    }
