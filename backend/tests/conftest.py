import base64
import hashlib
import io
import json
import socket
import tarfile
import zipfile
from typing import Dict, List, Optional, Tuple

import httpx
import respx

import pytest

_PUBLIC_IP_FOR_TESTS = "93.184.216.34"  # example.com's public IP; used as a stand-in resolution


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """The SSRF guard in app.utils.security resolves every outbound hostname
    via socket.getaddrinfo before connecting. respx mocks the HTTP transport
    but not DNS, and the test suite must not depend on live network/DNS
    availability — so by default, every hostname resolves to a fixed public
    IP. Tests that specifically exercise SSRF rejection override this within
    their own test body.
    """
    def _fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_FOR_TESTS, 443))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch, tmp_path):
    """Every test gets its own SQLite history file and a disabled AI provider, so no test can touch
    the developer's real database or call a hosted model."""
    from app.config import settings

    monkeypatch.setattr(settings, "DATABASE_PATH", str(tmp_path / "history.db"))
    monkeypatch.setattr(settings, "AI_ENABLED", False)
    monkeypatch.setattr(settings, "AI_API_KEY", "")
    monkeypatch.setattr(settings, "SUPABASE_URL", "")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_KEY", "")


def make_tar_gz(files: Dict[str, bytes], root_dir: Optional[str] = None) -> bytes:
    """Build an in-memory .tar.gz from a {relative_path: content} mapping.

    If root_dir is given, every entry is nested under that single top-level
    directory (mimicking npm's "package/" wrapper or GitHub's "{repo}-{ref}/").
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel_path, content in files.items():
            full_path = f"{root_dir}/{rel_path}" if root_dir else rel_path
            info = tarfile.TarInfo(name=full_path)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_malicious_traversal_tar_gz() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="../../etc/evil.txt")
        content = b"pwned"
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


@pytest.fixture
def simple_package_json() -> dict:
    return {
        "name": "example-package",
        "version": "1.0.0",
        "main": "index.js",
        "scripts": {"test": "jest"},
        "dependencies": {"left-pad": "^1.0.0"},
        "repository": {"type": "git", "url": "git+https://github.com/example/example-package.git"},
    }


def make_zip(files: Dict[str, bytes], modes: Optional[Dict[str, int]] = None) -> bytes:
    """In-memory .zip/.whl. `modes` maps a path to a Unix mode stored in external_attr (e.g. 0o755, or 0o120777 for a symlink)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            info = zipfile.ZipInfo(path)
            info.external_attr = ((modes or {}).get(path, 0o100644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
    return buf.getvalue()


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel(name: str, version: str, files: Dict[str, bytes], *, tamper: Optional[Dict[str, bytes]] = None,
               extra_unlisted: Optional[Dict[str, bytes]] = None) -> bytes:
    """A structurally valid wheel with a correct RECORD. `tamper` replaces file bytes AFTER the RECORD was
    written (simulating a post-build modification); `extra_unlisted` adds files RECORD does not mention."""
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    content = dict(files)
    content[f"{dist_info}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    content[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    rows = [f"{p},{record_hash(b)},{len(b)}" for p, b in content.items()]
    rows.append(f"{dist_info}/RECORD,,")
    content[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()
    content.update(tamper or {})
    content.update(extra_unlisted or {})
    return make_zip(content)


def mock_pypi_release(name: str, version: str, artifacts: List[Tuple[str, str, bytes]], *, project_urls=None,
                      sha_override: Optional[Dict[str, str]] = None, yanked: Optional[List[str]] = None) -> Dict[str, str]:
    """Register respx routes for a PyPI release. artifacts = [(filename, 'sdist'|'bdist_wheel', bytes)]. Returns {filename: url}."""
    urls, mapping = [], {}
    for filename, packagetype, blob in artifacts:
        url = f"https://files.pythonhosted.org/packages/ab/cd/{filename}"
        mapping[filename] = url
        urls.append({
            "filename": filename, "packagetype": packagetype, "url": url, "size": len(blob), "yanked": filename in (yanked or []),
            "digests": {"sha256": (sha_override or {}).get(filename, hashlib.sha256(blob).hexdigest())},
            "upload_time_iso_8601": "2026-01-02T03:04:05.000000Z",
        })
        respx.get(url).mock(return_value=httpx.Response(200, content=blob))
    respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(return_value=httpx.Response(200, json={
        "info": {"name": name, "version": version, "project_urls": project_urls if project_urls is not None else {"Source": "https://github.com/acme/" + name},
                 "requires_dist": ["urllib3<3,>=1.21", "pysocks; extra == 'socks'"]},
        "urls": urls,
    }))
    return mapping


def mock_github_tag(owner: str, repo: str, tag: str, source_tar: bytes) -> None:
    respx.get(f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag}").mock(
        return_value=httpx.Response(200, json={"ref": f"refs/tags/{tag}", "object": {"sha": "b" * 40, "type": "commit"}})
    )
    respx.get(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{'b' * 40}").mock(return_value=httpx.Response(200, content=source_tar))


def mock_pypi_provenance_missing(name: str, version: str, filename: str) -> None:
    respx.get(f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance").mock(return_value=httpx.Response(404))
