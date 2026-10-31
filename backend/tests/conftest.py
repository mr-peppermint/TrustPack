import io
import socket
import tarfile
from typing import Dict, Optional

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
