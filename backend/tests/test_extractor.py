from app.services.archive_extractor import extract_archive
from app.services.manifest_generator import generate_manifest
from tests.conftest import make_tar_gz


def test_extract_archive_unwraps_single_root(tmp_path):
    archive_path = tmp_path / "pkg.tgz"
    archive_path.write_bytes(
        make_tar_gz({"index.js": b"console.log(1)", "package.json": b"{}"}, root_dir="package")
    )
    dest = tmp_path / "dest"

    root = extract_archive(archive_path, dest)

    assert root.name == "package"
    assert (root / "index.js").exists()
    assert (root / "package.json").exists()


def test_manifest_generation_is_deterministic(tmp_path):
    archive_path = tmp_path / "pkg.tgz"
    archive_path.write_bytes(
        make_tar_gz({"index.js": b"console.log(1)", "lib/util.js": b"module.exports={}"}, root_dir="package")
    )
    dest = tmp_path / "dest"
    root = extract_archive(archive_path, dest)

    manifest = generate_manifest(root)

    assert set(manifest.keys()) == {"index.js", "lib/util.js"}
    assert manifest["index.js"].category == "javascript"
    assert manifest["index.js"].sha256 is not None
    assert len(manifest["index.js"].sha256) == 64
