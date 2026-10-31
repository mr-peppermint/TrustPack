"""Hashing and npm integrity-field verification helpers."""
import base64
import hashlib
from pathlib import Path
from typing import Optional, Tuple

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_integrity_field(integrity: str) -> Optional[Tuple[str, str]]:
    """Parse an npm `dist.integrity` SRI-style string, e.g. 'sha512-AbC...=='.

    Returns (algorithm, base64_digest) or None if the format is unrecognized.
    """
    if not integrity or "-" not in integrity:
        return None
    algo, _, b64digest = integrity.partition("-")
    algo = algo.lower()
    if algo not in ("sha512", "sha384", "sha256") or not b64digest:
        return None
    return algo, b64digest


def verify_integrity(data: bytes, integrity: Optional[str], shasum: Optional[str]) -> dict:
    """Verify tarball bytes against npm's published integrity metadata.

    Prefers the SRI `integrity` field (sha512/384/256). Falls back to the
    legacy `shasum` (sha1) field when integrity is unavailable. Returns a
    dict describing which check ran and whether it passed.
    """
    parsed = parse_integrity_field(integrity) if integrity else None
    if parsed:
        algo, expected_b64 = parsed
        digest = hashlib.new(algo, data).digest()
        actual_b64 = base64.b64encode(digest).decode("ascii")
        return {
            "algorithm": algo,
            "verified": actual_b64 == expected_b64,
            "expected": expected_b64,
            "actual": actual_b64,
            "method": "integrity",
        }
    if shasum:
        actual_hex = hashlib.sha1(data).hexdigest()
        return {
            "algorithm": "sha1",
            "verified": actual_hex.lower() == shasum.lower(),
            "expected": shasum,
            "actual": actual_hex,
            "method": "shasum",
        }
    return {
        "algorithm": None,
        "verified": None,
        "expected": None,
        "actual": None,
        "method": "none",
    }
