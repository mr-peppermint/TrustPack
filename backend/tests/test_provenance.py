import base64
import json

import httpx
import respx

from app.services.provenance_checker import verify_provenance

GIT_HEAD = "46e7056ff9912ebfee5298d94024895a9fea76c0"
TARBALL_SHA512 = "f06fbf5c353cc0db093904b9cac0d53b412d83dff6b80e6047d9786708a38e5" * 2
TARBALL_SHA512 = TARBALL_SHA512[:128]
REPO_URL = "https://github.com/sigstore/sigstore-js"


def _dsse_bundle(statement: dict) -> dict:
    payload_b64 = base64.b64encode(json.dumps(statement).encode()).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {"x509CertificateChain": {"certificates": []}},
        "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": payload_b64, "signatures": []},
    }


def _slsa_statement(repository: str, commit: str, subject_digest: str) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pkg:npm/sigstore@2.3.1", "digest": {"sha512": subject_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"repository": repository, "ref": "refs/heads/main"}},
                "resolvedDependencies": [{"uri": f"git+{repository}", "digest": {"gitCommit": commit}}],
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
        },
    }


ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@2.3.1"


async def test_provenance_not_available_when_no_attestations_metadata():
    result = await verify_provenance(
        attestations_meta=None, signatures=None, tarball_sha512_hex=TARBALL_SHA512,
        resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "NOT_AVAILABLE"
    assert result["findings"] == []


async def test_provenance_not_available_reports_registry_signature_separately():
    result = await verify_provenance(
        attestations_meta=None, signatures=[{"keyid": "abc", "sig": "xyz"}],
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=None, resolved_commit=None,
    )
    assert result["provenance_status"] == "NOT_AVAILABLE"
    assert result["registry_signature_present"] is True


@respx.mock
async def test_provenance_consistent_claims_is_not_verified_not_fabricated_verified():
    """Claims-consistent attestation must be reported as NOT_VERIFIED, never
    VERIFIED — no cryptographic chain-of-trust check is performed.
    """
    respx.get(ATTESTATIONS_URL).mock(return_value=httpx.Response(200, json={
        "attestations": [{"predicateType": "https://slsa.dev/provenance/v1",
                           "bundle": _dsse_bundle(_slsa_statement(REPO_URL, GIT_HEAD, TARBALL_SHA512))}]
    }))
    result = await verify_provenance(
        attestations_meta={"url": ATTESTATIONS_URL}, signatures=None,
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "NOT_VERIFIED"
    assert result["findings"] == []


@respx.mock
async def test_provenance_invalid_when_commit_mismatch():
    respx.get(ATTESTATIONS_URL).mock(return_value=httpx.Response(200, json={
        "attestations": [{"predicateType": "https://slsa.dev/provenance/v1",
                           "bundle": _dsse_bundle(_slsa_statement(REPO_URL, "f" * 40, TARBALL_SHA512))}]
    }))
    result = await verify_provenance(
        attestations_meta={"url": ATTESTATIONS_URL}, signatures=None,
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "INVALID"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == "PROVENANCE_CLAIM_MISMATCH"


@respx.mock
async def test_provenance_invalid_when_repository_mismatch():
    respx.get(ATTESTATIONS_URL).mock(return_value=httpx.Response(200, json={
        "attestations": [{"predicateType": "https://slsa.dev/provenance/v1",
                           "bundle": _dsse_bundle(_slsa_statement("https://github.com/attacker/evil-repo", GIT_HEAD, TARBALL_SHA512))}]
    }))
    result = await verify_provenance(
        attestations_meta={"url": ATTESTATIONS_URL}, signatures=None,
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "INVALID"


@respx.mock
async def test_provenance_invalid_when_subject_digest_mismatch():
    respx.get(ATTESTATIONS_URL).mock(return_value=httpx.Response(200, json={
        "attestations": [{"predicateType": "https://slsa.dev/provenance/v1",
                           "bundle": _dsse_bundle(_slsa_statement(REPO_URL, GIT_HEAD, "0" * 128))}]
    }))
    result = await verify_provenance(
        attestations_meta={"url": ATTESTATIONS_URL}, signatures=None,
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "INVALID"


@respx.mock
async def test_provenance_unknown_when_fetch_fails():
    respx.get(ATTESTATIONS_URL).mock(return_value=httpx.Response(500))
    result = await verify_provenance(
        attestations_meta={"url": ATTESTATIONS_URL}, signatures=None,
        tarball_sha512_hex=TARBALL_SHA512, resolved_repo_url=REPO_URL, resolved_commit=GIT_HEAD,
    )
    assert result["provenance_status"] == "UNKNOWN"
