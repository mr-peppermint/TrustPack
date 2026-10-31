"""npm provenance verification.

Scope, stated plainly: this performs claims-level cross-checking of an npm
provenance attestation (SLSA v1 / in-toto statement, as published by
`npm publish --provenance`) against facts this analysis already established
independently (tarball digest, resolved source repository, resolved commit).
It does NOT perform Fulcio certificate chain validation or Rekor
transparency-log inclusion verification — that would require trusting
Sigstore's TUF root and validating a full certificate chain, which is out of
scope for this MVP (see README limitations). Because the cryptographic trust
chain is never checked, a structurally-consistent attestation is reported as
NOT_VERIFIED, never VERIFIED — per the explicit requirement that verification
must never be inferred from metadata presence alone, and that an incomplete
verification must be reported as NOT_VERIFIED rather than fabricated as a pass.

Only an attestation whose claims actively CONTRADICT independently-observed
facts (wrong subject digest, wrong repository, wrong commit) is reported as
INVALID — that determination needs no cryptography, just arithmetic.
"""
import base64
import json
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.utils.http_client import safe_get
from app.utils.logging import get_logger
from app.utils.security import validate_outbound_url

logger = get_logger(__name__)

_PUBLISH_PREDICATE = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
_SLSA_PREDICATE = "https://slsa.dev/provenance/v1"


def _decode_dsse_statement(bundle: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        payload_b64 = bundle["dsseEnvelope"]["payload"]
        statement = json.loads(base64.b64decode(payload_b64))
        return statement
    except Exception as exc:  # noqa: BLE001 - any malformed/unexpected shape degrades gracefully
        logger.warning("Could not decode attestation DSSE payload: %s" % exc)
        return None


def _extract_slsa_claims(statement: Dict[str, Any]) -> Dict[str, Any]:
    predicate = statement.get("predicate") or {}
    build_def = predicate.get("buildDefinition") or {}
    workflow = (build_def.get("externalParameters") or {}).get("workflow") or {}
    resolved_deps = build_def.get("resolvedDependencies") or []
    commit = None
    for dep in resolved_deps:
        digest = dep.get("digest") or {}
        if digest.get("gitCommit"):
            commit = digest["gitCommit"]
            break
    builder_id = ((predicate.get("runDetails") or {}).get("builder") or {}).get("id")
    return {
        "repository": workflow.get("repository"),
        "ref": workflow.get("ref"),
        "commit": commit,
        "builder_id": builder_id,
    }


async def _fetch_attestations(attestations_url: str) -> Optional[List[Dict[str, Any]]]:
    validate_outbound_url(attestations_url, settings.ALLOWED_TARBALL_HOSTS)
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await safe_get(client, attestations_url, settings.ALLOWED_TARBALL_HOSTS)
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
    return data.get("attestations")


async def verify_provenance(
    *,
    attestations_meta: Optional[Dict[str, Any]],
    signatures: Optional[Any],
    tarball_sha512_hex: str,
    resolved_repo_url: Optional[str],
    resolved_commit: Optional[str],
) -> Dict[str, Any]:
    """Returns a dict with keys: provenance_status, detail,
    registry_signature_present, findings (list, only populated for INVALID).
    """
    registry_signature_present = bool(signatures)

    if not attestations_meta or not attestations_meta.get("url"):
        return {
            "provenance_status": "NOT_AVAILABLE",
            "registry_signature_present": registry_signature_present,
            "detail": (
                "No build provenance attestation was published for this version. "
                "This does not indicate the package is unsafe — provenance adoption is "
                "optional and most legitimate packages do not publish it. A baseline "
                f"registry signature {'is' if registry_signature_present else 'is not'} "
                "present, which only confirms the tarball matches what the registry "
                "served, not who built it or from what source."
            ),
            "findings": [],
        }

    try:
        attestations = await _fetch_attestations(attestations_meta["url"])
    except Exception as exc:  # noqa: BLE001 - network/allowlist failures degrade to UNKNOWN
        logger.warning("Provenance attestation fetch failed: %s" % exc)
        return {
            "provenance_status": "UNKNOWN",
            "registry_signature_present": registry_signature_present,
            "detail": f"Attestation metadata was present but could not be retrieved/parsed ({exc}).",
            "findings": [],
        }

    if not attestations:
        return {
            "provenance_status": "UNKNOWN",
            "registry_signature_present": registry_signature_present,
            "detail": "Attestation metadata was present but the attestation bundle could not be retrieved.",
            "findings": [],
        }

    slsa_bundle = next((a for a in attestations if a.get("predicateType") == _SLSA_PREDICATE), None)
    publish_bundle = next((a for a in attestations if a.get("predicateType") == _PUBLISH_PREDICATE), None)

    mismatches: List[str] = []
    claims: Dict[str, Any] = {}

    # Every attestation statement (publish and SLSA alike) carries the same
    # `subject[0].digest.sha512` claim — check it against whichever
    # statement(s) are available, not just one specific predicate type.
    for bundle_entry in (publish_bundle, slsa_bundle):
        if not bundle_entry:
            continue
        statement = _decode_dsse_statement(bundle_entry["bundle"])
        if not statement:
            continue
        subject = (statement.get("subject") or [{}])[0]
        attested_digest = (subject.get("digest") or {}).get("sha512")
        if attested_digest and attested_digest.lower() != tarball_sha512_hex.lower():
            mismatches.append(
                f"Attested tarball sha512 digest ({attested_digest}) does not match the "
                f"independently computed digest ({tarball_sha512_hex}) of the downloaded tarball."
            )

    if slsa_bundle:
        statement = _decode_dsse_statement(slsa_bundle["bundle"])
        if statement:
            claims = _extract_slsa_claims(statement)
            if resolved_repo_url and claims.get("repository"):
                if claims["repository"].rstrip("/").lower() != resolved_repo_url.rstrip("/").lower():
                    mismatches.append(
                        f"Attested build repository ({claims['repository']}) does not match "
                        f"the resolved source repository ({resolved_repo_url})."
                    )
            if resolved_commit and claims.get("commit"):
                if claims["commit"].lower() != resolved_commit.lower():
                    mismatches.append(
                        f"Attested build commit ({claims['commit']}) does not match the "
                        f"resolved source commit ({resolved_commit})."
                    )

    if mismatches:
        findings = [{
            "rule_id": "PROVENANCE_CLAIM_MISMATCH",
            "file": "package.json",
            "category": "provenance_claim_mismatch",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "evidence": " ".join(mismatches),
            "explanation": (
                "The published provenance attestation's own claims (subject digest, source "
                "repository, or source commit) contradict facts this analysis independently "
                "verified. This is a structural/claims-level check only — no cryptographic "
                "signature verification was performed."
            ),
            "recommendation": "Treat this version with heightened suspicion; the provenance record does not match the analyzed artifact.",
        }]
        return {
            "provenance_status": "INVALID",
            "registry_signature_present": registry_signature_present,
            "detail": "Attestation claims are internally inconsistent with independently observed facts: " + " ".join(mismatches),
            "findings": findings,
        }

    detail = (
        "A provenance attestation was published and its claims (subject digest"
        + (", source repository" if claims.get("repository") else "")
        + (", source commit" if claims.get("commit") else "")
        + ") are consistent with this analysis's independent findings. "
        "NOTE: this is a claims-consistency check only — the attestation's cryptographic "
        "signature chain (Fulcio certificate + Rekor transparency log) was NOT verified, "
        "so this is reported as NOT_VERIFIED rather than VERIFIED."
    )
    return {
        "provenance_status": "NOT_VERIFIED",
        "registry_signature_present": registry_signature_present,
        "detail": detail,
        "findings": [],
    }
