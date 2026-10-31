
def check_provenance(metadata):
    dist = metadata.get("dist", {})

    attestations = dist.get("attestations")
    signatures = dist.get("signatures")

    if attestations:
        status = "ATTESTATION_METADATA_AVAILABLE"
        message = (
            "Provenance attestation metadata is available. "
            "Cryptographic verification is still required."
        )

    elif signatures:
        status = "SIGNATURE_METADATA_AVAILABLE"
        message = (
            "Package signature metadata is available. "
            "Verify it using npm tooling."
        )

    else:
        status = "NOT_AVAILABLE"
        message = (
            "No signature or attestation metadata was found "
            "in the inspected registry response."
        )

    return {
        "provenance_status": status,
        "message": message
    }


import subprocess


def verify_npm_signatures(package_dir):
    try:
        result = subprocess.run(
            ["npm", "audit", "signatures"],
            cwd=package_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout + result.stderr

        if result.returncode == 0 and "verified" in output.lower():
            status = "VERIFIED"
        elif result.returncode == 0:
            status = "NO_VERIFIED_SIGNATURE_REPORTED"
        else:
            status = "FAILED_OR_UNVERIFIABLE"

        return {
            "status": status,
            "exit_code": result.returncode,
            "output": output
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT",
            "output": "Signature verification timed out"
        }

    except FileNotFoundError:
        return {
            "status": "UNAVAILABLE",
            "output": "npm is not installed or not available"
        }
