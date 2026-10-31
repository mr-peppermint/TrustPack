
RISK_WEIGHTS = {
    "unexpected_executable": 15,
    "added_dependency": 10,
    "dependency_version_changed": 10,
    "removed_dependency": 5,
    "dynamic_execution": 20,
    "remote_download": 15,
    "remote_shell_execution": 40,
    "encoded_execution": 25,
    "child_process": 10
}

CRITICAL_CATEGORIES = {
    "remote_shell_execution"
}


def assess_risk(findings):
    score = 0
    counted_findings = set()

    for finding in findings:
        category = finding.get("category", "")
        file_name = finding.get("file", "unknown")

        # Avoid counting the same category repeatedly
        # for the same file.
        finding_key = (file_name, category)

        if finding_key in counted_findings:
            continue

        counted_findings.add(finding_key)

        score += RISK_WEIGHTS.get(category, 0)

    score = min(score, 100)

    # Critical findings always result in HIGH risk.
    if any(
        finding.get("category") in CRITICAL_CATEGORIES
        for finding in findings
    ):
        risk = "HIGH"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "overall_risk": risk,
        "risk_score": score,
        "total_findings": len(findings),
        "findings": findings
    }
