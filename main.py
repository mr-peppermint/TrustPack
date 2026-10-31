
import json

from provenance import verify_npm_signatures

from security_checks import (
    detect_unexpected_files,
    inspect_install_script,
    compare_dependencies,
    inspect_package_metadata
)

from risk_engine import assess_risk


def analyze_package(
    added_files,
    scripts,
    source_package,
    published_package,
    npm_project_dir=None
):
    findings = []

    # 1. Detect unexpected executable files
    findings.extend(
        detect_unexpected_files(added_files)
    )

    # 2. Inspect installation scripts
    for script_name, content in scripts.items():
        findings.extend(
            inspect_install_script(script_name, content)
        )

    # 3. Compare dependencies
    findings.extend(
        compare_dependencies(
            source_package,
            published_package
        )
    )

    # 4. Compare package metadata
    findings.extend(
        inspect_package_metadata(
            source_package,
            published_package
        )
    )

    # 5. Calculate risk
    report = assess_risk(findings)

    # 6. Verify npm signatures, if a project directory is provided
    if npm_project_dir:
        report["provenance"] = verify_npm_signatures(
            npm_project_dir
        )
    else:
        report["provenance"] = {
            "status": "NOT_CHECKED",
            "output": "No npm project directory provided"
        }

    return report


def analyze_package_json(
    added_files,
    scripts,
    source_package,
    published_package,
    npm_project_dir=None
):
    report = analyze_package(
        added_files,
        scripts,
        source_package,
        published_package,
        npm_project_dir
    )

    return json.dumps(report, indent=4)


if __name__ == "__main__":

    # Harmless test: source and published packages are identical
    source = {
        "name": "demo-package",
        "version": "1.0.0",
        "repository": "https://github.com/demo/demo",
        "dependencies": {
            "express": "^4.18.0"
        }
    }

    published = source.copy()

    # No unexpected files
    added_files = []

    # No installation scripts to inspect
    scripts = {}

    # Run analysis
    report = analyze_package_json(
        added_files=added_files,
        scripts=scripts,
        source_package=source,
        published_package=published
    )

    print(report)
