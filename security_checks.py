
from pathlib import Path

EXECUTABLE_EXTENSIONS = {
    ".js", ".cjs", ".mjs", ".py", ".sh",
    ".bat", ".cmd", ".ps1"
}


def detect_unexpected_files(added_files):
    findings = []

    for file in added_files:
        path = Path(file)

        if path.suffix.lower() in EXECUTABLE_EXTENSIONS:
            findings.append({
                "file": file,
                "category": "unexpected_executable",
                "risk": "MEDIUM",
                "reason": "An executable file exists in the published package but was not found in the source comparison.",
                "evidence": f"Additional executable file: {file}"
            })

    return findings


import re


SUSPICIOUS_PATTERNS = {
    "remote_shell_execution": r"curl.{0,200}\|\s*(sh|bash)|wget.{0,200}\|\s*(sh|bash)",
    "remote_download": r"\b(curl|wget)\b",
    "dynamic_execution": r"\beval\s*\(",
    "child_process": r"child_process|execSync|spawnSync",
    "encoded_execution": r"base64\s+(-d|--decode)"
}


def inspect_install_script(script_name, script_content):
    findings = []

    for category, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, script_content, re.IGNORECASE):
            findings.append({
                "file": script_name,
                "category": category,
                "risk": "HIGH" if category in (
                    "remote_shell_execution",
                    "encoded_execution"
                ) else "MEDIUM",
                "reason": "Potentially dangerous behavior detected in an installation script.",
                "evidence": f"Matched static pattern: {category}"
            })

    return findings


def compare_dependencies(source_package, published_package):
    findings = []

    dependency_types = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies"
    ]

    for dep_type in dependency_types:
        source_deps = source_package.get(dep_type, {})
        published_deps = published_package.get(dep_type, {})

        for name, version in published_deps.items():
            if name not in source_deps:
                findings.append({
                    "file": "package.json",
                    "category": "added_dependency",
                    "risk": "MEDIUM",
                    "reason": f"New dependency added: {name}",
                    "evidence": (
                        f"{dep_type}: {name}@{version}"
                    )
                })

            elif source_deps[name] != version:
                findings.append({
                    "file": "package.json",
                    "category": "dependency_version_changed",
                    "risk": "MEDIUM",
                    "reason": f"Dependency version changed: {name}",
                    "evidence": (
                        f"Source: {source_deps[name]}, "
                        f"Published: {version}"
                    )
                })

        for name, version in source_deps.items():
            if name not in published_deps:
                findings.append({
                    "file": "package.json",
                    "category": "removed_dependency",
                    "risk": "LOW",
                    "reason": f"Dependency missing from published metadata: {name}",
                    "evidence": f"Source version: {version}"
                })

    return findings


def inspect_package_metadata(source, published):
    findings = []

    fields = [
        "name",
        "version",
        "repository"
    ]

    for field in fields:
        source_value = source.get(field)
        published_value = published.get(field)

        if source_value != published_value:
            findings.append({
                "file": "package.json",
                "category": "metadata_mismatch",
                "risk": "MEDIUM",
                "reason": f"Package metadata mismatch: {field}",
                "evidence": (
                    f"Source: {source_value}; "
                    f"Published: {published_value}"
                )
            })

    scripts = published.get("scripts", {})

    for script_name in [
        "preinstall",
        "install",
        "postinstall"
    ]:
        if script_name in scripts:
            findings.append({
                "file": "package.json",
                "category": "lifecycle_script",
                "risk": "MEDIUM",
                "reason": (
                    f"Published package has a "
                    f"{script_name} lifecycle script."
                ),
                "evidence": scripts[script_name]
            })

    return findings
