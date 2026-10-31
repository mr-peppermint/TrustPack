"""Static analysis of package scripts, dependencies, metadata, and code patterns.

All findings here are evidence-based pattern matches, explicitly framed as such.
Nothing in this module claims proof of malicious intent — it surfaces signals
for a human (or the risk engine) to weigh. Every finding carries a stable
`rule_id` so a reviewer (or a dedup pass) can trace exactly which check fired.
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

_LIFECYCLE_SCRIPTS_OF_CONCERN = (
    "preinstall", "install", "postinstall", "prepare", "prepublishOnly",
)

_SUSPICIOUS_SCRIPT_SUBSTRINGS = (
    "curl ", "wget ", "eval(", "base64", "nc -e", "bash -c", "powershell",
    "invoke-expression", "sudo ", "chmod +x", "rm -rf /", "> /dev/",
)

_CODE_PATTERNS = {
    "dynamic_code_execution": re.compile(r"\beval\s*\(|new\s+Function\s*\("),
    "child_process_usage": re.compile(r"require\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]"),
    "network_module_usage": re.compile(r"require\(\s*['\"](?:net|http|https|dgram)['\"]\s*\)"),
    "env_credential_access": re.compile(r"process\.env\[[^\]]+\]|process\.env\.\w+"),
    "base64_obfuscation": re.compile(r"Buffer\.from\([^)]*['\"]base64['\"]\)|atob\s*\("),
    "shell_execution": re.compile(r"\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\("),
}

_SCANNABLE_EXTENSIONS = {".js", ".mjs", ".cjs"}
_MAX_FINDINGS_PER_PATTERN = 5


def _severity_for_script(name: str, command: str) -> str:
    lower = command.lower()
    if any(s in lower for s in _SUSPICIOUS_SCRIPT_SUBSTRINGS):
        return "HIGH"
    if name in ("preinstall", "install", "postinstall"):
        return "MEDIUM"
    return "LOW"


def analyze_lifecycle_scripts(scripts: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    for name in _LIFECYCLE_SCRIPTS_OF_CONCERN:
        command = scripts.get(name)
        if not command:
            continue
        severity = _severity_for_script(name, command)
        findings.append({
            "rule_id": "LIFECYCLE_SCRIPT_PRESENT",
            "file": "package.json",
            "category": "lifecycle_script",
            "severity": severity,
            "confidence": "HIGH" if severity == "HIGH" else "MEDIUM",
            "evidence": f'scripts.{name} = "{command}"',
            "explanation": (
                f"The '{name}' lifecycle script runs automatically during npm install "
                "and can execute arbitrary code on the installing machine."
            ),
            "recommendation": f"Manually review the '{name}' script contents before installing.",
        })
    return findings


def analyze_lifecycle_script_changes(
    published_scripts: Dict[str, str], source_scripts: Optional[Dict[str, str]]
) -> List[Dict[str, Any]]:
    """Flag lifecycle scripts present in the published package.json but
    absent from the source repository's package.json. A script *injected*
    only at publish time — something the public source history never saw —
    is a materially stronger signal than a lifecycle script that has simply
    always existed in the source.
    """
    if source_scripts is None:
        return []
    findings = []
    for name in _LIFECYCLE_SCRIPTS_OF_CONCERN:
        published_cmd = published_scripts.get(name)
        if not published_cmd:
            continue
        source_cmd = source_scripts.get(name)
        if source_cmd is None:
            findings.append({
                "rule_id": "LIFECYCLE_SCRIPT_INJECTED",
                "file": "package.json",
                "category": "lifecycle_script_injected",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "evidence": f'scripts.{name} = "{published_cmd}" exists in the published package.json but not in source',
                "explanation": (
                    f"The '{name}' script was not present in the resolved source repository's "
                    "package.json and appears only in the published artifact — it was never "
                    "reviewable in the public source history before publish."
                ),
                "recommendation": f"Treat '{name}' as unreviewed code; confirm with the maintainer why it was added at publish time.",
            })
        elif source_cmd != published_cmd:
            findings.append({
                "rule_id": "LIFECYCLE_SCRIPT_CHANGED",
                "file": "package.json",
                "category": "lifecycle_script_changed",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "evidence": f"scripts.{name}: source=\"{source_cmd}\" published=\"{published_cmd}\"",
                "explanation": f"The '{name}' script's command differs between source and the published package.",
                "recommendation": f"Diff the '{name}' script between source and published package.json.",
            })
    return findings


def analyze_dependency_changes(
    published_deps: Dict[str, str], source_deps: Optional[Dict[str, str]]
) -> List[Dict[str, Any]]:
    if source_deps is None:
        return []
    findings = []
    published_only = sorted(set(published_deps) - set(source_deps))
    for dep in published_only:
        findings.append({
            "rule_id": "DEPENDENCY_ADDED_AT_PUBLISH",
            "file": "package.json",
            "category": "dependency_discrepancy",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": f"Dependency '{dep}' declared in the published package but absent from source repository metadata",
            "explanation": "A dependency present only at publish time cannot be verified against the public source history.",
            "recommendation": f"Confirm '{dep}' was intentionally added during the release/build process.",
        })
    common = set(published_deps) & set(source_deps)
    for dep in sorted(common):
        if published_deps[dep] != source_deps[dep]:
            findings.append({
                "rule_id": "DEPENDENCY_VERSION_MISMATCH",
                "file": "package.json",
                "category": "dependency_version_mismatch",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": f"Dependency '{dep}' version differs: source='{source_deps[dep]}' published='{published_deps[dep]}'",
                "explanation": "Dependency version ranges can change between the repository and the published release.",
                "recommendation": f"Confirm the version change for '{dep}' is an intentional release-time update.",
            })
    return findings


def scan_code_patterns(published_root: Path, manifest_paths: List[str]) -> List[Dict[str, Any]]:
    findings = []
    hits_per_pattern: Dict[str, int] = {}

    for rel_path in manifest_paths:
        if Path(rel_path).suffix.lower() not in _SCANNABLE_EXTENSIONS:
            continue
        abs_path = published_root / rel_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern_name, pattern in _CODE_PATTERNS.items():
            if hits_per_pattern.get(pattern_name, 0) >= _MAX_FINDINGS_PER_PATTERN:
                continue
            match = pattern.search(text)
            if match:
                hits_per_pattern[pattern_name] = hits_per_pattern.get(pattern_name, 0) + 1
                snippet = text[max(0, match.start() - 20):match.end() + 20].replace("\n", " ").strip()
                findings.append({
                    "rule_id": f"CODE_PATTERN_{pattern_name.upper()}",
                    "file": rel_path,
                    "category": pattern_name,
                    "severity": "LOW",
                    "confidence": "LOW",
                    "evidence": f"Static pattern match: ...{snippet}...",
                    "explanation": (
                        "This is a static text pattern match only, not proof of malicious behavior. "
                        "Many legitimate packages use these APIs."
                    ),
                    "recommendation": f"Manually review {rel_path} to confirm this usage is expected.",
                })
    return findings


def analyze_declared_entrypoints(package_json: Dict[str, Any], published_paths: set) -> List[Dict[str, Any]]:
    findings = []
    for key in ("main", "module", "types", "typings"):
        val = package_json.get(key)
        if isinstance(val, str) and val.strip():
            norm = val.strip().lstrip("./")
            if norm not in published_paths:
                findings.append({
                    "rule_id": "DECLARED_ENTRYPOINT_MISSING",
                    "file": "package.json",
                    "category": "metadata_discrepancy",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "evidence": f"package.json '{key}' declares '{val}' but no such file exists in the published tarball",
                    "explanation": "A declared entrypoint that does not exist indicates broken packaging or tampered metadata.",
                    "recommendation": f"Verify the '{key}' field and confirm the referenced file was intentionally omitted.",
                })
    return findings
