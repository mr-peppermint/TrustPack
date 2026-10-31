"""Decides whether a file that differs from the source repository is plausibly build output.

The old rule "anything under dist/ is generated" is a bypass: an attacker simply drops a payload into
dist/. This detector instead requires EVIDENCE tying the file to the source, scores it, and keeps the
result honest:

  EXPECTED_GENERATED  enough independent evidence (see below) and nothing contradicting it
  UNCERTAIN           looks like build output but the evidence is thin, or it cannot be verified
                      without rebuilding (binaries, bytecode), or its content looks suspicious
  NOT_GENERATED       no meaningful evidence; the caller classifies it as added/modified/unexplained

Evidence and weights (a file needs a total of >= 2.0 to be EXPECTED_GENERATED):
  strong (2.0)  a same-stem SOURCE file exists at a different path/extension (src/a.ts -> dist/a.js),
                a source map whose `sources` resolve to repository files, a .d.ts whose .ts exists,
                standardised wheel *.dist-info / sdist *.egg-info metadata, Cython .c <- .pyx
  medium (1.0)  declared as a package entry point (main/module/types/exports/bin...), the repository has
                a build script AND build tooling configuration (tsconfig/rollup/webpack/...)
  weak   (0.5)  conventional build-output directory or suffix (.min.js, .map, .d.ts, dist/...)

Hard disqualifiers — the file is never auto-trusted, however it is named or located:
  executable bit / shebang (unless declared in `bin`), script/executable extensions (.sh .py .exe ...),
  and content that looks obfuscated or hostile (see suspicious_code).

This module never proves a file is benign: it records WHY a file was considered build output so a reviewer
can challenge the rule. Reproducing the build is out of scope and is stated as a limitation of every report.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set

from app.services.suspicious_code import find_suspicious_content

EXPECTED = "EXPECTED_GENERATED"
UNCERTAIN = "UNCERTAIN"
NOT_GENERATED = "NOT_GENERATED"

_BUILD_DIRS = {
    "dist", "build", "out", "umd", "cjs", "esm", "es", "lib", "lib-es", "esm5", "esm2015", "bundles",
    "browser", "module", "types", "typings", "compiled", "_esm", "_cjs",
}
_SOURCE_EXTS = {
    ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".coffee", ".vue", ".svelte",
    ".scss", ".sass", ".less", ".styl", ".css", ".flow",
}
_BLOCKED_EXTS = {
    ".sh", ".bash", ".bat", ".cmd", ".ps1", ".py", ".rb", ".pl", ".php", ".exe", ".msi", ".com", ".scr",
    ".vbs", ".jar", ".class",
}
_COMPILED_EXTS = {".node", ".so", ".dylib", ".dll", ".pyd", ".wasm", ".pyc", ".pyo", ".a", ".o"}
_BUILD_CONFIGS = (
    "tsconfig.json", "tsconfig.build.json", "rollup.config.", "webpack.config.", "vite.config.",
    "tsup.config.", "esbuild.", "babel.config.", ".babelrc", "gulpfile.", "gruntfile.", "swc", "parcel",
    "microbundle", "unbuild", "build.config.", "pkgroll", "bunchee", "Makefile",
)
_PY_BUILD_CONFIGS = ("pyproject.toml", "setup.py", "setup.cfg", "MANIFEST.in", "tox.ini")
_DIST_INFO_FILES = {
    "metadata", "wheel", "record", "entry_points.txt", "top_level.txt", "installer", "requested",
    "direct_url.json", "dependency_links.txt", "zip-safe", "not-zip-safe", "namespace_packages.txt",
}
_EGG_INFO_FILES = {
    "pkg-info", "sources.txt", "requires.txt", "top_level.txt", "entry_points.txt", "dependency_links.txt",
    "not-zip-safe", "zip-safe", "namespace_packages.txt",
}
_VERSION_FILE_RE = re.compile(r"(?:^|/)(?:_version|version|_vendor_version)\.py$")
_VERSION_TOOLS = ("setuptools_scm", "setuptools-scm", "versioneer", "hatch-vcs", "hatch_vcs", "pdm-backend", "dunamai")
_MAX_READ_BYTES = 2_000_000


@dataclass
class Classification:
    status: str  # EXPECTED_GENERATED | UNCERTAIN | NOT_GENERATED
    reason: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    score: float = 0.0


def _stem(path: str) -> str:
    """Path without its final extension; '.d.ts' and '.min.<ext>' count as one suffix."""
    p = path
    for suffix in (".d.ts", ".d.mts", ".d.cts", ".min.js", ".min.css", ".js.map", ".css.map", ".mjs.map", ".cjs.map"):
        if p.lower().endswith(suffix):
            return p[: -len(suffix)]
    return str(PurePosixPath(p).with_suffix(""))


def _strip_build_dirs(path: str) -> str:
    parts = path.split("/")
    while len(parts) > 1 and parts[0].lower() in _BUILD_DIRS:
        parts = parts[1:]
    return "/".join(parts)


class GeneratedFileDetector:
    def __init__(
        self,
        *,
        ecosystem: str = "npm",
        source_manifest: Optional[Dict[str, Any]] = None,
        published_manifest: Optional[Dict[str, Any]] = None,
        published_root: Optional[Path] = None,
        source_root: Optional[Path] = None,
        published_package_json: Optional[Dict[str, Any]] = None,
        source_package_json: Optional[Dict[str, Any]] = None,
        artifact_kind: Optional[str] = None,
        package_name: Optional[str] = None,
        package_version: Optional[str] = None,
        source_path_for: Optional[Dict[str, str]] = None,
    ) -> None:
        self.ecosystem = ecosystem
        self.source = source_manifest or {}
        self.published = published_manifest or {}
        self.published_root = published_root
        self.source_root = source_root
        self.pkg = published_package_json or {}
        self.src_pkg = source_package_json or {}
        self.kind = artifact_kind
        self.name = package_name
        self.version = package_version
        # published path -> the aligned path of its counterpart in the source tree (when they differ)
        self.source_path_for = source_path_for or {}

        self._source_stems: Optional[Set[str]] = None
        self._declared = self._declared_outputs()
        self._build_evidence = self._detect_build_tooling()
        self._version_tool = self._detect_version_tool()

    # ----------------------------------------------------------------- indexes / helpers

    def _source_stem_index(self) -> Set[str]:
        """Every suffix of every source file's stem ('a/b/c' -> 'a/b/c', 'b/c', 'c') for source-like files."""
        if self._source_stems is None:
            idx: Set[str] = set()
            for p in self.source:
                if PurePosixPath(p.lower()).suffix in _SOURCE_EXTS | {".pyx", ".pxd", ".py"}:
                    parts = _stem(p).split("/")
                    for i in range(len(parts)):
                        idx.add("/".join(parts[i:]))
            self._source_stems = idx
        return self._source_stems

    def _declared_outputs(self) -> Dict[str, str]:
        pkg = self.pkg
        outputs: Dict[str, str] = {}

        def norm(v: str) -> str:
            return PurePosixPath(v.strip().lstrip("./")).as_posix()

        for key in ("main", "module", "types", "typings", "browser", "unpkg", "jsdelivr", "bin"):
            val = pkg.get(key)
            if isinstance(val, str):
                outputs[norm(val)] = key
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        outputs[norm(v)] = key

        def walk(node: Any) -> None:
            if isinstance(node, str):
                outputs[norm(node)] = "exports"
            elif isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(pkg.get("exports"))
        return outputs

    def _detect_build_tooling(self) -> Optional[str]:
        """Medium evidence: the repository has a build script AND tooling config for it."""
        if self.ecosystem == "pypi":
            present = [c for c in _PY_BUILD_CONFIGS if c in self.source]
            return ("repository has Python build configuration (%s)" % ", ".join(present)) if present else None
        scripts = (self.src_pkg or self.pkg).get("scripts") or {}
        has_script = any(k in scripts for k in ("build", "compile", "prepare", "prepublishOnly", "prepack"))
        names = [PurePosixPath(p).name for p in self.source]
        configs = sorted({c for c in _BUILD_CONFIGS for n in names if n == c or n.startswith(c)})
        if has_script and configs:
            return "repository has a build script and build tooling config (%s)" % ", ".join(configs[:4])
        return None

    def _detect_version_tool(self) -> Optional[str]:
        for name in ("pyproject.toml", "setup.py", "setup.cfg"):
            if name in self.source and self.source_root is not None:
                text = self._read(self.source_root, name) or ""
                for tool in _VERSION_TOOLS:
                    if tool in text:
                        return tool
        return None

    @staticmethod
    def _read(root: Optional[Path], rel: str) -> Optional[str]:
        if root is None:
            return None
        try:
            path = root / rel
            if not path.is_file() or path.is_symlink():
                return None
            with open(path, "rb") as fh:
                return fh.read(_MAX_READ_BYTES).decode("utf-8", errors="ignore")
        except OSError:
            return None

    def _has_source_counterpart(self, rest: str, own_path: str) -> Optional[str]:
        """A source file with the same stem at a DIFFERENT path (e.g. src/a.ts for dist/a.js)."""
        stem = _stem(rest)
        if stem in self._source_stem_index():
            for candidate in self.source:
                if candidate != own_path and _stem(candidate).endswith(stem) and (
                    _stem(candidate) == stem or _stem(candidate).endswith("/" + stem)
                ):
                    if PurePosixPath(candidate.lower()).suffix in _SOURCE_EXTS | {".pyx", ".pxd", ".py"}:
                        return candidate
        return None

    # ----------------------------------------------------------------- classification

    def classify(self, path: str, *, in_source: bool) -> Classification:
        lower = path.lower()
        ext = PurePosixPath(lower).suffix
        record = self.published.get(path)

        evidence: List[str] = []
        score = 0.0

        # ---- hard disqualifiers -----------------------------------------------------------
        if ext in _BLOCKED_EXTS:
            return Classification(NOT_GENERATED, f"'{ext}' files are scripts/executables and are never auto-trusted as build output")
        if record is not None and getattr(record, "is_executable", False) and path not in self._declared:
            return Classification(NOT_GENERATED, "file is executable (execute bit or shebang) and is not a declared `bin` entry")
        if lower.endswith(".pth"):
            return Classification(NOT_GENERATED, ".pth files are processed by the Python interpreter at startup and are never treated as generated")

        if ext in _COMPILED_EXTS or "/__pycache__/" in "/" + lower:
            return Classification(
                UNCERTAIN,
                "compiled artifact (binary/bytecode): its content cannot be compared with source without reproducing the build",
                ["file type cannot be verified against the repository"],
                0.0,
            )

        text = None
        if self.published_root is not None and ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".py", ".sh"}:
            text = self._read(self.published_root, path)
        if text:
            reasons = find_suspicious_content(path, text)
            if reasons:
                return Classification(
                    UNCERTAIN,
                    "content looks obfuscated or hostile, so it is not trusted as build output: " + "; ".join(reasons),
                    ["suspicious content: " + r for r in reasons],
                    0.0,
                )

        # ---- evidence ---------------------------------------------------------------------
        top = path.split("/")[0].lower()
        if top in _BUILD_DIRS and "/" in path:
            evidence.append(f"located in conventional build-output directory '{top}/' (weak: location alone proves nothing)")
            score += 0.5
        if lower.endswith((".min.js", ".min.css")):
            evidence.append("minified-asset suffix (weak)")
            score += 0.5
        if lower.endswith((".map",)):
            evidence.append("source-map suffix (weak)")
            score += 0.5
        if lower.endswith((".d.ts", ".d.mts", ".d.cts")):
            evidence.append("TypeScript declaration suffix (weak)")
            score += 0.5

        if path in self._declared:
            evidence.append(f"declared as package.json '{self._declared[path]}' entry point")
            score += 1.0

        # PyPI/standardised metadata
        if self.ecosystem == "pypi":
            score, evidence = self._pypi_evidence(path, lower, in_source, score, evidence)

        # source-to-generated relationships (JS/TS family)
        rest = _strip_build_dirs(path)
        if ext in {".js", ".mjs", ".cjs", ".jsx", ".css"} and not lower.endswith((".min.js", ".min.css")):
            counterpart = self._has_source_counterpart(rest, path)
            if counterpart:
                evidence.append(f"source file '{counterpart}' has the same module path (compiled-output relationship)")
                score += 2.0
        if lower.endswith((".min.js", ".min.css")):
            base = path[: -len(".min.js")] + ".js" if lower.endswith(".min.js") else path[: -len(".min.css")] + ".css"
            if base in self.published or base in self.source:
                evidence.append(f"unminified sibling '{base}' exists (minified-copy relationship)")
                score += 2.0
            else:
                counterpart = self._has_source_counterpart(_strip_build_dirs(_stem(path)), path)
                if counterpart:
                    evidence.append(f"source file '{counterpart}' has the same module path")
                    score += 2.0
        if lower.endswith((".d.ts", ".d.mts", ".d.cts")):
            counterpart = self._has_source_counterpart(_strip_build_dirs(path), path)
            if counterpart and PurePosixPath(counterpart.lower()).suffix in {".ts", ".tsx", ".mts", ".cts"}:
                evidence.append(f"TypeScript source '{counterpart}' exists for this declaration file")
                score += 2.0
        if lower.endswith(".map"):
            mapped = self._source_map_evidence(path)
            if mapped:
                evidence.append(mapped)
                score += 2.0

        if self._build_evidence and (top in _BUILD_DIRS or path in self._declared) and ext not in _BLOCKED_EXTS:
            evidence.append(self._build_evidence)
            score += 1.0

        if score >= 2.0:
            return Classification(EXPECTED, "; ".join(e for e in evidence if "(weak" not in e) or evidence[0], evidence, score)
        if score >= 0.5:
            return Classification(
                UNCERTAIN,
                "resembles build output but there is not enough evidence tying it to the repository source",
                evidence,
                score,
            )
        return Classification(NOT_GENERATED, None, evidence, score)

    # ----------------------------------------------------------------- ecosystem helpers

    def _pypi_evidence(self, path: str, lower: str, in_source: bool, score: float, evidence: List[str]):
        parts = lower.split("/")
        name = parts[-1]
        if len(parts) >= 2 and parts[-2].endswith(".dist-info") and self.kind == "wheel":
            leaf = "/".join(parts[-2:])
            base = parts[-2][: -len(".dist-info")]
            expected_prefix = self._wheel_dist_info_prefix()
            is_meta_name = (
                name in _DIST_INFO_FILES
                or name.startswith(("license", "licence", "copying", "notice", "authors"))
                or "licenses" in parts
            )
            if is_meta_name and (expected_prefix is None or base == expected_prefix):
                evidence.append("standard wheel metadata written by the build backend (%s)" % leaf)
                score += 2.0
        if len(parts) >= 2 and parts[-2].endswith(".egg-info") and self.kind == "sdist":
            if name in _EGG_INFO_FILES and self._build_evidence:
                evidence.append("setuptools egg-info metadata generated when the sdist was built")
                score += 2.0
        if name == "pkg-info" and len(parts) <= 2 and self.kind == "sdist" and self._build_evidence:
            evidence.append("PKG-INFO is generated by the sdist build")
            score += 2.0
        if name == "setup.cfg" and self.kind == "sdist" and in_source and self._setup_cfg_only_adds_egg_info(path):
            evidence.append("setup.cfg differs only by the [egg_info] section setuptools appends to sdists")
            score += 2.0
        if _VERSION_FILE_RE.search(lower) and self._version_tool:
            evidence.append(f"version module written by '{self._version_tool}' (configured in the repository)")
            score += 2.0
        if lower.endswith((".c", ".cpp", ".h")):
            pyx = self._cython_source_for(path)
            if pyx:
                evidence.append(f"Cython source '{pyx}' exists (generated C output; content not reproduced)")
                score += 2.0
        return score, evidence

    def _wheel_dist_info_prefix(self) -> Optional[str]:
        if not (self.name and self.version):
            return None
        return "%s-%s" % (re.sub(r"[-_.]+", "_", self.name).lower(), self.version.lower())

    def _setup_cfg_only_adds_egg_info(self, path: str) -> bool:
        pub = self._read(self.published_root, path)
        src = self._read(self.source_root, self.source_path_for.get(path, path))
        if pub is None or src is None:
            return False
        stripped = re.sub(r"\n\[egg_info\][^\[]*", "\n", pub)
        norm = lambda s: [ln.strip() for ln in s.splitlines() if ln.strip()]  # noqa: E731
        return "[egg_info]" in pub and norm(stripped) == norm(src)

    def _cython_source_for(self, path: str) -> Optional[str]:
        stem = _stem(path)
        for ext in (".pyx", ".pxd", ".py"):
            for candidate in (stem + ext, self.source_path_for.get(path, "") and _stem(self.source_path_for[path]) + ext):
                if candidate and candidate in self.source:
                    return candidate
        return None

    def _source_map_evidence(self, path: str) -> Optional[str]:
        text = self._read(self.published_root, path)
        if not text:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        sources = [s for s in (data.get("sources") or []) if isinstance(s, str)]
        resolved = 0
        for s in sources[:200]:
            clean = re.sub(r"^(webpack:///|webpack://[^/]*/|file://|ng://|\./)", "", s).replace("\\", "/")
            clean = "/".join(p for p in clean.split("/") if p not in ("", ".", ".."))
            if clean and clean in self.source:
                resolved += 1
                continue
            if clean and any(sp == clean or sp.endswith("/" + clean) for sp in self.source):
                resolved += 1
        if sources and resolved:
            return f"source map references {resolved} of {min(len(sources), 200)} repository source file(s)"
        return None
