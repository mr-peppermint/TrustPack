"""Text-level indicators of obfuscated or hostile code.

These are heuristics over file text — they flag *signals* a reviewer should look at, never proof of
intent (plenty of legitimate bundles use eval or base64). They are used (a) to stop a file from being
auto-trusted as "generated build output" and (b) to raise findings on files that changed or were added.
Nothing here executes, imports or evaluates the scanned content.
"""
import re
from pathlib import PurePosixPath
from typing import List

_JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
_PY_EXTS = {".py", ".pyw", ".pth"}
_SHELL_EXTS = {".sh", ".bash", ".bat", ".cmd", ".ps1"}

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")
_HEX_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_FROM_CHAR_CODE = re.compile(r"String\.fromCharCode")

_JS_EVAL_DECODED = re.compile(r"\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode)")
_JS_EVAL_B64 = re.compile(r"\beval\s*\([^)]{0,200}base64", re.IGNORECASE)
_JS_SHELL_DOWNLOAD = re.compile(r"(?:child_process|execSync|spawnSync|\bexec\s*\()[^;]{0,200}(?:curl|wget|powershell|bash -c|sh -c|/dev/tcp)", re.IGNORECASE | re.DOTALL)

_PY_EXEC_DECODED = re.compile(r"\b(?:exec|eval)\s*\(\s*(?:base64\.|zlib\.|marshal\.|codecs\.|bytes\.fromhex|compile\s*\()")
_PY_MARSHAL = re.compile(r"\bmarshal\.loads\s*\(")
_PY_SHELL_DOWNLOAD = re.compile(r"(?:os\.system|subprocess\.\w+)\s*\([^)]{0,200}(?:curl|wget|powershell|bash -c|sh -c|/dev/tcp)", re.IGNORECASE | re.DOTALL)
_PY_REVERSE_SHELL = re.compile(r"pty\.spawn|socket\.socket\([^)]*\)[\s\S]{0,300}(?:/bin/sh|/bin/bash|subprocess)", re.IGNORECASE)
_PY_B64_IMPORT_EXEC = re.compile(r"__import__\(\s*['\"](?:base64|zlib|marshal)['\"]\s*\)")

_SHELL_PIPE_TO_SHELL = re.compile(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.IGNORECASE)


def find_suspicious_content(path: str, text: str) -> List[str]:
    """Return human-readable reasons the text looks obfuscated or hostile (empty list if none)."""
    ext = PurePosixPath(path.lower()).suffix
    reasons: List[str] = []

    if ext in _JS_EXTS:
        if _JS_EVAL_DECODED.search(text) or _JS_EVAL_B64.search(text):
            reasons.append("evaluates dynamically decoded data (eval/Function over atob/base64/fromCharCode)")
        if _JS_SHELL_DOWNLOAD.search(text):
            reasons.append("spawns a shell command that downloads or pipes remote content")
        if len(_FROM_CHAR_CODE.findall(text)) > 8:
            reasons.append("builds code from many String.fromCharCode calls")
    elif ext in _PY_EXTS:
        if _PY_EXEC_DECODED.search(text) or _PY_B64_IMPORT_EXEC.search(text):
            reasons.append("executes dynamically decoded data (exec/eval over base64/zlib/marshal)")
        if _PY_MARSHAL.search(text):
            reasons.append("loads marshalled bytecode")
        if _PY_SHELL_DOWNLOAD.search(text):
            reasons.append("runs a shell command that downloads or pipes remote content")
        if _PY_REVERSE_SHELL.search(text):
            reasons.append("contains reverse-shell style socket/shell code")
    elif ext in _SHELL_EXTS:
        if _SHELL_PIPE_TO_SHELL.search(text):
            reasons.append("pipes downloaded content into a shell")
    else:
        return reasons

    if ext in _JS_EXTS | _PY_EXTS:
        if _B64_BLOB.search(text):
            reasons.append("contains a very long base64-like string literal (>=300 characters)")
        if len(_HEX_ESCAPES.findall(text)) > 60:
            reasons.append("contains dense hex/unicode escape sequences typical of obfuscation")
    return reasons


def pth_executes_code(text: str) -> bool:
    """`.pth` files are normally plain path lists; a line starting with `import` is executed by site.py
    at every interpreter start."""
    return any(line.lstrip().startswith(("import ", "import\t")) for line in text.splitlines())
