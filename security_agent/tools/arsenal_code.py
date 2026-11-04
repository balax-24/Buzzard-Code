"""
Source-code analysis capabilities: dangerous-pattern audit and secret
scanning. Uses semgrep/gitleaks when installed, with a Python fallback
so the agent can still audit any checked-out codebase.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from security_agent.tools.fallback import FallbackRunner, strategy_from_cmd


DANGEROUS_PATTERNS: List[Tuple[str, str, str]] = [
    ("sql-string-format", r"""execute\(\s*["'][^"']*%["']""", "SQL query built with % formatting"),
    ("sql-concat",        r"""execute\(\s*["'][^"']*\+["']""", "SQL query built with + concatenation"),
    ("sql-fstring",       r"""execute\(\s*f["']""", "SQL query built with f-string"),
    ("eval",              r"""\beval\s*\(""", "eval() of dynamic input"),
    ("exec",              r"""\bexec\s*\(""", "exec() of dynamic input"),
    ("os-system",         r"""os\.system\s*\(""", "os.system() shell execution"),
    ("popen",             r"""(subprocess\.Popen|os\.popen)\s*\(""", "shell pipe execution"),
    ("shell-true",        r"""subprocess\.(run|call|check_output)\([^)]*shell\s*=\s*True""", "subprocess with shell=True"),
    ("pickle-loads",      r"""pickle\.loads\s*\(""", "unsafe deserialization"),
    ("yaml-load",         r"""yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader|yaml\.load\s*\([^)]*""" , "unsafe YAML load"),
    ("render-template",   r"""render_template_string\s*\(""", "template injection surface"),
    ("hardcoded-secret",  r"""(secret_key|SECRET_KEY|api[_-]?key|password)\s*[=:]\s*["'][^"']{6,}["']""", "possible hardcoded credential"),
    ("command-format",    r"""(os\.system|subprocess\.\w+)\s*\(f["']|(os\.system|subprocess\.\w+)\s*\([^)]*%""", "shell command built from variables"),
    ("md5-sha1-hash",     r"""hashlib\.(md5|sha1)\s*\(""", "weak hash for passwords"),
    ("unsafe-redirect",   r"""redirect\s*\([^)]*request\.(args|form|values)""", "open redirect"),
]


def _code_audit_semgrep(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("path") or kw.get("dir") or "."
    if not os.path.isdir(path):
        return False, f"path not found: {path}", ""
    cmd = f"semgrep --config=auto --json -q {path} 2>/dev/null | head -c 8000"
    res = runner.run_cmd(cmd, timeout=180)
    out = (res.get("stdout") or "").strip()
    if res.get("exit_code") not in (0, 1) or not out:
        return False, "semgrep produced no usable output", out
    try:
        import json
        data = json.loads(out)
        results = data.get("results", [])
        if not results:
            return True, "semgrep: no findings", "semgrep scan clean"
        lines = [f"semgrep: {len(results)} finding(s):"]
        for r in results[:40]:
            path_f = r.get("path", "?")
            start = r.get("start", {}).get("line", "?")
            lines.append(f"  {path_f}:{start}  {r.get('check_id', '')}  {r.get('extra', {}).get('message', '')[:120]}")
        return True, f"semgrep: {len(results)} findings", "\n".join(lines)
    except Exception as e:
        return False, f"semgrep output unparseable: {e}", out[:1000]


def _code_audit_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("path") or kw.get("dir") or "."
    if not os.path.exists(path):
        return False, f"path not found: {path}", ""
    exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java", ".c", ".cpp", ".cs", ".sh"}
    skip = {".git", ".venv", "node_modules", "__pycache__", "dist", "build", ".tox", ".pytest_cache"}
    findings: List[str] = []
    scanned = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in files:
            if os.path.splitext(fn)[1] not in exts:
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, "r", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        for name, pat, desc in DANGEROUS_PATTERNS:
                            if re.search(pat, line, re.IGNORECASE):
                                findings.append(f"{fp}:{lineno}  [{name}] {desc}")
                                break
                scanned += 1
            except Exception:
                continue
    if not findings:
        return True, f"no dangerous patterns in {scanned} files", f"Scanned {scanned} source files under {path}"
    lines = [f"Found {len(findings)} dangerous pattern(s) across {scanned} files:"]
    lines += findings[:60]
    if len(findings) > 60:
        lines.append(f"... and {len(findings) - 60} more (see full list)")
    return True, f"{len(findings)} dangerous patterns", "\n".join(lines)


def code_audit_chain() -> List[Tuple[str, Any]]:
    return [("semgrep", _code_audit_semgrep), ("python-patterns", _code_audit_py)]


# ---------------------------------------------------------------------------
# secret_scan
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret-key", r"(?i)aws_secret_access_key\s*=\s*[\"'][A-Za-z0-9/+=]{40}[\"']"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("google-api-key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("stripe-key", r"sk_live_[0-9a-zA-Z]{20,}"),
    ("private-key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("jwt-token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("generic-api-key", r"(?i)(api[_-]?key|apikey|secret|token)\s*[=:]\s*[\"'][A-Za-z0-9_\-\.]{16,}[\"']"),
    ("basic-auth-url", r"https?://[^\s:/@]+:[^\s@/]+@[^\s]+"),
]


def _secret_scan_gitleaks(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("path") or kw.get("dir") or "."
    if not os.path.exists(path):
        return False, f"path not found: {path}", ""
    cmd = f"gitleaks detect --source {path} --no-banner --no-color 2>&1 | tail -40"
    res = runner.run_cmd(cmd, timeout=180)
    out = (res.get("stdout") or "").strip()
    if res.get("exit_code") == 0:
        return True, "gitleaks: no secrets found", "gitleaks scan clean"
    if "finding" in out.lower() or "leak" in out.lower():
        return True, "gitleaks found potential secrets", out
    return False, "gitleaks unavailable or no output", out


def _secret_scan_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("path") or kw.get("dir") or "."
    if not os.path.exists(path):
        return False, f"path not found: {path}", ""
    if os.path.isfile(path):
        files = [path]
    else:
        skip = {".git", ".venv", "node_modules", "__pycache__", "dist", "build", ".tox", ".pytest_cache"}
        files = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skip]
            for n in names:
                files.append(os.path.join(root, n))
    hits: List[str] = []
    for fp in files[:2000]:
        try:
            with open(fp, "r", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    for name, pat in SECRET_PATTERNS:
                        if re.search(pat, line):
                            snippet = line.strip()[:100]
                            hits.append(f"{fp}:{lineno}  [{name}]  {snippet}")
                            break
        except Exception:
            continue
    if not hits:
        return True, f"no secrets in {len(files)} files", f"Scanned {len(files)} files under {path}"
    lines = [f"{len(hits)} potential secret(s) found across {len(files)} files:"]
    lines += hits[:50]
    return True, f"{len(hits)} potential secrets", "\n".join(lines)


def secret_scan_chain() -> List[Tuple[str, Any]]:
    return [("gitleaks", _secret_scan_gitleaks), ("python-regex", _secret_scan_py)]
