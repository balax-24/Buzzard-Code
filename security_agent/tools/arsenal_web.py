"""Web enumeration strategies: dir brute, API discovery, endpoint fuzz, tech detect."""
from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Tuple

from security_agent.tools.fallback import FallbackRunner, is_failed_result, strategy_from_cmd
from security_agent.tools.arsenal_http import (
    API_PATHS, DIR_WORDS, best_wordlist, format_url, http_get, http_request,
    threaded_http_probe, HTTP_BANNER_LINES,
)

INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _url(kw: Dict[str, Any]) -> str:
    return format_url(kw.get("url", ""))


# ---------------------------------------------------------------------------
# directory brute force
# ---------------------------------------------------------------------------
def _dir_ffuf(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ffuf"):
        return False, "ffuf not installed", ""
    url = _url(kw)
    wl = kw.get("wordlist") or best_wordlist("dir")
    fu = kw.get("fu", "FUZZ")
    if fu not in url:
        url = url.rstrip("/") + "/" + fu
    cmd = (f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wl)}:{shlex.quote(fu)} "
           f"-mc 200,201,204,301,302,307,308,401,403,405,500 -t 20 -s -timeout 6 2>&1 | tail -60")
    res = runner.run_cmd(cmd, timeout=180)
    if is_failed_result(res):
        return False, "ffuf failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    hits = [l for l in out.splitlines() if l.strip() and ":" in l or l.strip().startswith("/")]
    if hits:
        return True, f"{len(hits)} paths found", "\n".join(hits[:60])
    if out:
        return True, "fuzz completed (no hits)", out
    return False, "ffuf produced no output", ""


def _dir_gobuster(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("gobuster"):
        return False, "gobuster not installed", ""
    url = _url(kw)
    wl = kw.get("wordlist") or best_wordlist("dir")
    res = runner.run_cmd(f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wl)} -t 20 -q "
                         f"--timeout 8s --no-error 2>&1 | tail -60", timeout=180)
    if is_failed_result(res):
        return False, "gobuster failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    if out:
        return True, "gobuster finished", out
    return False, "gobuster produced no output", ""


def _dir_dirb(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("dirb"):
        return False, "dirb not installed", ""
    url = _url(kw)
    wl = kw.get("wordlist") or best_wordlist("dir")
    res = runner.run_cmd(f"dirb {shlex.quote(url)} {shlex.quote(wl)} -r -S 2>&1 | grep -E '^\\+\\s' | head -60",
                         timeout=180)
    if is_failed_result(res):
        return False, "dirb failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    if out:
        return True, "dirb finished", out
    return False, "dirb produced no hits", ""


def _dir_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import os
    url = _url(kw)
    if not url:
        return False, "no url", ""
    words = []
    wl = kw.get("wordlist") or ""
    if wl and os.path.exists(wl):
        try:
            with open(wl) as f:
                words = [l.strip() for l in f if l.strip()][:1500]
        except Exception:
            words = []
    if not words:
        words = DIR_WORDS
    paths = [f"{url.rstrip('/')}/{w.lstrip('/')}" for w in words[:800]]
    results = threaded_http_probe(paths, timeout=5.0, max_workers=25)
    hits = [r for r in results if r["status"] in INTERESTING_STATUS]
    if hits:
        lines = [f"{r['status']}  {r['len']:>6}  {r['url'].replace(url, '')}" for r in hits[:60]]
        return True, f"{len(hits)} paths found", "\n".join(lines)
    return True, "0 paths found", "Python wordlist probe found no interesting paths."


# ---------------------------------------------------------------------------
# API discovery
# ---------------------------------------------------------------------------
def _api_ffuf(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ffuf"):
        return False, "ffuf not installed", ""
    url = _url(kw)
    wl = kw.get("wordlist") or best_wordlist("api")
    target = url.rstrip("/") + "/FUZZ"
    cmd = (f"ffuf -u {shlex.quote(target)} -w {shlex.quote(wl)}:FUZZ "
           f"-mc 200,201,204,301,302,307,308,401,403,405 -t 20 -s -timeout 6 2>&1 | tail -60")
    res = runner.run_cmd(cmd, timeout=180)
    if is_failed_result(res):
        return False, "ffuf failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    hits = [l for l in out.splitlines() if l.strip()]
    if hits:
        return True, f"{len(hits)} API endpoints", "\n".join(hits[:60])
    return False, "no API endpoints from ffuf", out


def _api_nuclei(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nuclei"):
        return False, "nuclei not installed", ""
    url = _url(kw)
    res = runner.run_cmd(
        f"nuclei -u {shlex.quote(url)} -tags exposure,api,swagger,graphql -silent "
        f"-timeout 8 -retries 1 2>&1 | tail -40", timeout=200)
    if is_failed_result(res):
        return False, "nuclei failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    if out:
        return True, "nuclei found exposures", out
    return False, "nuclei found nothing", ""


def _api_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = _url(kw)
    if not url:
        return False, "no url", ""
    base = url.rstrip("/")
    paths = [f"{base}/{p.lstrip('/')}" for p in API_PATHS[:400]]
    results = threaded_http_probe(paths, timeout=4.0, max_workers=25)
    hits = [r for r in results if r["status"] in (200, 201, 204, 401, 403, 405, 500)]
    if hits:
        lines = [f"{r['status']}  {r['len']:>6}  {r['url'].replace(base, '')}" for r in hits[:60]]
        return True, f"{len(hits)} API endpoints", "\n".join(lines)
    return True, "0 API endpoints found", "Probed common API paths; no active endpoints responded."


def _api_methods(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Probe HTTP methods on the base URL to map API surface."""
    url = _url(kw)
    if not url:
        return False, "no url", ""
    lines = []
    for m in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"):
        r = http_request(m, url, timeout=4.0)
        allow = r["headers"].get("allow", "")
        lines.append(f"  {m:7s} -> {r['status']}" + (f"  Allow: {allow}" if allow else ""))
    return True, "method map", "\n".join(lines)


# ---------------------------------------------------------------------------
# endpoint fuzzing (GET/POST params)
# ---------------------------------------------------------------------------
def _fuzz_ffuf(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ffuf"):
        return False, "ffuf not installed", ""
    url = _url(kw)
    wl = kw.get("wordlist") or best_wordlist("dir")
    fu = kw.get("fu", "FUZZ")
    method = kw.get("method", "GET").upper()
    data = kw.get("data", "")
    if fu not in url and fu not in data:
        url = url.rstrip("/") + "/" + fu
    cmd = f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wl)}:{shlex.quote(fu)} -mc 200,201,204,301,302,307,308,401,403,405,500 -t 20 -s -timeout 8"
    if method == "POST":
        cmd += f" -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d {shlex.quote(data or fu + '=FUZZ')}"
    res = runner.run_cmd(cmd + " 2>&1 | tail -60", timeout=180)
    if is_failed_result(res):
        return False, "ffuf failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "").strip()
    hits = [l for l in out.splitlines() if l.strip()]
    if hits:
        return True, f"{len(hits)} fuzz hits", "\n".join(hits[:60])
    return False, "no fuzz hits", out


def _fuzz_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import os
    url = _url(kw)
    if not url:
        return False, "no url", ""
    fu = kw.get("fu", "FUZZ")
    method = kw.get("method", "GET").upper()
    data = kw.get("data", "")
    words = []
    wl = kw.get("wordlist") or ""
    if wl and os.path.exists(wl):
        with open(wl) as f:
            words = [l.strip() for l in f if l.strip()][:600]
    if not words:
        words = DIR_WORDS[:300]
    if fu in url:
        targets = [url.replace(fu, w) for w in words]
        results = threaded_http_probe(targets, timeout=4.0, max_workers=25)
    else:
        base = url.rstrip("/") + "/"
        targets = [base + w for w in words]
        results = threaded_http_probe(targets, timeout=4.0, max_workers=25)
    hits = [r for r in results if r["status"] in INTERESTING_STATUS]
    if hits:
        lines = [f"{r['status']}  {r['len']:>6}  {r['url']}" for r in hits[:60]]
        return True, f"{len(hits)} hits", "\n".join(lines)
    return True, "0 fuzz hits", "Fuzzing complete; no responsive endpoints found."


# ---------------------------------------------------------------------------
# web technology detection
# ---------------------------------------------------------------------------
def _tech_whatweb(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("whatweb"):
        return False, "whatweb not installed", ""
    url = _url(kw)
    res = runner.run_cmd(f"whatweb -a 3 {shlex.quote(url)} 2>/dev/null | head -20", timeout=90)
    out = res.get("stdout", "").strip()
    if out and "ERROR" not in out.upper():
        return True, "tech stack fingerprinted", out
    return False, "whatweb failed", out


def _tech_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = _url(kw)
    if not url:
        return False, "no url", ""
    r = http_get(url, timeout=6.0)
    if r["status"] == 0:
        return False, "connection failed", r["error"]
    hdrs = r["headers"]
    sigs = []
    for h in HTTP_BANNER_LINES:
        v = hdrs.get(h)
        if v:
            sigs.append(f"{h}: {v[:120]}")
    body_low = r["body"][:5000].lower()
    tech = []
    for name, patterns in {
        "PHP": ["php", "php/"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal"],
        "Joomla": ["joomla"],
        "Laravel": ["laravel", "csrf-token"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Flask": ["flask", "werkzeug"],
        "Express/Node": ["express", "powered by express", "node.js"],
        "React": ["_next", "react"],
        "Vue": ["vue.js", "vuejs", "__vue__"],
        "Angular": ["ng-version", "angular"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "nginx": ["nginx"],
        "Apache": ["apache"],
        "ASP.NET": ["asp.net", "viewstate", "x-aspnet"],
        "Tomcat": ["tomcat", "jsessionid"],
        "JBoss": ["jboss"],
        "GraphQL": ["graphql"],
        "Swagger": ["swagger", "openapi"],
        "Docker": ["docker"],
        "Kubernetes": ["kubernetes", "k8s"],
        "Grafana": ["grafana"],
        "Jenkins": ["jenkins"],
        "GitLab": ["gitlab"],
    }.items():
        if any(p in body_low or p in str(hdrs).lower() for p in patterns):
            tech.append(name)
    out = sigs + ([f"Detected: {', '.join(tech)}"] if tech else ["Detected: (none by signature)"])
    return True, f"status {r['status']}, {len(r['body'])} bytes", "\n".join(out)


def web_tech_chain() -> List[Tuple[str, Any]]:
    return [("whatweb", _tech_whatweb), ("python-fingerprint", _tech_py)]


def dir_bruteforce_chain() -> List[Tuple[str, Any]]:
    return [("ffuf", _dir_ffuf), ("gobuster", _dir_gobuster), ("dirb", _dir_dirb), ("python-probe", _dir_py)]


def api_discovery_chain() -> List[Tuple[str, Any]]:
    return [("ffuf-api", _api_ffuf), ("nuclei-exposure", _api_nuclei), ("python-api", _api_py)]


def endpoint_fuzz_chain() -> List[Tuple[str, Any]]:
    return [("ffuf", _fuzz_ffuf), ("python-fuzz", _fuzz_py)]


def http_method_map_chain() -> List[Tuple[str, Any]]:
    return [("python-methods", _api_methods)]
