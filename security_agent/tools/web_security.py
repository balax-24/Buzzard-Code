"""
Web Security Suite for Buzzard Code.

Provides bounded, safe, non-destructive web application security assessment tools:
- check_headers
- ssl_check
- http_request
- http_methods
- redirect_check
- robots_check
- security_txt_check
- tech_fingerprint
- cookie_audit
- cors_check
- directory_probe
- web_endpoint_probe
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional
import requests

from security_agent.tools.registry import ToolCategory, ToolRegistry

MAX_RESPONSE_BYTES = 256 * 1024  # 256 KB max response payload
DEFAULT_USER_AGENT = "BuzzardCode/1.0 (+https://github.com/buzzard-code/security-agent)"


def _normalize_url(url: str) -> str:
    cleaned = str(url or "").strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def check_headers(url: str) -> str:
    """
    Audits HTTP response headers for security protections and disclosure risks.
    Arguments:
        url: Target web URL or domain.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    try:
        resp = requests.get(target_url, timeout=10, allow_redirects=True, headers={"User-Agent": DEFAULT_USER_AGENT})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        security_headers = {
            "strict-transport-security": "HSTS (Enforces HTTPS, protects against SSL stripping)",
            "content-security-policy": "CSP (Mitigates XSS, data injection, and clickjacking)",
            "x-frame-options": "Clickjacking defense (DENY or SAMEORIGIN)",
            "x-content-type-options": "MIME-sniffing protection (nosniff)",
            "referrer-policy": "Referrer leak protection",
            "permissions-policy": "Browser feature access restrictions",
            "cross-origin-opener-policy": "COOP (Cross-Origin isolation)",
            "cross-origin-embedder-policy": "COEP (Cross-Origin isolation)",
        }

        present = {}
        missing = {}
        for h, desc in security_headers.items():
            if h in headers:
                present[h] = {"value": headers[h], "description": desc}
            else:
                missing[h] = desc

        disclosures = {}
        for disc_hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if disc_hdr in headers:
                disclosures[disc_hdr] = headers[disc_hdr]

        score = int((len(present) / len(security_headers)) * 100)

        return json.dumps({
            "status": "success",
            "url": target_url,
            "status_code": resp.status_code,
            "security_score_pct": score,
            "present_headers": present,
            "missing_headers": missing,
            "information_disclosures": disclosures,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "url": target_url, "error": f"Header check failed: {e}"}, indent=2)


def ssl_check(host: str, port: int = 443) -> str:
    """
    Audits SSL/TLS certificate validity, issuer, cipher suite, and expiry dates.
    Arguments:
        host: Target hostname or domain.
        port: SSL port (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    clean_host = str(host).strip().split("://")[-1].split("/")[0].split(":")[0]
    port_num = int(port or 443)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                sans = [v for k, v in cert.get("subjectAltName", ())]

                return json.dumps({
                    "status": "success",
                    "host": clean_host,
                    "port": port_num,
                    "tls_version": version,
                    "cipher": {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    },
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "subject_alt_names": sans[:15]
                }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "host": clean_host, "port": port_num, "error": f"SSL check error: {e}"}, indent=2)


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = 10,
    max_redirects: int = 3
) -> str:
    """
    Executes a bounded, safe HTTP request with strict size and redirect limits.
    Arguments:
        url: Target web URL (HTTP/HTTPS only).
        method: HTTP method (GET, POST, HEAD, OPTIONS, PUT, DELETE, PATCH).
        headers: Optional dictionary of HTTP request headers.
        body: Optional request body string.
        timeout: Request timeout in seconds (default 10, max 30).
        max_redirects: Maximum redirect hops (default 3, max 5).
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"status": "error", "error": "Only HTTP and HTTPS schemes are permitted."})

    clean_method = str(method or "GET").strip().upper()
    valid_methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}
    if clean_method not in valid_methods:
        return json.dumps({"status": "error", "error": f"Method '{clean_method}' not permitted. Supported: {valid_methods}"})

    req_timeout = max(1, min(int(timeout or 10), 30))
    redirect_limit = max(0, min(int(max_redirects or 3), 5))

    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers and isinstance(headers, dict):
        req_headers.update(headers)

    session = requests.Session()
    session.max_redirects = redirect_limit

    start_time = time.time()
    try:
        resp = session.request(
            method=clean_method,
            url=target_url,
            headers=req_headers,
            data=body.encode("utf-8") if body else None,
            timeout=req_timeout,
            allow_redirects=(redirect_limit > 0),
            stream=True
        )

        content_bytes = b""
        for chunk in resp.iter_content(chunk_size=4096):
            content_bytes += chunk
            if len(content_bytes) >= MAX_RESPONSE_BYTES:
                break

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        encoding = resp.encoding or "utf-8"
        body_text = content_bytes.decode(encoding, errors="replace")

        return json.dumps({
            "status": "success",
            "url": resp.url,
            "method": clean_method,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "response_bytes": len(content_bytes),
            "truncated": len(content_bytes) >= MAX_RESPONSE_BYTES,
            "elapsed_ms": elapsed_ms,
            "body_snippet": body_text[:2000]
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "url": target_url, "error": f"HTTP request failed: {e}"}, indent=2)


def http_methods(url: str) -> str:
    """
    Tests supported HTTP verbs (OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PATCH) on an endpoint.
    Arguments:
        url: Target web URL.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    verbs = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "PATCH"]
    allowed_methods = []
    statuses = {}

    for v in verbs:
        try:
            r = requests.request(v, target_url, timeout=3, allow_redirects=False, headers={"User-Agent": DEFAULT_USER_AGENT})
            statuses[v] = r.status_code
            if r.status_code not in (405, 501, 403):
                allowed_methods.append(v)
            if v == "OPTIONS" and "allow" in r.headers:
                explicit_allow = [m.strip() for m in r.headers["allow"].split(",")]
                for m in explicit_allow:
                    if m not in allowed_methods:
                        allowed_methods.append(m)
        except Exception:
            statuses[v] = "timeout/error"

    return json.dumps({
        "status": "success",
        "url": target_url,
        "allowed_methods": allowed_methods,
        "method_status_codes": statuses,
        "trace_vulnerable": statuses.get("TRACE") == 200
    }, indent=2)


def redirect_check(url: str, max_hops: int = 5) -> str:
    """
    Inspects HTTP redirect chain for protocol downgrade, loops, or open redirects.
    Arguments:
        url: Starting web URL.
        max_hops: Maximum redirect hops to trace (default 5, max 10).
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    current_url = _normalize_url(url)
    max_hops = max(1, min(int(max_hops or 5), 10))
    chain = []

    for _ in range(max_hops):
        try:
            r = requests.get(current_url, timeout=5, allow_redirects=False, headers={"User-Agent": DEFAULT_USER_AGENT})
            chain.append({
                "url": current_url,
                "status_code": r.status_code,
                "location": r.headers.get("location")
            })
            if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location")
                if not loc:
                    break
                current_url = urllib.parse.urljoin(current_url, loc)
            else:
                break
        except Exception as e:
            chain.append({"url": current_url, "error": str(e)})
            break

    https_downgrade = False
    for i in range(len(chain) - 1):
        if chain[i]["url"].startswith("https://") and chain[i + 1]["url"].startswith("http://"):
            https_downgrade = True

    return json.dumps({
        "status": "success",
        "start_url": url,
        "final_url": current_url,
        "total_hops": len(chain) - 1,
        "chain": chain,
        "https_downgrade_detected": https_downgrade
    }, indent=2)


def robots_check(url: str) -> str:
    """
    Fetches and parses the /robots.txt file of a target domain.
    Arguments:
        url: Target web URL or domain.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    base = _normalize_url(url)
    parsed = urllib.parse.urlparse(base)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    try:
        r = requests.get(robots_url, timeout=5, headers={"User-Agent": DEFAULT_USER_AGENT})
        if r.status_code != 200:
            return json.dumps({
                "status": "success",
                "robots_url": robots_url,
                "exists": False,
                "status_code": r.status_code
            }, indent=2)

        disallows = []
        allows = []
        sitemaps = []
        for line in r.text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if key == "disallow":
                    disallows.append(val)
                elif key == "allow":
                    allows.append(val)
                elif key == "sitemap":
                    sitemaps.append(val)

        return json.dumps({
            "status": "success",
            "robots_url": robots_url,
            "exists": True,
            "disallowed_paths_count": len(disallows),
            "disallowed_paths": disallows[:20],
            "sitemaps": sitemaps
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "robots_url": robots_url, "error": str(e)}, indent=2)


def security_txt_check(url: str) -> str:
    """
    Checks for RFC 9116 security.txt disclosure file at /.well-known/security.txt and /security.txt.
    Arguments:
        url: Target web URL or domain.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    base = _normalize_url(url)
    parsed = urllib.parse.urlparse(base)

    paths_to_test = [
        f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt",
        f"{parsed.scheme}://{parsed.netloc}/security.txt"
    ]

    for test_url in paths_to_test:
        try:
            r = requests.get(test_url, timeout=5, headers={"User-Agent": DEFAULT_USER_AGENT})
            if r.status_code == 200 and ("contact:" in r.text.lower() or "expires:" in r.text.lower()):
                fields = {}
                for line in r.text.split("\n"):
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        k, v = line.split(":", 1)
                        fields[k.strip()] = v.strip()

                return json.dumps({
                    "status": "success",
                    "exists": True,
                    "url": test_url,
                    "fields": fields
                }, indent=2)
        except Exception:
            continue

    return json.dumps({
        "status": "success",
        "exists": False,
        "notice": f"No RFC 9116 security.txt found on {parsed.netloc}"
    }, indent=2)


def tech_fingerprint(url: str) -> str:
    """
    Fingerprints web server, frameworks, CMS, and JavaScript frontend libraries.
    Arguments:
        url: Target web URL.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    try:
        r = requests.get(target_url, timeout=8, headers={"User-Agent": DEFAULT_USER_AGENT})
        technologies = []
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text.lower()

        # Server headers
        if "server" in headers:
            technologies.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            technologies.append(f"Runtime: {headers['x-powered-by']}")

        # CMS & Framework signatures
        indicators = {
            "WordPress": ["wp-content", "wp-includes", "xmlrpc.php"],
            "Drupal": ["drupal.js", "/sites/default/files"],
            "Joomla": ["joomla! - open source content management", "/components/com_"],
            "Next.js": ["__next", "/_next/static/"],
            "React": ["react.production.min.js", "data-reactroot"],
            "Vue.js": ["vue.js", "vue.min.js", "data-v-"],
            "Angular": ["ng-version", "ng-app"],
            "Django": ["csrfmiddlewaretoken"],
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "Tailwind CSS": ["tailwind", "tw-"],
        }

        for tech, sigs in indicators.items():
            if any(sig.lower() in body for sig in sigs):
                technologies.append(tech)

        return json.dumps({
            "status": "success",
            "url": target_url,
            "status_code": r.status_code,
            "detected_technologies": list(dict.fromkeys(technologies)),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "url": target_url, "error": str(e)}, indent=2)


def cookie_audit(url: str) -> str:
    """
    Audits HTTP response cookies for Secure, HttpOnly, and SameSite attributes.
    Arguments:
        url: Target web URL.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    try:
        r = requests.get(target_url, timeout=5, headers={"User-Agent": DEFAULT_USER_AGENT})
        findings = []

        for cookie in r.cookies:
            is_secure = cookie.secure
            is_httponly = cookie.has_nonstandard_attr("httponly") or "httponly" in cookie._rest.keys()
            samesite = cookie._rest.get("samesite", "None")

            issues = []
            if not is_secure and target_url.startswith("https://"):
                issues.append("Missing Secure flag")
            if not is_httponly:
                issues.append("Missing HttpOnly flag (vulnerable to XSS theft)")
            if samesite.lower() not in ("lax", "strict"):
                issues.append(f"Weak/Missing SameSite policy ('{samesite}')")

            findings.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": is_secure,
                "httponly": is_httponly,
                "samesite": samesite,
                "issues": issues
            })

        return json.dumps({
            "status": "success",
            "url": target_url,
            "total_cookies": len(findings),
            "cookies": findings
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "url": target_url, "error": str(e)}, indent=2)


def cors_check(url: str, origin: str = "https://evil.com") -> str:
    """
    Tests Cross-Origin Resource Sharing (CORS) configuration for overly permissive access.
    Arguments:
        url: Target web URL or API endpoint.
        origin: Test origin to probe (default 'https://evil.com').
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target_url = _normalize_url(url)
    test_origin = str(origin or "https://evil.com").strip()

    try:
        headers = {"Origin": test_origin, "User-Agent": DEFAULT_USER_AGENT}
        r = requests.options(target_url, headers=headers, timeout=5)
        if r.status_code in (405, 501):
            r = requests.get(target_url, headers=headers, timeout=5)

        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        acam = r.headers.get("Access-Control-Allow-Methods")

        is_wildcard = acao == "*"
        is_origin_reflected = acao == test_origin
        credentials_allowed = str(acac).lower() == "true"

        severity = "SAFE"
        findings = []
        if is_origin_reflected and credentials_allowed:
            severity = "CRITICAL"
            findings.append("Arbitrary origin reflection with credentials enabled (allows CSRF/data theft)")
        elif is_wildcard and credentials_allowed:
            severity = "HIGH"
            findings.append("Wildcard origin with credentials (invalid configuration in modern browsers)")
        elif is_wildcard:
            severity = "LOW"
            findings.append("Public resource (Wildcard Access-Control-Allow-Origin: *)")

        return json.dumps({
            "status": "success",
            "url": target_url,
            "test_origin": test_origin,
            "allow_origin": acao,
            "allow_credentials": acac,
            "allow_methods": acam,
            "severity": severity,
            "findings": findings
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "url": target_url, "error": str(e)}, indent=2)


def directory_probe(base_url: str, paths: Optional[List[str]] = None) -> str:
    """
    Probes a bounded set of common sensitive administrative and backup paths (max 20 paths).
    Arguments:
        base_url: Base web URL.
        paths: Optional custom list of paths (default uses standard sensitive paths).
    """
    if not base_url or not str(base_url).strip():
        return json.dumps({"status": "error", "error": "Base URL parameter is required."})

    target = _normalize_url(base_url).rstrip("/")
    default_paths = [
        "admin", "administrator", "login", ".env", ".git/HEAD",
        "backup.zip", "backup.sql", "config.json", "phpinfo.php",
        "wp-login.php", "api", "health", "metrics", "server-status",
        "console", "actuator/health", "debug", "test"
    ]
    probe_paths = [str(p).lstrip("/") for p in (paths or default_paths)][:20]

    found = []
    for p in probe_paths:
        test_url = f"{target}/{p}"
        try:
            r = requests.head(test_url, timeout=2, headers={"User-Agent": DEFAULT_USER_AGENT}, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                found.append({
                    "path": f"/{p}",
                    "status_code": r.status_code,
                    "location": r.headers.get("location")
                })
        except Exception:
            continue

    return json.dumps({
        "status": "success",
        "base_url": target,
        "probed_count": len(probe_paths),
        "discovered_endpoints": found
    }, indent=2)


def web_endpoint_probe(base_url: str, endpoints: Optional[List[str]] = None) -> str:
    """
    Audits common API and documentation endpoints on a web host.
    Arguments:
        base_url: Target base URL.
        endpoints: Optional custom list of endpoints to verify.
    """
    default_endpoints = [
        "api", "api/v1", "api/v2", "swagger.json", "swagger-ui.html",
        "openapi.json", "graphql", "health", "healthz", "metrics", "status"
    ]
    return directory_probe(base_url, paths=endpoints or default_endpoints)


def register_web_security_tools(registry: ToolRegistry):
    """
    Registers the Web Security Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="check_headers",
        description="Audits HTTP response headers for missing security protections (HSTS, CSP, X-Frame-Options). Arguments: url (str).",
        func=check_headers,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="ssl_check",
        description="Audits SSL/TLS certificate, ciphers, issuer, and validity dates. Arguments: host (str), port (int, default 443).",
        func=ssl_check,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="http_request",
        description="Executes a bounded, safe HTTP request (GET, POST, OPTIONS, etc.). Arguments: url (str), method (str), headers (dict), body (str).",
        func=http_request,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="MEDIUM",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=30
    )
    registry.register(
        name="http_methods",
        description="Tests supported HTTP verbs (OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE) on an endpoint. Arguments: url (str).",
        func=http_methods,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="redirect_check",
        description="Traces HTTP redirect chains, detecting open redirects and protocol downgrades. Arguments: url (str), max_hops (int).",
        func=redirect_check,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="robots_check",
        description="Fetches and parses /robots.txt directives and sitemaps. Arguments: url (str).",
        func=robots_check,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="security_txt_check",
        description="Checks for RFC 9116 security.txt contact and disclosure guidelines. Arguments: url (str).",
        func=security_txt_check,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="tech_fingerprint",
        description="Detects web servers, backend languages, CMS, and frontend frameworks. Arguments: url (str).",
        func=tech_fingerprint,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="cookie_audit",
        description="Audits HTTP cookies for Secure, HttpOnly, and SameSite attributes. Arguments: url (str).",
        func=cookie_audit,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="cors_check",
        description="Audits Cross-Origin Resource Sharing policy for wildcard or arbitrary origin reflection. Arguments: url (str), origin (str).",
        func=cors_check,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="directory_probe",
        description="Probes a bounded set of common sensitive administrative and backup paths. Arguments: base_url (str), paths (list).",
        func=directory_probe,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="MEDIUM",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=30
    )
    registry.register(
        name="web_endpoint_probe",
        description="Probes common API endpoints (/api, /swagger.json, /graphql, /health). Arguments: base_url (str), endpoints (list).",
        func=web_endpoint_probe,
        sandbox_required=False,
        category=ToolCategory.WEB,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=20
    )
