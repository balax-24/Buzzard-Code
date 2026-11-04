"""
HTTP and API Security Testing Suite.

Provides safe, deterministic tools for testing parameter injection boundaries,
CORS misconfigurations, CSRF defenses, and HTTP header security controls.
See plan sections 20-25 and Phase C.
"""

import json
import re
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from tools.registry import ToolRegistry
from security.risk import RiskClass, ToolRiskMetadata, DEFAULT_TOOL_RISK_PROFILES
from security.autonomy import AutonomyLevel, EnvironmentProfile


def evaluate_security_headers(url: str) -> str:
    """
    Evaluates HTTP security response headers on a target URL and scores compliance.
    
    url: Target URL to evaluate.
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        client = httpx.Client(timeout=15.0, follow_redirects=True, verify=False)
        response = client.get(url)
        headers = {k.lower(): v for k, v in response.headers.items()}

        analysis = {
            "target": url,
            "status_code": response.status_code,
            "checks": {},
            "score": 100,
            "recommendations": []
        }

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" in headers:
            analysis["checks"]["Content-Security-Policy"] = {"present": True, "value": headers["content-security-policy"]}
        else:
            analysis["checks"]["Content-Security-Policy"] = {"present": False}
            analysis["score"] -= 25
            analysis["recommendations"].append("Implement a robust Content-Security-Policy header to mitigate XSS.")

        # 2. Strict-Transport-Security (HSTS)
        if "strict-transport-security" in headers:
            analysis["checks"]["Strict-Transport-Security"] = {"present": True, "value": headers["strict-transport-security"]}
        else:
            analysis["checks"]["Strict-Transport-Security"] = {"present": False}
            if url.startswith("https://"):
                analysis["score"] -= 20
                analysis["recommendations"].append("Add Strict-Transport-Security (HSTS) with max-age >= 31536000.")

        # 3. X-Frame-Options
        if "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", ""):
            analysis["checks"]["X-Frame-Options"] = {"present": True, "value": headers.get("x-frame-options", "Covered via CSP")}
        else:
            analysis["checks"]["X-Frame-Options"] = {"present": False}
            analysis["score"] -= 15
            analysis["recommendations"].append("Add X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking.")

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() == "nosniff":
            analysis["checks"]["X-Content-Type-Options"] = {"present": True, "value": "nosniff"}
        else:
            analysis["checks"]["X-Content-Type-Options"] = {"present": False}
            analysis["score"] -= 15
            analysis["recommendations"].append("Set X-Content-Type-Options: nosniff to prevent MIME sniffing.")

        # 5. Referrer-Policy
        if "referrer-policy" in headers:
            analysis["checks"]["Referrer-Policy"] = {"present": True, "value": headers["referrer-policy"]}
        else:
            analysis["checks"]["Referrer-Policy"] = {"present": False}
            analysis["score"] -= 10
            analysis["recommendations"].append("Configure Referrer-Policy: strict-origin-when-cross-origin.")

        # 6. Server banner leakage
        server = headers.get("server")
        x_powered = headers.get("x-powered-by")
        if server or x_powered:
            analysis["checks"]["Server-Fingerprint"] = {
                "server": server or "None",
                "x_powered_by": x_powered or "None"
            }
            analysis["score"] -= 10
            analysis["recommendations"].append("Suppress or obfuscate Server and X-Powered-By response headers.")

        analysis["score"] = max(0, analysis["score"])
        return json.dumps(analysis, indent=2)
    except Exception as e:
        return f"Error evaluating security headers: {e}"


def check_cors_configuration(url: str, custom_origin: str = "https://evil-attacker.com") -> str:
    """
    Tests CORS configuration on an endpoint for origin reflection and credential exposure.
    
    url: Target URL to test.
    custom_origin: Arbitrary origin header to test against the server.
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        client = httpx.Client(timeout=15.0, follow_redirects=False, verify=False)
        headers = {
            "Origin": custom_origin,
            "Access-Control-Request-Method": "POST",
        }
        
        # Test OPTIONS preflight
        opt_resp = client.options(url, headers=headers)
        # Test GET with Origin
        get_resp = client.get(url, headers={"Origin": custom_origin})

        acao = get_resp.headers.get("access-control-allow-origin") or opt_resp.headers.get("access-control-allow-origin")
        acac = get_resp.headers.get("access-control-allow-credentials") or opt_resp.headers.get("access-control-allow-credentials")

        result = {
            "target": url,
            "tested_origin": custom_origin,
            "allow_origin_header": acao,
            "allow_credentials_header": acac,
            "is_vulnerable": False,
            "vulnerability_type": None,
            "details": "CORS configuration appears secure or restrictive."
        }

        if acao == custom_origin and acac == "true":
            result["is_vulnerable"] = True
            result["vulnerability_type"] = "CRITICAL_CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS"
            result["details"] = f"Endpoint reflects arbitrary origin '{custom_origin}' and enables Access-Control-Allow-Credentials: true."
        elif acao == "*":
            result["is_vulnerable"] = False
            result["details"] = "Wildcard origin (*) allowed without credentials."
        elif acao == custom_origin:
            result["is_vulnerable"] = True
            result["vulnerability_type"] = "ARBITRARY_ORIGIN_REFLECTION"
            result["details"] = f"Endpoint dynamically reflects untrusted Origin '{custom_origin}'."

        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error testing CORS configuration: {e}"


def probe_parameter_injection(
    url: str,
    parameter: str,
    method: str = "GET",
    probe_type: str = "sql_error"
) -> str:
    """
    Performs safe boundary probing on an input parameter to detect injection vulnerabilities.
    
    url: Target URL endpoint.
    parameter: The name of the query or form parameter to test.
    method: HTTP method (GET or POST).
    probe_type: Type of safety probe ('sql_error', 'xss_reflection', 'path_traversal').
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        probes = {
            "sql_error": ["' OR '1'='1", "''", "';--", "1' ORDER BY 1--"],
            "xss_reflection": ["<sec_probe_test_12345>", "\"><sec_probe_test_12345>"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        }

        chosen_probes = probes.get(probe_type, probes["sql_error"])
        client = httpx.Client(timeout=15.0, follow_redirects=True, verify=False)

        results = {
            "target": url,
            "parameter": parameter,
            "probe_type": probe_type,
            "indicators_found": [],
            "potential_vulnerability": False
        }

        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Driver.* SQL[\-\_\ ]*Server",
            r"ORA-[0-9]{4,5}",
            r"SQLite/JDBCDriver",
            r"sqlite3\.OperationalError"
        ]

        for probe in chosen_probes:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[parameter] = [probe]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                resp = client.get(test_url)
            else:
                resp = client.post(url, data={parameter: probe})

            body = resp.text

            if probe_type == "sql_error":
                for pattern in sql_error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        results["indicators_found"].append({
                            "probe": probe,
                            "matched_pattern": pattern,
                            "status_code": resp.status_code
                        })
                        results["potential_vulnerability"] = True

            elif probe_type == "xss_reflection":
                if "<sec_probe_test_12345>" in body:
                    results["indicators_found"].append({
                        "probe": probe,
                        "reflected_unencoded": True,
                        "status_code": resp.status_code
                    })
                    results["potential_vulnerability"] = True

            elif probe_type == "path_traversal":
                if "root:x:0:0:" in body or "[extensions]" in body:
                    results["indicators_found"].append({
                        "probe": probe,
                        "system_file_revealed": True,
                        "status_code": resp.status_code
                    })
                    results["potential_vulnerability"] = True

        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error executing parameter injection probe: {e}"


def register_http_suite_tools(registry: ToolRegistry) -> None:
    """
    Registers HTTP testing suite tools and attaches risk metadata.
    """
    registry.register(
        "evaluate_security_headers",
        "Audits HTTP response security headers (CSP, HSTS, X-Frame-Options, CORS) and computes compliance score.",
        evaluate_security_headers
    )
    registry.register(
        "check_cors_configuration",
        "Tests CORS configuration on an endpoint for arbitrary origin reflection and credential exposure.",
        check_cors_configuration
    )
    registry.register(
        "probe_parameter_injection",
        "Tests an input parameter with safe probes for SQL errors, unencoded XSS reflections, or traversal leaks.",
        probe_parameter_injection
    )

    # Register Risk Metadata
    DEFAULT_TOOL_RISK_PROFILES["evaluate_security_headers"] = ToolRiskMetadata(
        name="evaluate_security_headers",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    )
    DEFAULT_TOOL_RISK_PROFILES["check_cors_configuration"] = ToolRiskMetadata(
        name="check_cors_configuration",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    )
    DEFAULT_TOOL_RISK_PROFILES["probe_parameter_injection"] = ToolRiskMetadata(
        name="probe_parameter_injection",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=False,
        environments=[EnvironmentProfile.LAB, EnvironmentProfile.STAGING],
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    )
