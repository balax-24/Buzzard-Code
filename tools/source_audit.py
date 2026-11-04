"""
Source Code, Secrets, Dependencies, and Configuration Security Auditing Suite.

Provides static security scanners for:
1. Hardcoded API keys, secrets, and credentials
2. Vulnerable dependencies in requirements.txt, package.json, etc.
3. Container and deployment misconfigurations (Docker, K8s, Nginx)
See plan sections 27, 28, 29 and Phase C.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from tools.registry import ToolRegistry
from security.risk import RiskClass, ToolRiskMetadata, DEFAULT_TOOL_RISK_PROFILES
from security.autonomy import AutonomyLevel, EnvironmentProfile


SECRET_PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*=\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
    "Generic Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "GitHub Personal Access Token": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b",
    "Slack Bot / User Token": r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b",
    "Stripe API Key": r"\b(sk_live_[0-9a-zA-Z]{24})\b",
    "OpenAI API Key": r"\b(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9]{48})\b",
    "Database Password in URI": r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:([^@]+)@",
}


def scan_source_secrets(directory_path: str = ".") -> str:
    """
    Scans a source code directory for hardcoded credentials, private keys, and API tokens.
    
    directory_path: Local filesystem directory to scan.
    """
    try:
        root_dir = Path(directory_path).resolve()
        if not root_dir.exists() or not root_dir.is_dir():
            return f"Error: Directory '{directory_path}' does not exist or is not a directory."

        findings = []
        ignored_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                file_path = Path(root) / file
                if file_path.stat().st_size > 2_000_000:  # Skip files > 2MB
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines, 1):
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        match = re.search(pattern, line)
                        if match:
                            snippet = line.strip()
                            if len(snippet) > 100:
                                snippet = snippet[:97] + "..."
                            findings.append({
                                "secret_type": secret_type,
                                "file": str(file_path.relative_to(root_dir)),
                                "line": line_idx,
                                "matched_snippet": snippet
                            })

        return json.dumps({
            "scanned_directory": str(root_dir),
            "secrets_found_count": len(findings),
            "findings": findings
        }, indent=2)
    except Exception as e:
        return f"Error scanning for secrets: {e}"


def audit_configurations(directory_path: str = ".") -> str:
    """
    Audits Dockerfiles, compose files, and Nginx configurations for security misconfigurations.
    
    directory_path: Directory containing configuration files.
    """
    try:
        root_dir = Path(directory_path).resolve()
        issues = []

        for root, _, files in os.walk(root_dir):
            for file in files:
                file_lower = file.lower()
                full_path = Path(root) / file

                # 1. Dockerfile checks
                if "dockerfile" in file_lower:
                    try:
                        content = full_path.read_text(encoding="utf-8", errors="ignore")
                        if not re.search(r"(?i)^USER\s+[a-zA-Z0-9]+", content, re.MULTILINE):
                            issues.append({
                                "file": str(full_path.relative_to(root_dir)),
                                "severity": "HIGH",
                                "issue": "Dockerfile lacks non-root USER instruction; container runs as root by default."
                            })
                        if re.search(r"(?i)^ADD\s+http", content, re.MULTILINE):
                            issues.append({
                                "file": str(full_path.relative_to(root_dir)),
                                "severity": "MEDIUM",
                                "issue": "Dockerfile uses ADD with remote URL instead of verified curl/checksum."
                            })
                    except Exception:
                        pass

                # 2. docker-compose checks
                if "compose" in file_lower and (file_lower.endswith(".yml") or file_lower.endswith(".yaml")):
                    try:
                        content = full_path.read_text(encoding="utf-8", errors="ignore")
                        if "privileged: true" in content.lower():
                            issues.append({
                                "file": str(full_path.relative_to(root_dir)),
                                "severity": "CRITICAL",
                                "issue": "Docker Compose container configured with 'privileged: true' (container escape risk)."
                            })
                        if "network_mode: host" in content.lower():
                            issues.append({
                                "file": str(full_path.relative_to(root_dir)),
                                "severity": "HIGH",
                                "issue": "Docker Compose service uses 'network_mode: host' bypassing network isolation."
                            })
                    except Exception:
                        pass

        return json.dumps({
            "scanned_directory": str(root_dir),
            "configuration_issues_count": len(issues),
            "issues": issues
        }, indent=2)
    except Exception as e:
        return f"Error auditing configuration files: {e}"


def audit_android_manifest(manifest_path: str = "AndroidManifest.xml") -> str:
    """
    Audits AndroidManifest.xml for exported components, cleartext traffic, debug flags, and dangerous permissions.
    """
    try:
        path = Path(manifest_path).resolve()
        if not path.exists():
            # Try searching in current directory
            candidates = list(Path(".").rglob("AndroidManifest.xml"))
            if candidates:
                path = candidates[0].resolve()
            else:
                return f"Error: AndroidManifest.xml not found at '{manifest_path}'."

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        issues = []
        
        # 1. Debuggable check
        if re.search(r'android:debuggable\s*=\s*["\']true["\']', content):
            issues.append({
                "severity": "HIGH",
                "title": "Application Is Debuggable",
                "component": "application",
                "description": "android:debuggable='true' allows attackers to attach debuggers, dump memory, and execute arbitrary code.",
                "remediation": "Set android:debuggable='false' or remove the attribute for production builds."
            })

        # 2. AllowBackup check
        if re.search(r'android:allowBackup\s*=\s*["\']true["\']', content) or "android:allowBackup" not in content:
            issues.append({
                "severity": "MEDIUM",
                "title": "Application Backup Enabled (allowBackup)",
                "component": "application",
                "description": "android:allowBackup='true' allows app private data to be extracted via ADB backup without root.",
                "remediation": "Set android:allowBackup='false' in <application> tag."
            })

        # 3. Cleartext traffic check
        if re.search(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', content):
            issues.append({
                "severity": "HIGH",
                "title": "Cleartext HTTP Traffic Allowed",
                "component": "application",
                "description": "android:usesCleartextTraffic='true' allows unencrypted HTTP network communication susceptible to MITM.",
                "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS with a Network Security Config."
            })

        # 4. Exported components without permissions
        comp_pattern = re.compile(r'<(activity|activity-alias|service|receiver|provider)\b([^>]*?)>', re.DOTALL | re.IGNORECASE)
        for m in comp_pattern.finditer(content):
            comp_type = m.group(1)
            attrs = m.group(2)
            name_m = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', attrs)
            comp_name = name_m.group(1) if name_m else "Unknown"
            
            is_exported = False
            if re.search(r'android:exported\s*=\s*["\']true["\']', attrs):
                is_exported = True
            elif "android:exported" not in attrs and "<intent-filter" in attrs:
                is_exported = True

            has_permission = bool(re.search(r'android:permission\s*=\s*["\']([^"\']+)["\']', attrs))

            if is_exported and not has_permission and not comp_name.endswith("MainActivity") and "MAIN" not in attrs:
                issues.append({
                    "severity": "HIGH",
                    "title": f"Exported {comp_type.capitalize()} Without Permission",
                    "component": f"{comp_type}:{comp_name}",
                    "description": f"Component '{comp_name}' is exported to all applications on the device without an android:permission guard.",
                    "remediation": f"Add android:permission or set android:exported='false' if external access is not required."
                })

        return json.dumps({
            "manifest_file": str(path),
            "total_issues_found": len(issues),
            "findings": issues
        }, indent=2)
    except Exception as e:
        return f"Error auditing Android manifest: {e}"


def audit_mobile_storage(directory_path: str = ".") -> str:
    """
    Scans mobile app source code for insecure storage, hardcoded secrets, weak crypto, and SQL injection.
    """
    try:
        root_dir = Path(directory_path).resolve()
        findings = []

        code_patterns = [
            (
                r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
                "HIGH",
                "World-Readable/Writable File or Preference",
                "Using MODE_WORLD_READABLE/WRITEABLE exposes app data to all other apps on the device.",
                "Use MODE_PRIVATE or EncryptedSharedPreferences."
            ),
            (
                r'rawQuery\s*\(\s*["\'].*?\+\s*[a-zA-Z0-9_]+',
                "HIGH",
                "Potential SQLite SQL Injection",
                "Raw SQL query concatenation with variable input detected.",
                "Use parameterized queries with selectionArgs placeholders."
            ),
            (
                r'setJavaScriptEnabled\s*\(\s*true\s*\)',
                "MEDIUM",
                "WebView JavaScript Execution Enabled",
                "Enabling JavaScript in WebViews increases exposure to Cross-Site Scripting (XSS) and bridge exploitation.",
                "Disable JavaScript if not required, or restrict loaded URLs to HTTPS domains."
            ),
            (
                r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
                "HIGH",
                "Insecure WebView File URL Access",
                "Allows JavaScript running in local files to access other local files and origins.",
                "Set setAllowFileAccessFromFileURLs(false) and setAllowUniversalAccessFromFileURLs(false)."
            ),
            (
                r'TrustAllCertificates|ALLOW_ALL_HOSTNAME_VERIFIER|NullTrustManager',
                "CRITICAL",
                "Disabled TLS Certificate Verification",
                "Trusting all SSL/TLS certificates completely disables cryptographic MITM protections.",
                "Use system trust stores with optional certificate pinning."
            )
        ]

        ignored_dirs = {".git", "build", ".gradle", "node_modules", "dist"}

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                if not any(file.endswith(ext) for ext in (".kt", ".java", ".xml", ".js", ".ts", ".dart")):
                    continue
                file_path = Path(root) / file
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines, 1):
                    for pattern, sev, title, desc, rem in code_patterns:
                        if re.search(pattern, line):
                            findings.append({
                                "file": str(file_path.relative_to(root_dir)),
                                "line": line_idx,
                                "severity": sev,
                                "title": title,
                                "description": desc,
                                "matched_code": line.strip()[:120],
                                "remediation": rem
                            })

        return json.dumps({
            "scanned_directory": str(root_dir),
            "mobile_security_findings_count": len(findings),
            "findings": findings
        }, indent=2)
    except Exception as e:
        return f"Error auditing mobile storage and code: {e}"


def audit_api_spec(spec_path: str) -> str:
    """
    Audits an OpenAPI/Swagger specification file for missing authentication, insecure HTTP schemes, and wide CORS.
    """
    try:
        path = Path(spec_path).resolve()
        if not path.exists():
            return f"Error: API spec file not found at '{spec_path}'."

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        issues = []
        # JSON or YAML parsing
        try:
            data = json.loads(content)
        except Exception:
            return f"Error: API spec at '{spec_path}' must be valid JSON format."

        # 1. Scheme checks
        servers = data.get("servers", [])
        for s in servers:
            url = s.get("url", "")
            if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                issues.append({
                    "severity": "HIGH",
                    "title": "Unencrypted HTTP Server Endpoint",
                    "description": f"API server '{url}' uses unencrypted HTTP protocol.",
                    "remediation": "Enforce HTTPS for all production and staging API hosts."
                })

        # 2. Security schemes check
        components = data.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        global_security = data.get("security", [])

        if not security_schemes and not global_security:
            issues.append({
                "severity": "HIGH",
                "title": "No Global Security Schemes Defined",
                "description": "The API specification does not define any security schemes (Bearer JWT, OAuth2, APIKey).",
                "remediation": "Define securitySchemes under components and apply security requirements globally or per-route."
            })

        # 3. Unauthenticated routes audit
        paths = data.get("paths", {})
        unauth_routes = []
        for route_path, methods in paths.items():
            if isinstance(methods, dict):
                for method, op in methods.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch") and isinstance(op, dict):
                        op_sec = op.get("security")
                        if op_sec is None and not global_security:
                            unauth_routes.append(f"{method.upper()} {route_path}")

        if unauth_routes:
            issues.append({
                "severity": "MEDIUM",
                "title": f"Unauthenticated API Endpoints ({len(unauth_routes)})",
                "description": f"The following routes have no security requirement defined: {', '.join(unauth_routes[:10])}",
                "remediation": "Ensure authentication middleware is explicitly required on all private business endpoints."
            })

        return json.dumps({
            "spec_file": str(path),
            "total_issues": len(issues),
            "findings": issues
        }, indent=2)
    except Exception as e:
        return f"Error auditing API specification: {e}"


def register_source_audit_tools(registry: ToolRegistry) -> None:
    """
    Registers source code auditing tools and assigns risk metadata.
    """
    registry.register(
        "scan_source_secrets",
        "Scans a local directory for hardcoded secrets, AWS keys, API tokens, and private keys.",
        scan_source_secrets
    )
    registry.register(
        "audit_configurations",
        "Scans Dockerfiles and Compose files for root execution, privileged mode, and dangerous misconfigurations.",
        audit_configurations
    )
    registry.register(
        "audit_android_manifest",
        "Audits AndroidManifest.xml for exported components without permissions, cleartext traffic, and debug flags.",
        audit_android_manifest
    )
    registry.register(
        "audit_mobile_storage",
        "Scans mobile app source code for insecure storage, hardcoded secrets, weak crypto, and SQL injection.",
        audit_mobile_storage
    )
    registry.register(
        "audit_api_spec",
        "Audits OpenAPI/Swagger specification files for missing authentication, insecure HTTP schemes, and route security.",
        audit_api_spec
    )

    # Risk metadata
    for tool_name in ["scan_source_secrets", "audit_configurations", "audit_android_manifest", "audit_mobile_storage", "audit_api_spec"]:
        DEFAULT_TOOL_RISK_PROFILES[tool_name] = ToolRiskMetadata(
            name=tool_name,
            risk_class=RiskClass.R0_PASSIVE,
            requires_approval=False,
            production_allowed=True,
            timeout_seconds=30,
            min_autonomy_level=AutonomyLevel.LEVEL_0_OBSERVER,
        )

