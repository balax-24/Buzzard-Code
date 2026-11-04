"""
Remediation and Patch Generation Engine.

Produces actionable, copy-paste code patches, defensive validation rules,
and framework security configurations for discovered findings.
See plan sections 57, 58, 59 and Phase F.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from security_agent.model.schemas import Finding


@dataclass
class RemediationPatch:
    finding_id: str
    vulnerability_title: str
    summary: str
    code_diff: str
    config_snippet: str
    language: str
    validation_steps: List[str]


class RemediationGenerator:
    """
    Generates remediation blueprints and code-level diffs for security findings.
    """
    def generate_patch(self, finding: Finding) -> RemediationPatch:
        title_lower = finding.title.lower()

        # 1. SQL Injection Patch
        if "sql" in title_lower or "injection" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Replace raw string formatting with parameterized prepared statements or ORM queries.",
                code_diff=(
                    "- cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n"
                    "+ cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"
                ),
                config_snippet="# Ensure DB connection uses prepared statement pooling",
                language="python",
                validation_steps=[
                    "Submit test SQL probe \"' OR '1'='1\" and confirm database returns parameterized match or empty set, not syntax error.",
                    "Verify input length and type validation at API boundary."
                ]
            )

        # 2. XSS / Reflection Patch
        elif "xss" in title_lower or "reflection" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Apply context-aware output encoding and strict Content Security Policy.",
                code_diff=(
                    "- document.getElementById('output').innerHTML = userInput;\n"
                    "+ document.getElementById('output').textContent = userInput;"
                ),
                config_snippet="Content-Security-Policy: default-src 'self'; script-src 'self';",
                language="javascript",
                validation_steps=[
                    "Send probe payload '<script>' to input parameter and confirm response renders HTML entities (&lt;script&gt;).",
                    "Verify CSP header blocks inline script execution."
                ]
            )

        # 3. Security Headers Missing
        elif "header" in title_lower or "csp" in title_lower or "hsts" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Configure modern defensive HTTP response headers at reverse proxy / web server layer.",
                code_diff="",
                config_snippet=(
                    "# Nginx Header Hardening\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self';\" always;"
                ),
                language="nginx",
                validation_steps=[
                    "Execute evaluate_security_headers tool against target endpoint.",
                    "Confirm all 4 headers are present with non-zero max-age on HTTPS."
                ]
            )

        # 4. Android Manifest & Mobile Security Patches
        elif "android" in title_lower or "exported" in title_lower or "cleartext" in title_lower or "backup" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Harden AndroidManifest.xml: disable debuggable, disable allowBackup, restrict cleartext, and guard exported components.",
                code_diff=(
                    "--- a/AndroidManifest.xml\n"
                    "+++ b/AndroidManifest.xml\n"
                    "@@ -5,4 +5,4 @@\n"
                    "-    <application android:debuggable=\"true\" android:allowBackup=\"true\" android:usesCleartextTraffic=\"true\">\n"
                    "+    <application android:debuggable=\"false\" android:allowBackup=\"false\" android:usesCleartextTraffic=\"false\">\n"
                    "-        <activity android:name=\".ExportedActivity\" android:exported=\"true\" />\n"
                    "+        <activity android:name=\".ExportedActivity\" android:exported=\"false\" />"
                ),
                config_snippet=(
                    "<!-- res/xml/network_security_config.xml -->\n"
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    "<network-security-config>\n"
                    "    <base-config cleartextTrafficPermitted=\"false\">\n"
                    "        <trust-anchors>\n"
                    "            <certificates src=\"system\" />\n"
                    "        </trust-anchors>\n"
                    "    </base-config>\n"
                    "</network-security-config>"
                ),
                language="xml",
                validation_steps=[
                    "Run audit_android_manifest tool to confirm total_issues_found is 0.",
                    "Verify app builds successfully in release mode without cleartext traffic."
                ]
            )

        # 5. CORS Wildcard Misconfiguration
        elif "cors" in title_lower or "origin" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Replace wildcard Access-Control-Allow-Origin '*' with an explicit whitelist of trusted origins.",
                code_diff=(
                    "--- a/server.js\n"
                    "+++ b/server.js\n"
                    "@@ -10,2 +10,6 @@\n"
                    "-app.use(cors({ origin: '*' }));\n"
                    "+const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];\n"
                    "+app.use(cors({\n"
                    "+    origin: (origin, callback) => callback(null, allowedOrigins.includes(origin) ? origin : false),\n"
                    "+    credentials: true\n"
                    "+}));"
                ),
                config_snippet="# Restrict CORS to trusted domain whitelist in API gateway",
                language="javascript",
                validation_steps=[
                    "Send OPTIONS preflight request with Origin: https://evil.com and verify response denies Access-Control-Allow-Origin.",
                    "Send request with Origin: https://app.example.com and verify access is permitted."
                ]
            )

        # 6. Docker Container Privileged / Root Execution
        elif "docker" in title_lower or "root" in title_lower or "privileged" in title_lower:
            return RemediationPatch(
                finding_id=finding.id,
                vulnerability_title=finding.title,
                summary="Run container as a non-privileged dedicated user and drop dangerous Linux capabilities.",
                code_diff=(
                    "--- a/Dockerfile\n"
                    "+++ b/Dockerfile\n"
                    "@@ -20,1 +20,4 @@\n"
                    "+RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser\n"
                    "+USER appuser\n"
                    " ENTRYPOINT [\"node\", \"server.js\"]"
                ),
                config_snippet=(
                    "# docker-compose.yml hardening\n"
                    "services:\n"
                    "  app:\n"
                    "    read_only: true\n"
                    "    security_opt:\n"
                    "      - no-new-privileges:true\n"
                    "    cap_drop:\n"
                    "      - ALL"
                ),
                language="dockerfile",
                validation_steps=[
                    "Run docker exec container id and verify UID is non-zero (non-root).",
                    "Verify file system is read-only except for explicitly mounted tmpfs volumes."
                ]
            )

        # Default Generic Patch
        return RemediationPatch(
            finding_id=finding.id,
            vulnerability_title=finding.title,
            summary="Enforce strict input validation, least privilege, and error suppression.",
            code_diff="# Apply input sanitization and boundary check",
            config_snippet="# Restrict endpoint access via authentication middleware",
            language="python",
            validation_steps=[
                "Re-run verification test against modified endpoint.",
                "Verify unauthorized requests receive HTTP 401/403."
            ]
        )
