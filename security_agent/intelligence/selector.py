"""
Tool Selection Layer (hypothesis-driven).

Instead of "randomly running 20 tools", the agent reasons about the current
situation and picks the *right* capability for the hypothesis it is testing.
This module maps observed situations / keywords to recommended capabilities
with a rationale, and can optionally create a SecurityHypothesis for each
recommendation so the loop can track verification.

Design goal (per the architecture mandate): the agent should think, e.g.
"This is an authenticated object endpoint. I should first determine whether
authorization is enforced consistently between users" -> request_diff (IDOR).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from security_agent.intelligence.hypothesis import HypothesisEngine, HypothesisStatus


class ToolSelector:
    """Rule-based capability recommender driven by situation + observed keywords."""

    # situation -> (capability, rationale)
    SITUATION_RULES: List[Tuple[str, str, str]] = [
        # --- recon / discovery ---
        ("open port", "service_fingerprint",
         "An open port was found; fingerprint the service/version before choosing an attack."),
        ("http service", "web_tech_detect",
         "An HTTP service is present; identify the tech stack to narrow the attack surface."),
        ("web app", "dir_bruteforce",
         "A web app is present; enumerate hidden directories/files for additional surface."),
        ("api", "api_discovery",
         "An API is present; discover endpoints before testing authorization."),
        ("domain", "dns_enum",
         "A domain is in scope; enumerate DNS records for subdomains and services."),
        ("unknown host", "port_scan",
         "Host is unknown; scan ports to map the attack surface."),
        ("login page", "http_login_brute",
         "A login form is present; test for weak/default credentials."),
        ("login page", "sqli_scan",
         "A login form is present; test the credential fields for SQL injection."),
        # --- auth / access control ---
        ("authenticated object endpoint", "request_diff",
         "This is an authenticated object endpoint; determine whether authorization is enforced consistently between users (IDOR)."),
        ("jwt", "jwt_decode",
         "A JWT was observed; decode header/payload to inspect alg and claims."),
        ("jwt hs256", "jwt_crack",
         "A HS256 JWT was observed; attempt to crack the signing secret."),
        ("session cookie", "session_forgery",
         "A session cookie is present; check whether the signing secret is guessable/forgable."),
        ("rate limit", "rate_limit_test",
         "An endpoint is in scope; verify whether rate limiting is enforced."),
        # --- vuln classes ---
        ("sql", "sqli_scan",
         "SQL is suspected; test the parameter for SQL injection."),
        ("xss", "xss_scan",
         "Reflected input is present; test for cross-site scripting."),
        ("file read", "lfi_scan",
         "A file parameter is present; test for local file inclusion / path traversal."),
        ("command", "cmd_injection_scan",
         "A command-like parameter is present; test for OS command injection."),
        ("ssrf", "ssrf_scan",
         "A URL-fetching parameter is present; test for server-side request forgery."),
        ("cve", "cve_scan",
         "A known product/version is identified; check for known CVEs."),
        # --- API / schema ---
        ("openapi", "openapi_parse",
         "An OpenAPI/Swagger spec is available; parse it to enumerate endpoints, params, and auth."),
        ("graphql", "graphql_introspect",
         "A GraphQL endpoint is present; introspect the schema for types and queries."),
        # --- code / secrets ---
        ("source code", "code_audit",
         "Source code is available; statically audit for common vulnerability patterns."),
        ("repository", "secret_scan",
         "A repository is in scope; scan for leaked secrets/keys."),
        ("secret", "secret_scan",
         "Secrets are suspected; scan the tree for hardcoded credentials."),
        # --- binary / pwn ---
        ("binary", "binary_analyze",
         "A binary is in scope; analyze type, arch, and security properties."),
        ("binary mitigations", "binary_checksec",
         "A binary is in scope; check exploit mitigations (NX/PIE/RELRO/Canary)."),
        ("pwn", "pwn_check",
         "A pwn challenge/binary is in scope; look for format-string/overflow primitives."),
        # --- CTF ---
        ("crypto", "crypto_analyze",
         "Crypto/encoding is suspected; identify and decode the cipher/hash."),
        ("forensics", "forensics_analyze",
         "A forensics artifact is in scope; run file/exiftool/binwalk/strings."),
        ("stego", "stego_extract",
         "Steganography is suspected; attempt to extract hidden data."),
        # --- fuzzing ---
        ("fuzz", "fuzz_url",
         "Fuzzing is requested; mutate the URL/parameter with a vulnerability corpus."),
        ("fuzz binary", "fuzz_target",
         "A binary target is in scope; fuzz it with AFL (or HTTP fallback)."),
        # --- cloud / IaC ---
        ("container", "cloud_scan",
         "A container image is in scope; scan for vulns/secrets/misconfig."),
        ("terraform", "iac_scan",
         "IaC is in scope; scan for misconfigurations."),
        ("kubernetes", "k8s_scan",
         "A Kubernetes cluster is in scope; audit with kube-bench/kube-hunter."),
        ("cloud iam", "cloud_iam",
         "Cloud IAM posture is in scope; audit with prowler/scoutsuite."),
        # --- recon extras ---
        ("whois", "whois_lookup",
         "Registration info is needed; perform a WHOIS/RDAP lookup."),
        ("probe", "http_probe",
         "A quick HTTP probe is needed; fetch status, headers, and title."),
    ]

    # keyword -> capability (fallback when no situation matches)
    KEYWORD_RULES: List[Tuple[str, str]] = [
        ("port", "port_scan"), ("scan", "port_scan"), ("nmap", "port_scan"),
        ("fingerprint", "service_fingerprint"), ("banner", "service_fingerprint"),
        ("http", "web_tech_detect"), ("tech", "web_tech_detect"), ("stack", "web_tech_detect"),
        ("dir", "dir_bruteforce"), ("directory", "dir_bruteforce"), ("gobuster", "dir_bruteforce"),
        ("endpoint", "api_discovery"), ("api", "api_discovery"),
        ("dns", "dns_enum"), ("subdomain", "subdomain_enum"),
        ("login", "http_login_brute"), ("brute", "http_login_brute"), ("password", "http_login_brute"),
        ("sql", "sqli_scan"), ("injection", "sqli_scan"),
        ("xss", "xss_scan"), ("cross-site", "xss_scan"),
        ("lfi", "lfi_scan"), ("traversal", "lfi_scan"), ("file", "lfi_scan"),
        ("command", "cmd_injection_scan"), ("rce", "cmd_injection_scan"),
        ("ssrf", "ssrf_scan"),
        ("jwt", "jwt_decode"), ("token", "jwt_decode"),
        ("idor", "request_diff"), ("authorization", "request_diff"), ("access control", "request_diff"),
        ("rate", "rate_limit_test"),
        ("openapi", "openapi_parse"), ("swagger", "openapi_parse"),
        ("graphql", "graphql_introspect"),
        ("code", "code_audit"), ("audit", "code_audit"),
        ("secret", "secret_scan"), ("key", "secret_scan"), ("credential", "secret_scan"),
        ("binary", "binary_analyze"), ("elf", "binary_analyze"),
        ("checksec", "binary_checksec"), ("mitigation", "binary_checksec"),
        ("pwn", "pwn_check"), ("format string", "pwn_check"), ("overflow", "pwn_check"),
        ("crypto", "crypto_analyze"), ("cipher", "crypto_analyze"), ("hash", "crypto_analyze"),
        ("forensic", "forensics_analyze"), ("memory", "forensics_analyze"),
        ("stego", "stego_extract"), ("hidden", "stego_extract"),
        ("fuzz", "fuzz_url"), ("fuzzing", "fuzz_url"),
        ("container", "cloud_scan"), ("docker", "cloud_scan"), ("image", "cloud_scan"),
        ("terraform", "iac_scan"), ("iac", "iac_scan"), ("cloudformation", "iac_scan"),
        ("kubernetes", "k8s_scan"), ("k8s", "k8s_scan"), ("cluster", "k8s_scan"),
        ("iam", "cloud_iam"), ("aws", "cloud_iam"),
        ("whois", "whois_lookup"), ("registration", "whois_lookup"),
        ("probe", "http_probe"), ("title", "http_probe"),
    ]

    def __init__(self, hypothesis_engine: Optional[HypothesisEngine] = None):
        self.hypothesis_engine = hypothesis_engine

    def recommend(self, situation: str, context: Optional[Dict[str, Any]] = None,
                  top_k: int = 3) -> List[Dict[str, Any]]:
        """Return ranked capability recommendations for a situation string.

        Each item: {capability, rationale, source (situation|keyword), confidence}
        """
        context = context or {}
        s = (situation or "").lower()
        scored: List[Dict[str, Any]] = []
        seen: set = set()

        # 1) exact situation match (highest confidence).
        #    Sort by specificity (longest matched phrase first) so a precise
        #    situation like "authenticated object endpoint" outranks a generic
        #    keyword like "api".
        situation_hits = [(sit, cap, rationale) for sit, cap, rationale in self.SITUATION_RULES
                          if sit in s]
        situation_hits.sort(key=lambda t: len(t[0]), reverse=True)
        for sit, cap, rationale in situation_hits:
            if cap not in seen:
                scored.append({"capability": cap, "rationale": rationale,
                               "source": "situation", "confidence": 0.9})
                seen.add(cap)

        # 2) keyword match
        for kw, cap in self.KEYWORD_RULES:
            if kw in s and cap not in seen:
                scored.append({"capability": cap, "rationale": f"Keyword '{kw}' matched.",
                               "source": "keyword", "confidence": 0.6})
                seen.add(cap)

        # 3) context hints (e.g. known open ports, discovered endpoints)
        for hint in context.get("hints", []):
            for kw, cap in self.KEYWORD_RULES:
                if kw in str(hint).lower() and cap not in seen:
                    scored.append({"capability": cap, "rationale": f"Context hint '{hint}'.",
                                   "source": "context", "confidence": 0.5})
                    seen.add(cap)

        return scored[:top_k]

    def recommend_for_hypothesis(self, vulnerability_type: str,
                                 target_asset: str) -> Optional[Dict[str, Any]]:
        """Map a hypothesis's vulnerability type to a capability and register it."""
        recs = self.recommend(vulnerability_type)
        if not recs:
            return None
        top = recs[0]
        if self.hypothesis_engine:
            self.hypothesis_engine.create_hypothesis(
                target_asset=target_asset,
                vulnerability_type=vulnerability_type,
                description=f"Testing {vulnerability_type} on {target_asset} via {top['capability']}.",
                initial_confidence=0.5,
            )
        return top

    def describe(self) -> str:
        """Human-readable summary of the selection layer for prompts/docs."""
        return (f"ToolSelector: {len(self.SITUATION_RULES)} situation rules, "
                f"{len(self.KEYWORD_RULES)} keyword rules.")
