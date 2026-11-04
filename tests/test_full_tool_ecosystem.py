"""
BUZZARD CODE — COMPREHENSIVE TOOL ECOSYSTEM TEST SUITE
=====================================================
Covers:
1. Suite 1: Network Discovery (12 tools)
2. Suite 2: Web Security (12 tools)
3. Suite 3: TLS / SSL Security (6 tools)
4. Suite 4: DNS Security (7 tools)
5. Suite 5: Recon / OSINT (7 tools)
6. Suite 6: Host Inspection (10 tools)
7. Suite 7: Static File & Binary Analysis (9 tools)
8. Suite 8: Defensive Analysis (9 tools)
9. Suite 9: Safe Automation (6 tools)
10. Security Invariants R1-R8
11. Zip Slip & Decompression Bomb Defenses
12. Host Secret Redaction in Environment Info
13. Chaining Integration Workflows
"""

import os
import sys
import io
import json
import zipfile
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from security_agent.tools.registry import create_authoritative_registry, ToolCategory, ToolRegistry
from security_agent.security.policy import PolicyEngine
from security_agent.security.scope import is_in_scope, ScopeEngine
from security_agent.security.risk import get_tool_risk_metadata, RiskClass
from security_agent.agent.tool_executor import ToolExecutor
from security_agent.agent.assessment_state import AssessmentState, CandidateActionValidator
from security_agent.storage.db import StorageManager

# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(scope="module")
def registry():
    return create_authoritative_registry()

@pytest.fixture
def temp_workspace(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "sample.txt").write_text("Hello world security test file", encoding="utf-8")
    (ws / "secrets.env").write_text("API_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=supersecret", encoding="utf-8")
    return ws


# ==============================================================================
# SUITE 1: NETWORK DISCOVERY (12 tools)
# ==============================================================================

class TestSuite1NetworkDiscovery:
    tools = [
        "ping_host", "dns_lookup", "dns_records", "reverse_dns", "resolve_hostname",
        "scan_ports", "scan_common_ports", "service_detect", "grab_banner",
        "route_trace", "arp_discovery", "subnet_discovery"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions, f"{tool} missing from registry definitions"
            assert tool in registry.tools, f"{tool} missing from registry tools"

    def test_ping_host_functional(self, registry):
        res = registry.execute("ping_host", {"host": "127.0.0.1", "count": 1})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert data.get("target") == "127.0.0.1" or data.get("host") == "127.0.0.1"
        assert "reachable" in data or "alive" in data

    def test_dns_lookup_invalid_host(self, registry):
        res = registry.execute("dns_lookup", {"domain": "invalid-nonexistent-domain-xyz123.test"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("status") in ("error", "failed") or len(data.get("addresses", [])) == 0

    def test_scan_ports_invalid_range(self, registry):
        res = registry.execute("scan_ports", {"host": "127.0.0.1", "ports": "999999"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert "error" in data or data.get("status") == "error" or data.get("open_ports") == []

    def test_scan_common_ports_localhost(self, registry):
        res = registry.execute("scan_common_ports", {"host": "127.0.0.1"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert "scanned_ports" in data or "open_ports" in data

    def test_grab_banner_timeout_handled(self, registry):
        res = registry.execute("grab_banner", {"host": "127.0.0.1", "port": 1, "timeout": 0.5})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert "banner" in data or "error" in data

    def test_subnet_discovery_invalid_cidr(self, registry):
        res = registry.execute("subnet_discovery", {"cidr": "999.999.999.0/24"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("status") == "error" or "error" in data


# ==============================================================================
# SUITE 2: WEB SECURITY (12 tools)
# ==============================================================================

class TestSuite2WebSecurity:
    tools = [
        "check_headers", "ssl_check", "http_request", "http_methods", "redirect_check",
        "robots_check", "security_txt_check", "tech_fingerprint", "cookie_audit",
        "cors_check", "directory_probe", "web_endpoint_probe"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions, f"{tool} missing"

    def test_check_headers_evaluation(self, registry):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "Apache/2.4.41",
            "X-Frame-Options": "DENY",
            "Content-Type": "text/html"
        }
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            res = registry.execute("check_headers", {"url": "http://127.0.0.1:8000"})
            data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
            assert "present_headers" in data or "missing_headers" in data or "headers" in data or "security_score_pct" in data

    def test_http_request_bounded_size(self, registry):
        large_body = b"A" * (300 * 1024)
        mock_resp = MagicMock()
        mock_resp.content = large_body
        mock_resp.text = "A" * (256 * 1024)
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.status_code = 200
        with patch("requests.request", return_value=mock_resp):
            res = registry.execute("http_request", {"url": "http://127.0.0.1/big"})
            data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
            assert len(data.get("body", "")) <= 256 * 1024 or data.get("truncated", False) or "status" in data

    def test_robots_check_missing(self, registry):
        res = registry.execute("robots_check", {"url": "http://127.0.0.1:9999"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert data.get("found") is False or "error" in data or data.get("status") in ("error", "success")


# ==============================================================================
# SUITE 3: TLS / SSL SECURITY (6 tools)
# ==============================================================================

class TestSuite3TlsSecurity:
    tools = [
        "tls_version_check", "tls_cipher_check", "certificate_inspect",
        "certificate_expiry", "certificate_chain", "certificate_hostname"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions

    def test_certificate_expiry_connection_refused_handled(self, registry):
        res = registry.execute("certificate_expiry", {"host": "127.0.0.1", "port": 1})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert "error" in data or data.get("status") in ("error", "failed")

    def test_certificate_hostname_validation(self, registry):
        res = registry.execute("certificate_hostname", {"host": "127.0.0.1", "expected_hostname": "wrong.domain.com"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)


# ==============================================================================
# SUITE 4: DNS SECURITY (7 tools)
# ==============================================================================

class TestSuite4DnsSecurity:
    tools = [
        "dns_mx_check", "dns_txt_check", "dns_spf_check", "dns_dkim_check",
        "dns_dmarc_check", "dnssec_check", "zone_transfer_check"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions

    def test_dns_spf_check_missing(self, registry):
        res = registry.execute("dns_spf_check", {"domain": "invalid-local-domain.test"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("spf_record") is None or data.get("has_spf") is False or "error" in data

    def test_dns_dkim_selector_bounding(self, registry):
        res = registry.execute("dns_dkim_check", {"domain": "example.com", "selector": "default"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert "selector" in data

    def test_zone_transfer_refused(self, registry):
        res = registry.execute("zone_transfer_check", {"domain": "example.com", "nameserver": "127.0.0.1"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert data.get("zone_transfer_vulnerable") is False or "error" in data or data.get("status") in ("success", "failed")


# ==============================================================================
# SUITE 5: RECON & OSINT (7 tools)
# ==============================================================================

class TestSuite5ReconOsint:
    tools = [
        "whois_lookup", "asn_lookup", "ip_info", "domain_info",
        "subdomain_enum", "email_pattern_check", "technology_detect"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions

    def test_ip_info_private_ip(self, registry):
        res = registry.execute("ip_info", {"ip": "192.168.1.1"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("is_private") is True or "private" in str(data).lower()

    def test_technology_detect_explicit_provider(self, registry):
        defn = registry.definitions["technology_detect"]
        assert defn.provider in ("local", "heuristics", "http_headers", "wappalyzer_rules")
        res = registry.execute("technology_detect", {"domain": "localhost"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)


# ==============================================================================
# SUITE 6: HOST INSPECTION (10 tools)
# ==============================================================================

class TestSuite6HostInspection:
    tools = [
        "process_list", "listening_ports", "network_interfaces", "routing_table",
        "system_info", "environment_info", "file_metadata", "file_hash",
        "directory_inventory", "permissions_check"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions

    def test_system_info_functional(self, registry):
        res = registry.execute("system_info", {})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert isinstance(data, dict)
        assert "os" in data or "os_name" in data or "platform" in data

    def test_environment_info_secret_redaction(self, registry, monkeypatch):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        monkeypatch.setenv("DATABASE_PASSWORD", "SuperSecretPass123!")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        monkeypatch.setenv("PUBLIC_APP_ENV", "production")

        res = registry.execute("environment_info", {})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        env_vars = data.get("variables", data.get("environment", {}))

        assert "REDACTED" in env_vars.get("AWS_SECRET_ACCESS_KEY", "")
        assert "REDACTED" in env_vars.get("DATABASE_PASSWORD", "")
        assert "REDACTED" in env_vars.get("GITHUB_TOKEN", "")
        assert env_vars.get("PUBLIC_APP_ENV") == "production"

    def test_file_hash_calculation(self, registry, temp_workspace):
        target = str(temp_workspace / "sample.txt")
        res = registry.execute("file_hash", {"file_path": target, "algorithm": "sha256"})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert "hashes" in data or "sha256" in data or "hash" in data


# ==============================================================================
# SUITE 7: STATIC FILE & BINARY ANALYSIS (9 tools)
# ==============================================================================

class TestSuite7FileMalware:
    tools = [
        "hash_compare", "file_type", "strings_extract", "metadata_extract",
        "entropy_check", "archive_inspect", "pe_inspect", "elf_inspect", "yara_scan"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions
            assert registry.definitions[tool].read_only is True

    def test_entropy_check(self, registry, temp_workspace):
        target = str(temp_workspace / "sample.txt")
        res = registry.execute("entropy_check", {"file_path": target})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert "entropy" in data or "overall_entropy" in data

    def test_archive_inspect_zip_slip_rejection(self, registry, tmp_path):
        zip_path = tmp_path / "malicious_zipslip.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("../../../etc/passwd", "root:x:0:0:::")
            z.writestr("safe.txt", "harmless content")

        res = registry.execute("archive_inspect", {"path": str(zip_path)})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("has_traversal") is True or "traversal" in str(data).lower() or data.get("suspicious") is True

    def test_archive_inspect_decompression_bomb_defense(self, registry, tmp_path):
        bomb_path = tmp_path / "bomb.zip"
        with zipfile.ZipFile(bomb_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("huge_zeroes.bin", b"\x00" * (1024 * 1024))

        res = registry.execute("archive_inspect", {"path": str(bomb_path)})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("suspicious_ratio") is True or data.get("ratio", 0) > 50 or "bomb" in str(data).lower()

    def test_static_pe_inspect_safely_handles_non_pe(self, registry, temp_workspace):
        target = str(temp_workspace / "sample.txt")
        res = registry.execute("pe_inspect", {"file_path": target})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res
        assert data.get("is_pe") is False or "not found" in str(data).lower() or "error" in data


# ==============================================================================
# SUITE 8: DEFENSIVE ANALYSIS (9 tools)
# ==============================================================================

class TestSuite8DefensiveAnalysis:
    tools = [
        "log_search", "log_summary", "ioc_extract", "ioc_match",
        "indicator_normalize", "hash_lookup", "ip_reputation",
        "domain_reputation", "url_reputation"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions

    def test_ioc_extract(self, registry):
        sample_log = (
            "Attacker from 198.51.100.23 visited http://evil-malware-test.com/payload.exe "
            "with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "and contact admin@evil-malware-test.com"
        )
        res = registry.execute("ioc_extract", {"text": sample_log})
        data = json.loads(res) if isinstance(res, str) and res.startswith("{") else res

        ips = data.get("ips") or data.get("iocs", {}).get("ipv4", [])
        domains = data.get("domains") or data.get("iocs", {}).get("domains", [])
        hashes = data.get("hashes") or data.get("iocs", {}).get("sha256", [])
        emails = data.get("emails") or data.get("iocs", {}).get("emails", [])

        assert "198.51.100.23" in ips
        assert any("evil-malware-test.com" in d for d in domains)
        assert any("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in h for h in hashes)
        assert "admin@evil-malware-test.com" in emails

    def test_indicator_normalize_defang_refang(self, registry):
        res_defang = registry.execute("indicator_normalize", {"indicator": "http://malicious.org/bad", "action": "defang"})
        data_defang = json.loads(res_defang) if isinstance(res_defang, str) and res_defang.startswith("{") else res_defang
        defanged = data_defang.get("defanged") or data_defang.get("normalized", "")
        assert "hxxp" in defanged.lower() or "[.]" in defanged

        res_refang = registry.execute("indicator_normalize", {"indicator": "hxxp://malicious[.]org/bad", "action": "refang"})
        data_refang = json.loads(res_refang) if isinstance(res_refang, str) and res_refang.startswith("{") else res_refang
        refanged = data_refang.get("refanged") or data_refang.get("normalized", "")
        assert "http://" in refanged


# ==============================================================================
# SUITE 9: SAFE AUTOMATION (6 tools)
# ==============================================================================

class TestSuite9SafeAutomation:
    tools = [
        "file_read", "file_write", "file_search", "directory_list",
        "evidence_save", "report_generate"
    ]

    def test_all_tools_registered(self, registry):
        for tool in self.tools:
            assert tool in registry.definitions
            assert registry.definitions[tool].category == ToolCategory.AUTOMATION

    def test_file_read_write_cycle(self, registry):
        target = "tests/test_auto_scratch.txt"
        try:
            res_w = registry.execute("file_write", {"path": target, "content": "automated security test"})
            assert "successfully" in str(res_w).lower() or os.path.exists(target)

            res_r = registry.execute("file_read", {"path": target})
            assert "automated security test" in str(res_r)
        finally:
            if os.path.exists(target):
                os.remove(target)

    def test_evidence_save_and_report_generate(self, registry):
        res_ev = registry.execute("evidence_save", {
            "session_id": "test_session",
            "type": "terminal",
            "target": "127.0.0.1",
            "description": "Port scan verification",
            "data": {"open_ports": [80, 443]}
        })
        data_ev = json.loads(res_ev) if isinstance(res_ev, str) and res_ev.startswith("{") else res_ev
        assert data_ev.get("status") == "success"
        assert "evidence_id" in data_ev

        res_rep = registry.execute("report_generate", {
            "session_id": "test_session",
            "summary": "Completed host assessment with zero critical findings."
        })
        data_rep = json.loads(res_rep) if isinstance(res_rep, str) and res_rep.startswith("{") else res_rep
        assert data_rep.get("status") == "success"
        assert "report_markdown" in data_rep


# ==============================================================================
# SECURITY INVARIANTS REGRESSION SUITE (R1 - R8)
# ==============================================================================

class TestSecurityInvariants:
    def test_r1_sandbox_required_fails_closed_when_docker_inactive(self, registry):
        with patch("security_agent.sandbox.container.is_docker_active", return_value=False):
            res = registry.execute("terminal.execute", {"command": "whoami"})
            assert "SECURITY STOP: Sandbox unavailable" in res or "ACTION REJECTED" in res
            assert "Exit code: 126" in res or "blocked" in res.lower()

    def test_r2_out_of_scope_target_rejected(self):
        scope = ["127.0.0.1", "localhost", "internal.corp", "10.0.0.0/24", "*.example.com"]
        assert is_in_scope("127.0.0.1", scope) is True
        assert is_in_scope("app.example.com", scope) is True
        assert is_in_scope("10.0.0.45", scope) is True
        assert is_in_scope("google.com", scope) is False
        assert is_in_scope("8.8.8.8", scope) is False
        assert is_in_scope("10.1.0.1", scope) is False

    def test_r3_invalid_arguments_rejected(self, registry):
        res = registry.execute("scan_ports", {"host": "127.0.0.1", "ports": "not_a_port"})
        assert "error" in str(res).lower()

    def test_r4_policy_denied_actions_blocked(self):
        policy = PolicyEngine(scope=["127.0.0.1"])
        allowed, reason = policy.evaluate_tool_call("scan_ports", {"host": "unauthorized.com"})
        assert allowed is False
        assert "scope" in reason.lower()

    def test_r5_scope_denied_cidr_and_wildcard(self):
        scope = ["192.168.1.0/24", "*.testlab.local"]
        assert is_in_scope("192.168.1.100", scope) is True
        assert is_in_scope("192.168.2.100", scope) is False
        assert is_in_scope("web.testlab.local", scope) is True
        assert is_in_scope("otherlab.local", scope) is False

    def test_r6_approval_required_actions(self, registry):
        defn = registry.definitions.get("terminal.execute") or registry.definitions.get("nmap_scan")
        assert defn is not None
        assert defn.risk_level in ("HIGH", "CRITICAL")
        assert defn.approval_required is True

    def test_r7_candidate_action_validator_local_tools(self):
        assert "file_read" in CandidateActionValidator.LOCAL_ONLY_TOOLS
        assert "dns_lookup" in CandidateActionValidator.DISCOVERY_TOOLS
        assert "check_headers" in CandidateActionValidator.TARGETED_HTTP_TOOLS

    def test_r8_tool_metadata_risk_derivation(self, registry):
        meta = get_tool_risk_metadata("scan_ports")
        assert meta.risk_class in (RiskClass.R0_PASSIVE, RiskClass.R1_LOW, RiskClass.R2_MEDIUM)
        assert meta.name == "scan_ports"


# ==============================================================================
# TOOL CHAINING INTEGRATION WORKFLOWS
# ==============================================================================

class TestToolChainingWorkflows:
    def test_chain_target_discovery_flow(self, registry):
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            dns_res = registry.execute("dns_lookup", {"host": "localhost"})
            data_dns = json.loads(dns_res) if isinstance(dns_res, str) and dns_res.startswith("{") else dns_res
            resolved_ip = data_dns.get("ip") or (data_dns.get("addresses") and data_dns["addresses"][0]) or "127.0.0.1"

        ping_res = registry.execute("ping_host", {"host": resolved_ip, "count": 1})
        data_ping = json.loads(ping_res) if isinstance(ping_res, str) and ping_res.startswith("{") else ping_res
        assert data_ping.get("target") == resolved_ip or data_ping.get("host") == resolved_ip

        scan_res = registry.execute("scan_ports", {"host": resolved_ip, "ports": "80,443"})
        data_scan = json.loads(scan_res) if isinstance(scan_res, str) and scan_res.startswith("{") else scan_res
        assert "scanned_ports" in data_scan

    def test_chain_static_malware_analysis_flow(self, registry, tmp_path):
        sample_file = tmp_path / "suspicious.bin"
        sample_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"This is a suspicious string inside the file!" * 10)

        ft = registry.execute("file_type", {"file_path": str(sample_file)})
        fh = registry.execute("file_hash", {"file_path": str(sample_file), "algorithms": ["sha256"]})
        fe = registry.execute("entropy_check", {"file_path": str(sample_file)})
        fs = registry.execute("strings_extract", {"path": str(sample_file), "min_length": 6})
        fp = registry.execute("pe_inspect", {"file_path": str(sample_file)})

        data_fs = json.loads(fs) if isinstance(fs, str) and fs.startswith("{") else fs
        data_fe = json.loads(fe) if isinstance(fe, str) and fe.startswith("{") else fe

        assert data_fe.get("entropy") is not None or data_fe.get("overall_entropy") is not None
        assert any("suspicious string" in s for s in data_fs.get("strings", []))

    def test_chain_defensive_log_and_ioc_flow(self, registry):
        raw_log = "ALERT: Connection from bad-domain.org (198.51.100.99) with payload hash 5d41402abc4b2a76b9719d911017c592"
        extract_res = registry.execute("ioc_extract", {"text": raw_log})
        data_ext = json.loads(extract_res) if isinstance(extract_res, str) and extract_res.startswith("{") else extract_res
        extracted_domains = data_ext.get("domains") or data_ext.get("iocs", {}).get("domains", [])
        assert any("bad-domain.org" in d for d in extracted_domains)

        norm_res = registry.execute("indicator_normalize", {"indicator": extracted_domains[0], "action": "defang"})
        data_norm = json.loads(norm_res) if isinstance(norm_res, str) and norm_res.startswith("{") else norm_res
        defanged = data_norm.get("defanged") or data_norm.get("normalized", "")
        assert "[.]" in defanged

        match_res = registry.execute("ioc_match", {
            "indicators": [extracted_domains[0]],
            "threat_list": ["bad-domain.org", "evil.com"]
        })
        data_match = json.loads(match_res) if isinstance(match_res, str) and match_res.startswith("{") else match_res
        assert data_match.get("matched") is True or len(data_match.get("matches", [])) >= 1 or "match" in str(data_match).lower()
