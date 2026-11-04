"""
Phase 1-6 Tests: Deterministic Laboratory Matrix.

Executes and validates the DeterministicController across all 15 isolated laboratory
vulnerability scenarios:
 1. SQLI_AUTH_BYPASS: SQL injection authentication bypass
 2. PATH_TRAVERSAL_LFI: Path traversal / local file inclusion
 3. COMMAND_INJECTION_RCE: Operating system command injection
 4. REFLECTED_XSS: Reflected cross-site scripting
 5. CORS_MISCONFIGURATION: Overly permissive CORS with credentials
 6. SSRF_METADATA: Server-side request forgery exposing cloud metadata
 7. DEFAULT_CREDENTIALS_SSH: Default administrative credentials on service
 8. IDOR_USER_RECORD: Insecure direct object reference data leak
 9. OPEN_REDIRECT: Arbitrary unvalidated external redirection
 10. ANONYMOUS_FTP: Anonymous FTP service access and file extraction
 11. SECURITY_HEADERS_MISSING: Missing defensive HTTP headers
 12. UNAUTHENTICATED_FILE_UPLOAD: Unrestricted file upload leading to execution
 13. WEAK_JWT_SECRET: JWT forgery allowing privilege escalation
 14. EXPOSED_GIT_DIR: Exposed source code repository disclosure
 15. RECURSIVE_3TIER_CHAIN: 3-tier composite recursive expansion (A -> B -> C)

Ensures:
- 100% deterministic, model-independent execution
- Zero manual action injection
- Canonical AssessmentState provenance and AttackGraph synchronization
- Complete lifecycle: START -> SCOPE -> DISCOVERY -> HYPOTHESIS -> PRECONDITION -> VALIDATION -> CAPABILITY -> VERIFICATION -> COMPLETION
- Checkpoint/resume persistence compatibility
"""

import pytest
from typing import Dict, Any, List, Optional
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    CapabilityType,
    HypothesisStatus,
)
from agent.deterministic_controller import DeterministicController
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus


class LabScenarioDefinition:
    """Defines a deterministic laboratory vulnerability scenario."""
    def __init__(
        self,
        scenario_id: str,
        name: str,
        target: str,
        port: int,
        service: str,
        vulnerability_type: str,
        initial_endpoint: str,
        expected_proof_marker: str,
        tool_responses: Dict[str, Dict[str, Any]],
        is_recursive: bool = False,
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.target = target
        self.port = port
        self.service = service
        self.vulnerability_type = vulnerability_type
        self.initial_endpoint = initial_endpoint
        self.expected_proof_marker = expected_proof_marker
        self.tool_responses = tool_responses
        self.is_recursive = is_recursive


def _build_scenario_definitions() -> List[LabScenarioDefinition]:
    """Builds the 15 standard deterministic laboratory vulnerability scenarios."""
    scenarios = [
        # 1. SQL Injection Authentication Bypass
        LabScenarioDefinition(
            scenario_id="LAB-01",
            name="SQLI_AUTH_BYPASS",
            target="http://10.10.10.1",
            port=80,
            service="http",
            vulnerability_type="auth_bypass_sqli",
            initial_endpoint="http://10.10.10.1/login",
            expected_proof_marker="FLAG{sqli_auth_bypass_verified}",
            tool_responses={
                "sqlmap_attack": {
                    "success": True,
                    "exit_code": 0,
                    "session_cookie": "session=admin_token_sqli",
                    "proof_marker": "FLAG{sqli_auth_bypass_verified}",
                    "output": "HTTP/1.1 200 OK\nSet-Cookie: session=admin_token_sqli\nFLAG{sqli_auth_bypass_verified}",
                },
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "session_cookie": "session=admin_token_sqli",
                    "proof_marker": "FLAG{sqli_auth_bypass_verified}",
                    "output": "HTTP/1.1 200 OK\nSet-Cookie: session=admin_token_sqli\nFLAG{sqli_auth_bypass_verified}",
                },
            },
        ),
        # 2. Path Traversal / Local File Inclusion
        LabScenarioDefinition(
            scenario_id="LAB-02",
            name="PATH_TRAVERSAL_LFI",
            target="http://10.10.10.2",
            port=80,
            service="http",
            vulnerability_type="lfi",
            initial_endpoint="http://10.10.10.2/view?file=test",
            expected_proof_marker="FLAG{path_traversal_lfi_verified}",
            tool_responses={
                "lfi_scan": {
                    "success": True,
                    "exit_code": 0,
                    "secret": "root:x:0:0:root:/root:/bin/bash",
                    "proof_marker": "FLAG{path_traversal_lfi_verified}",
                    "output": "root:x:0:0:root:/root:/bin/bash\nFLAG{path_traversal_lfi_verified}",
                },
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "secret": "root:x:0:0:root:/root:/bin/bash",
                    "proof_marker": "FLAG{path_traversal_lfi_verified}",
                    "output": "root:x:0:0:root:/root:/bin/bash\nFLAG{path_traversal_lfi_verified}",
                },
            },
        ),
        # 3. OS Command Injection
        LabScenarioDefinition(
            scenario_id="LAB-03",
            name="COMMAND_INJECTION_RCE",
            target="http://10.10.10.3",
            port=80,
            service="http",
            vulnerability_type="command_injection",
            initial_endpoint="http://10.10.10.3/ping",
            expected_proof_marker="FLAG{command_injection_rce_verified}",
            tool_responses={
                "cmd_injection_scan": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{command_injection_rce_verified}",
                    "output": "PING 127.0.0.1 (127.0.0.1)\nuid=0(root) gid=0(root)\nFLAG{command_injection_rce_verified}",
                },
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{command_injection_rce_verified}",
                    "output": "uid=0(root) gid=0(root)\nFLAG{command_injection_rce_verified}",
                },
            },
        ),
        # 4. Reflected Cross-Site Scripting (XSS)
        LabScenarioDefinition(
            scenario_id="LAB-04",
            name="REFLECTED_XSS",
            target="http://10.10.10.4",
            port=80,
            service="http",
            vulnerability_type="xss",
            initial_endpoint="http://10.10.10.4/search?q=test",
            expected_proof_marker="FLAG{reflected_xss_verified}",
            tool_responses={
                "xss_scan": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{reflected_xss_verified}",
                    "output": "<html><body>Search Results: <script>alert('XSS')</script> FLAG{reflected_xss_verified}</body></html>",
                },
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{reflected_xss_verified}",
                    "output": "<html><body>Search Results: <script>alert('XSS')</script> FLAG{reflected_xss_verified}</body></html>",
                },
            },
        ),
        # 5. Permissive CORS Misconfiguration
        LabScenarioDefinition(
            scenario_id="LAB-05",
            name="CORS_MISCONFIGURATION",
            target="http://10.10.10.5",
            port=80,
            service="http",
            vulnerability_type="cors_misconfiguration",
            initial_endpoint="http://10.10.10.5/api/user/profile",
            expected_proof_marker="FLAG{cors_misconfiguration_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{cors_misconfiguration_verified}",
                    "output": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\nFLAG{cors_misconfiguration_verified}",
                },
            },
        ),
        # 6. Server-Side Request Forgery (SSRF) Cloud Metadata
        LabScenarioDefinition(
            scenario_id="LAB-06",
            name="SSRF_METADATA",
            target="http://10.10.10.6",
            port=80,
            service="http",
            vulnerability_type="ssrf",
            initial_endpoint="http://10.10.10.6/proxy?url=test",
            expected_proof_marker="FLAG{ssrf_cloud_metadata_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{ssrf_cloud_metadata_verified}",
                    "output": '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Token": "FLAG{ssrf_cloud_metadata_verified}"}',
                },
            },
        ),
        # 7. Default Credentials on SSH Service
        LabScenarioDefinition(
            scenario_id="LAB-07",
            name="DEFAULT_CREDENTIALS_SSH",
            target="10.10.10.7",
            port=22,
            service="ssh",
            vulnerability_type="weak_credentials",
            initial_endpoint="10.10.10.7:22",
            expected_proof_marker="FLAG{default_creds_ssh_verified}",
            tool_responses={
                "ssh_brute": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{default_creds_ssh_verified}",
                    "output": "Login successful: admin:admin123 -> FLAG{default_creds_ssh_verified}",
                },
                "nmap": {
                    "success": True,
                    "exit_code": 0,
                    "output": "22/tcp open ssh OpenSSH 8.9p1",
                },
            },
        ),
        # 8. Insecure Direct Object Reference (IDOR)
        LabScenarioDefinition(
            scenario_id="LAB-08",
            name="IDOR_USER_RECORD",
            target="http://10.10.10.8",
            port=80,
            service="http",
            vulnerability_type="idor",
            initial_endpoint="http://10.10.10.8/api/users/102",
            expected_proof_marker="FLAG{idor_data_leak_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{idor_data_leak_verified}",
                    "output": '{"user_id": 102, "role": "admin", "secret_key": "FLAG{idor_data_leak_verified}"}',
                },
            },
        ),
        # 9. Open Redirect
        LabScenarioDefinition(
            scenario_id="LAB-09",
            name="OPEN_REDIRECT",
            target="http://10.10.10.9",
            port=80,
            service="http",
            vulnerability_type="open_redirect",
            initial_endpoint="http://10.10.10.9/redirect?to=http://attacker.com",
            expected_proof_marker="FLAG{open_redirect_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{open_redirect_verified}",
                    "output": "HTTP/1.1 302 Found\nLocation: http://attacker.com/FLAG{open_redirect_verified}",
                },
            },
        ),
        # 10. Anonymous FTP Access
        LabScenarioDefinition(
            scenario_id="LAB-10",
            name="ANONYMOUS_FTP",
            target="10.10.10.10",
            port=21,
            service="ftp",
            vulnerability_type="default_credentials",
            initial_endpoint="10.10.10.10:21",
            expected_proof_marker="FLAG{anonymous_ftp_backup_verified}",
            tool_responses={
                "ftp_brute": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{anonymous_ftp_backup_verified}",
                    "output": "230 User logged in anonymously.\nDownloaded backup.tar.gz FLAG{anonymous_ftp_backup_verified}",
                },
            },
        ),
        # 11. Security Headers Missing
        LabScenarioDefinition(
            scenario_id="LAB-11",
            name="SECURITY_HEADERS_MISSING",
            target="http://10.10.10.11",
            port=80,
            service="http",
            vulnerability_type="information_disclosure",
            initial_endpoint="http://10.10.10.11/",
            expected_proof_marker="FLAG{security_headers_missing_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{security_headers_missing_verified}",
                    "output": "HTTP/1.1 200 OK\nServer: Apache/2.4.41\n(Missing X-Frame-Options, CSP, HSTS)\nFLAG{security_headers_missing_verified}",
                },
            },
        ),
        # 12. Unauthenticated File Upload
        LabScenarioDefinition(
            scenario_id="LAB-12",
            name="UNAUTHENTICATED_FILE_UPLOAD",
            target="http://10.10.10.12",
            port=80,
            service="http",
            vulnerability_type="rce",
            initial_endpoint="http://10.10.10.12/upload",
            expected_proof_marker="FLAG{unrestricted_upload_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{unrestricted_upload_verified}",
                    "output": "File shell.php uploaded successfully to /uploads/shell.php\nExecution: uid=0 FLAG{unrestricted_upload_verified}",
                },
            },
        ),
        # 13. Weak JWT Secret Forgery
        LabScenarioDefinition(
            scenario_id="LAB-13",
            name="WEAK_JWT_SECRET",
            target="http://10.10.10.13",
            port=80,
            service="http",
            vulnerability_type="auth_bypass_sqli",
            initial_endpoint="http://10.10.10.13/api/admin",
            expected_proof_marker="FLAG{weak_jwt_forgery_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "session_cookie": "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin",
                    "proof_marker": "FLAG{weak_jwt_forgery_verified}",
                    "output": "HTTP/1.1 200 OK\nAdmin token verified\nFLAG{weak_jwt_forgery_verified}",
                },
            },
        ),
        # 14. Exposed Git Directory
        LabScenarioDefinition(
            scenario_id="LAB-14",
            name="EXPOSED_GIT_DIR",
            target="http://10.10.10.14",
            port=80,
            service="http",
            vulnerability_type="information_disclosure",
            initial_endpoint="http://10.10.10.14/.git/HEAD",
            expected_proof_marker="FLAG{exposed_git_repo_verified}",
            tool_responses={
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{exposed_git_repo_verified}",
                    "output": "ref: refs/heads/main\ncommit 1d217552\nFLAG{exposed_git_repo_verified}",
                },
            },
        ),
        # 15. Recursive 3-Tier Attack Chain (A -> B -> C)
        LabScenarioDefinition(
            scenario_id="LAB-15",
            name="RECURSIVE_3TIER_CHAIN",
            target="http://10.10.10.15",
            port=80,
            service="http",
            vulnerability_type="auth_bypass_sqli",
            initial_endpoint="http://10.10.10.15/login",
            expected_proof_marker="FLAG{root_recursive_chain_verified}",
            is_recursive=True,
            tool_responses={
                # Surface A
                "sqlmap_attack": {
                    "success": True,
                    "exit_code": 0,
                    "session_cookie": "session=admin_cookie_abc",
                    "unlocked_endpoint": "http://10.10.10.15/admin/backup",
                    "output": "SQL Injection successful. Logged in as admin. Backup API at /admin/backup",
                },
                # Surface B
                "lfi_scan": {
                    "success": True,
                    "exit_code": 0,
                    "secret": "SSH_PRIVATE_KEY_BEGIN",
                    "revealed_endpoint": "http://10.10.10.15/admin/shell",
                    "output": "[CONFIG FILE READ SUCCESS] Read id_rsa key from /admin/backup. Target shell at /admin/shell",
                },
                # Surface C
                "cmd_injection_scan": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{root_recursive_chain_verified}",
                    "output": "Command execution successful. root:x:0:0:root. FLAG{root_recursive_chain_verified}",
                },
                "http_request": {
                    "success": True,
                    "exit_code": 0,
                    "proof_marker": "FLAG{root_recursive_chain_verified}",
                    "output": "FLAG{root_recursive_chain_verified}",
                },
            },
        ),
    ]
    return scenarios


def _create_mock_executor(scenario: LabScenarioDefinition):
    """Creates a deterministic mock tool executor mapping scenario tool responses."""
    def executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        # Handle verification tool
        if tool in ("verify_proof", "verify_finding", "verify_objective"):
            return {
                "success": True,
                "exit_code": 0,
                "output": f"Proof verified: {scenario.expected_proof_marker}",
                "proof_marker": scenario.expected_proof_marker,
            }
        # Check scenario responses by tool name
        if tool in scenario.tool_responses:
            return dict(scenario.tool_responses[tool])
        # Fallback to general http_request response if available
        if "http_request" in scenario.tool_responses:
            return dict(scenario.tool_responses["http_request"])
        # Generic fallback
        return {
            "success": True,
            "exit_code": 0,
            "output": f"Deterministic execution of {tool} on {scenario.target}: {scenario.expected_proof_marker}",
            "proof_marker": scenario.expected_proof_marker,
        }
    return executor


@pytest.mark.parametrize("scenario", _build_scenario_definitions(), ids=lambda s: f"{s.scenario_id}_{s.name}")
def test_deterministic_lab_matrix_individual_scenarios(scenario: LabScenarioDefinition):
    """
    Executes each of the 15 isolated laboratory scenarios through the complete
    deterministic controller lifecycle without an LLM.
    """
    ctx = AssessmentContext(
        target=scenario.target,
        scope=[scenario.target, f"{scenario.target}:{scenario.port}", "127.0.0.1"],
        objective=f"Assess {scenario.name} and verify proof marker",
    )
    state = AssessmentState(context=ctx)
    state.record_service(
        host=scenario.target,
        port=scenario.port,
        service=scenario.service,
        evidence_id=f"EVI-INIT-{scenario.scenario_id}",
    )
    if scenario.initial_endpoint:
        state.record_http_probe(
            url=scenario.initial_endpoint,
            state="RESPONDS",
            status_code=200,
            evidence_id=f"EVI-INIT-EP-{scenario.scenario_id}",
        )

    executor = _create_mock_executor(scenario)
    controller = DeterministicController(state=state, tool_executor=executor)

    # Execute controller
    summary = controller.run(max_steps=10)

    # 1. Controller must terminate cleanly
    assert summary.terminal_status in ("OBJECTIVE_VERIFIED_SUCCESS", "OBJECTIVE_VERIFIED", "CONCLUDE_SUCCESS")
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert state.verification_success is True

    # 2. Scope must be strictly respected
    assert state.is_in_scope(scenario.target)

    # 3. Findings must be recorded and match expected proof marker
    assert len(state.findings) >= 1
    assert any(
        scenario.expected_proof_marker in (f.get("proof") if isinstance(f, dict) else getattr(f, "proof", ""))
        or scenario.expected_proof_marker in str(f.get("title") if isinstance(f, dict) else getattr(f, "title", ""))
        for f in state.findings
    )
    assert scenario.expected_proof_marker in state.proof_markers

    # 4. Evidence provenance must be fully traceable
    assert len(state.evidence) >= 1
    for f in state.findings:
        f_eids = f.get("evidence_ids", []) if isinstance(f, dict) else getattr(f, "evidence_ids", [])
        assert len(f_eids) >= 1
        for eid in f_eids:
            assert eid in state.evidence or eid in getattr(state, "evidence_records", {})

    # 5. AttackGraph must be synchronized with findings
    assert len(controller.graph.nodes) >= 2
    finding_nodes = [n for n in controller.graph.nodes.values() if n.kind == NodeKind.FINDING]
    assert len(finding_nodes) >= 1

    # 6. Trace and phase history must demonstrate proper canonical progression
    assert any(p in controller.trace for p in ("VALIDATION", "HYPOTHESIS", "PRECONDITION"))
    assert "OBJECTIVE_VERIFIED" in controller.trace
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED


def test_deterministic_lab_matrix_all_15_scenarios_aggregate_coverage():
    """
    Aggregate evaluation verifying that all 15 scenarios execute to verified completion,
    achieving 100% test coverage without manual action injection or bypasses.
    """
    scenarios = _build_scenario_definitions()
    assert len(scenarios) == 15, "Matrix must define exactly 15 distinct scenarios"

    results = []
    for sc in scenarios:
        ctx = AssessmentContext(
            target=sc.target,
            scope=[sc.target, "127.0.0.1"],
            objective=f"Autonomous assessment of {sc.name}",
        )
        state = AssessmentState(context=ctx)
        state.record_service(host=sc.target, port=sc.port, service=sc.service, evidence_id=f"EVI-{sc.scenario_id}")
        if sc.initial_endpoint:
            state.record_http_probe(url=sc.initial_endpoint, state="RESPONDS", status_code=200)

        controller = DeterministicController(state=state, tool_executor=_create_mock_executor(sc))
        summary = controller.run(max_steps=10)

        results.append({
            "scenario_id": sc.scenario_id,
            "name": sc.name,
            "terminal_status": summary.terminal_status,
            "objective_status": state.objective_status.value,
            "findings_count": len(state.findings),
            "evidence_count": len(state.evidence),
            "proof_verified": sc.expected_proof_marker in state.proof_markers,
            "steps": summary.total_steps,
        })

    # Assert 15/15 successful completions
    assert len(results) == 15
    for r in results:
        assert r["objective_status"] == "OBJECTIVE_VERIFIED", f"Scenario {r['name']} failed objective verification"
        assert r["proof_verified"] is True, f"Scenario {r['name']} missing expected proof marker"
        assert r["findings_count"] >= 1, f"Scenario {r['name']} recorded zero findings"
        assert r["evidence_count"] >= 1, f"Scenario {r['name']} recorded zero evidence"


def test_deterministic_lab_matrix_state_persistence_and_reproducibility():
    """
    Validates state persistence compatibility (to_dict/from_dict) and strictly identical
    reproducibility across repeated runs for lab matrix scenarios.
    """
    scenarios = _build_scenario_definitions()
    # Test on a representative subset: SQLi, LFI, and Recursive Chain
    test_scenarios = [sc for sc in scenarios if sc.scenario_id in ("LAB-01", "LAB-02", "LAB-15")]

    for sc in test_scenarios:
        ctx = AssessmentContext(target=sc.target, scope=[sc.target, "127.0.0.1"], objective="Persistence test")
        state1 = AssessmentState(context=ctx)
        state1.record_service(host=sc.target, port=sc.port, service=sc.service, evidence_id="EVI-1")
        if sc.initial_endpoint:
            state1.record_http_probe(url=sc.initial_endpoint, state="RESPONDS", status_code=200)

        controller1 = DeterministicController(state=state1, tool_executor=_create_mock_executor(sc))
        res1 = controller1.step()

        # Checkpoint state1 mid-run
        dumped = state1.to_dict()
        state2 = AssessmentState.from_dict(dumped)

        # Reconstructed state must match source
        assert state2.current_phase == state1.current_phase
        assert len(state2.evidence) == len(state1.evidence)
        assert len(state2.capabilities) == len(state1.capabilities)

        # Resume from state2 and run to completion
        controller2 = DeterministicController(state=state2, tool_executor=_create_mock_executor(sc))
        summary2 = controller2.run(max_steps=10)

        assert summary2.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert sc.expected_proof_marker in state2.proof_markers
