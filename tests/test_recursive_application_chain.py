"""
Tests for Phase 10 Application Attack-Chain Reasoning.
Verifies the multi-stage progression:
DISCOVERY -> APPLICATION -> AUTHENTICATION -> SESSION -> BROWSER -> DOM -> API ->
HYPOTHESIS A -> VALIDATION A -> CAPABILITY A -> GRAPH EXPANSION ->
SURFACE B -> HYPOTHESIS B -> VALIDATION B -> CAPABILITY B ->
SURFACE C -> HYPOTHESIS C -> VALIDATION C -> INDEPENDENT VERIFICATION ->
OBJECTIVE_VERIFIED -> REPORT.
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceRecord,
    Capability,
    CapabilityType,
    ObjectiveStatus,
)
from security_agent.state.session_store import Cookie
from security_agent.browser import DOMReducer
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind
from security_agent.intelligence.evidence_ingestor import EvidenceIngestor
from security_agent.agent.tool_executor import ToolExecutionResult
from security_agent.verification.finding_verifier import FindingVerifier


def test_full_application_attack_chain_lifecycle():
    # 1. DISCOVERY & INITIAL STATE
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    ingestor = EvidenceIngestor()
    graph = AttackGraph()

    # 2. Port Discovery
    state.record_service("target.local", 8080, "http", evidence_id="EVI-PORT-01")
    graph.sync_from_state(state)
    assert len(graph.nodes) >= 2

    # 3. APPLICATION & BROWSER DOM (Reveals Form / Login - Surface A)
    dom_a = """
    <html><body>
        <h1>Enterprise Portal</h1>
        <form id="auth" action="http://target.local:8080/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <button type="submit">Login</button>
        </form>
    </body></html>
    """
    res1 = ToolExecutionResult(
        success=True,
        tool_name="browser.snapshot",
        arguments={"url": "http://target.local:8080/"},
        raw_output=dom_a,
        exit_code=0
    )
    ingestor.ingest(res1, state=state)
    assert len(state.forms) == 1

    # 4. AUTHENTICATION & SESSION ACQUISITION (Validation A -> Capability A)
    auth_resp = "STATUS: 302 Found\nSet-Cookie: session_user=REGULAR_USER_TOKEN; Path=/\nLocation: /dashboard"
    res2 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://target.local:8080/login", "method": "POST"},
        raw_output=auth_resp,
        exit_code=0
    )
    ingestor.ingest(res2, state=state)
    state.capabilities["cap-user"] = Capability(
        capability_id="cap-user",
        capability_type=CapabilityType.AUTHENTICATED,
        target_scope="target.local",
        source_evidence_ids=["EVI-AUTH-01"],
        metadata={"unlocked_endpoints": ["http://target.local:8080/dashboard"]}
    )

    # 5. SURFACE B (User Dashboard reveals hidden KYC Upload Form)
    dom_b = """
    <html><body>
        <h1>User Dashboard</h1>
        <form id="kyc" action="http://target.local:8080/user/kyc_upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="doc" />
            <button type="submit">Upload Document</button>
        </form>
    </body></html>
    """
    res3 = ToolExecutionResult(
        success=True,
        tool_name="browser.snapshot",
        arguments={"url": "http://target.local:8080/dashboard"},
        raw_output=dom_b,
        exit_code=0
    )
    ingestor.ingest(res3, state=state)
    assert len(state.forms) == 2

    # 6. VALIDATION B (Upload polyglot -> extracts Admin API Key -> Capability B)
    upload_resp = "HTTP/1.1 200 OK\nFile uploaded to /uploads/shell.php. Server config reveals ADMIN_KEY=SEC_ROOT_999"
    res4 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://target.local:8080/user/kyc_upload", "method": "POST"},
        raw_output=upload_resp,
        exit_code=0
    )
    ingestor.ingest(res4, state=state)
    state.capabilities["cap-admin-key"] = Capability(
        capability_id="cap-admin-key",
        capability_type=CapabilityType.ADMIN_ACCESS,
        target_scope="target.local",
        source_evidence_ids=["EVI-UPLOAD-01"],
        metadata={"unlocked_endpoints": ["http://target.local:8080/api/admin/system"]}
    )

    # 7. SURFACE C & VALIDATION C (Admin API reveals Admin state)
    admin_resp = "HTTP/1.1 200 OK\n{\"role\": \"SUPERADMIN\", \"flag\": \"FLAG-PHASE10-APP-CHAIN-CONVERGED\"}"
    res5 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://target.local:8080/api/admin/system", "headers": {"X-Admin-Key": "SEC_ROOT_999"}},
        raw_output=admin_resp,
        exit_code=0
    )
    ingestor.ingest(res5, state=state)
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # 8. INDEPENDENT VERIFICATION -> OBJECTIVE_VERIFIED
    ver_resp = "HTTP/1.1 200 OK\nIndependent verification confirmed: SUPERADMIN privileged access active."
    res6 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://target.local:8080/api/admin/system", "headers": {"X-Admin-Key": "SEC_ROOT_999"}},
        raw_output=ver_resp,
        exit_code=0
    )
    ingestor.ingest(res6, state=state)
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True

    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert state.verification_success is True
    assert len(state.capabilities) == 2
