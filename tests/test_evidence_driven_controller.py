"""
Acceptance Test Suite for Buzzard Code Evidence-Driven State Controller.
Verifies all 23 specifications:
1. Canonical Service State & Version Grounding
2. Canonical HTTP State & Contradiction Detection
3. ToolResult Payload Classification (Catching ERR_CONNECTION_REFUSED with exit 0)
4. Candidate Action Pre-Execution Validation (Schema & Target Justification)
5. Service-specific Deterministic Routing (IPP / HTTP)
6. Anti-Hallucination Report Generation & Claim Sanitization
7. Context Compaction & State-Scoped Caching
"""

import pytest
from unittest.mock import MagicMock
from security_agent.sandbox.container import ToolResult, ToolErrorType
from security_agent.tools.manifest_suite import service_inventory
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    CandidateActionValidator,
    ServiceRecord,
    HTTPEndpointRecord,
    HTTPState,
    ServiceState,
    VerificationStatus,
    FailureClassification
)
from security_agent.intelligence.evidence_parser import (
    EvidenceValidator,
    AttackSurfaceSnapshot,
    DiscoveredService
)
from security_agent.agent.loop import AgentLoop
from security_agent.tools.registry import ToolRegistry


def test_tool_result_classification_connection_refused():
    """
    Test #5: ToolResult must classify connection refused as FAILED with CONNECTION_REFUSED
    even when exit code is 0.
    """
    raw_output = "TOOL ERROR: HTTP request failed: <urlopen error [Errno 111] Connection refused>"
    res = ToolResult.from_raw_output(raw_output, exit_code=0, tool_name="http.request")
    
    assert res.success is False
    assert res.error_type == ToolErrorType.CONNECTION_REFUSED
    assert res.exit_code == 111

    browser_output = "TOOL ERROR: Failed to open browser: net::ERR_CONNECTION_REFUSED at https://localhost/"
    res_b = ToolResult.from_raw_output(browser_output, exit_code=0, tool_name="browser.open")
    assert res_b.success is False
    assert res_b.error_type == ToolErrorType.CONNECTION_REFUSED


def test_candidate_action_validation_missing_ports():
    """
    Test #9: scan_ports without ports parameter must be rejected before tool execution.
    """
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="scan_ports",
        args={"host": "127.0.0.1"},
        state=state
    )
    
    assert is_valid is False
    assert "ACTION REJECTED" in reason
    assert "ports" in reason


def test_candidate_action_validation_unsupported_port():
    """
    Test #7: HTTP tool targeting port 80 when only port 631 is open must be rejected.
    """
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    # Discover only port 631 as open
    state.record_service(host="127.0.0.1", port=631, service="ipp", state=ServiceState.OPEN)
    
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="http.request",
        args={"url": "http://127.0.0.1:80/"},
        state=state
    )
    
    assert is_valid is False
    assert "TARGET_NOT_SUPPORTED_BY_EVIDENCE" in reason
    assert "Port 80" in reason


def test_candidate_action_validation_supported_ipp_or_http():
    """
    Test #7 & #13: Targeted action against discovered port 631 is permitted.
    """
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.record_service(host="127.0.0.1", port=631, service="ipp", state=ServiceState.OPEN)
    
    is_valid, reason, norm_args = CandidateActionValidator.validate_candidate(
        tool_name="grab_banner",
        args={"port": 631},
        state=state
    )
    
    assert is_valid is True
    assert norm_args["host"] == "127.0.0.1"


def test_evidence_contradiction_detection_http_refused():
    """
    Test #3 & #16: Website claim marked online must be rejected when HTTP state is REFUSED.
    """
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.record_http_probe("http://127.0.0.1:80/", HTTPState.REFUSED)
    
    is_contra, reason = state.check_evidence_contradiction("Website is online and responsive.")
    assert is_contra is True
    assert "Evidence contradiction" in reason
    assert "CONNECTION REFUSED" in reason


def test_evidence_validator_sanitizes_unverified_cups_version():
    """
    Test #1 & #14: service = ipp with version UNKNOWN cannot claim CUPS 2.4.
    """
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    snapshot.services.append(DiscoveredService(port=631, service="ipp", version=""))
    
    validator = EvidenceValidator(snapshot=snapshot)
    raw_llm_claim = "Discovered CUPS 2.4 running on port 631/tcp."
    
    sanitized = validator.sanitize_report_claims(raw_llm_claim, open_ports=[631], refused_http=True)
    assert "CUPS 2.4" not in sanitized
    assert "IPP (version undetected)" in sanitized


def test_evidence_validator_sanitizes_website_online_contradiction():
    """
    Test #16: Sanitize report claims discards online claims when refused_http is True.
    """
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    validator = EvidenceValidator(snapshot=snapshot)
    
    raw_claim = "Website is online and responsive on port 80."
    sanitized = validator.sanitize_report_claims(raw_claim, open_ports=[631], refused_http=True)
    
    assert "[CONTRADICTION DISCARDED]" in sanitized
    assert "ERR_CONNECTION_REFUSED" in sanitized


def test_service_inventory_host_handling():
    """
    Test #8: service_inventory must properly accept host, target, or param_name without dropping host.
    """
    res1 = service_inventory(host="127.0.0.1")
    assert "127.0.0.1" in res1
    
    res2 = service_inventory(target="127.0.0.1")
    assert "127.0.0.1" in res2

    res3 = service_inventory(param_name="localhost")
    assert "localhost" in res3


def test_deterministic_next_action_routing():
    """
    Test #12 & #13: AssessmentState computes deterministic pending action for discovered IPP service.
    """
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.record_service(host="127.0.0.1", port=631, service="ipp", state=ServiceState.OPEN)
    
    next_action = state.get_deterministic_next_action()
    assert next_action is not None
    assert next_action["tool"] == "grab_banner"
    assert next_action["args"]["port"] == 631
    assert next_action["priority"] == "HIGH"


def test_agent_loop_candidate_validation_rejection_e2e():
    """
    Test #10: AgentLoop automatically rejects candidate tool calls targeting undiscovered ports.
    """
    mock_provider = MagicMock()
    mock_provider.chat.side_effect = [
        # 1. Model discovers only port 631
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="nmap_scan"><host>127.0.0.1</host></tool_call>',
                "tool_calls": []
            }
        },
        # 2. Model tries to open browser at port 80 (undiscovered) -> should be rejected!
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="http.request"><url>http://127.0.0.1:80/</url></tool_call>',
                "tool_calls": []
            }
        },
        # 3. Model concludes
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="complete"><summary>Done</summary></tool_call>',
                "tool_calls": []
            }
        }
    ]

    registry = ToolRegistry()
    registry.register("nmap_scan", "Scan host", lambda host="127.0.0.1", ports="1-1000", options="": "631/tcp open ipp")
    http_called = []
    registry.register("http.request", "HTTP", lambda method="GET", url="", **kwargs: http_called.append(url) or "OK")
    registry.register("complete", "Complete", lambda summary="": summary)

    loop = AgentLoop(
        provider=mock_provider,
        registry=registry,
        max_iterations=4,
        config={"max_actions": 5},
        approval_callback=lambda tool, args, metadata: True,
    )

    result = loop.run(task_goal="Assess target", target="127.0.0.1")
    assert result["status"] == "completed"
    # http.request on port 80 was rejected before reaching handler because port 80 was not open!
    assert len(http_called) == 0
    assert loop.tools_failed >= 1
