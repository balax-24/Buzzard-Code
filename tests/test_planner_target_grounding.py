"""
Unit tests for Planner Target Grounding & Action Eligibility:
1. Placeholder rejection (<target>, target.com, example.com)
2. Out-of-scope target blocking
3. Canonical target authorization
4. Immutable AssessmentContext
5. Connection refused recovery (HTTP 80 refused -> Discovery transition)
6. Known HTTP service eligibility (8080 open -> HTTP tools allowed)
7. Unknown HTTP service ineligibility (80 closed -> HTTP tools blocked)
8. Target drift logging & Planner status formatting
"""

import pytest
from dataclasses import FrozenInstanceError

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ServiceState,
    HTTPState,
    FailureClassification,
    TargetValidator,
    TargetValidationResult,
    CandidateActionValidator,
)


def test_assessment_context_immutability():
    """Verify AssessmentContext is immutable and cannot be mutated."""
    ctx = AssessmentContext(
        target="127.0.0.1",
        scope=("127.0.0.1", "localhost"),
        objective="Assess local services"
    )
    assert ctx.target == "127.0.0.1"
    
    with pytest.raises(FrozenInstanceError):
        ctx.target = "attacker.com"  # type: ignore


def test_placeholder_target_rejection():
    """Verify placeholders like <target>, target.com, example.com are rejected."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    
    placeholders = [
        "<target>", "<TARGET>", "<target_url>", "<host>", "target", 
        "example.com", "target.example.com", "localhost.example",
        "victim.com", "target.com"
    ]
    
    for ph in placeholders:
        is_valid, msg, res = TargetValidator.validate_target(ph, ctx)
        assert not is_valid, f"Expected {ph} to be blocked as placeholder"
        assert res in (TargetValidationResult.BLOCKED_PLACEHOLDER, TargetValidationResult.BLOCKED_OUT_OF_SCOPE)
        assert "ACTION BLOCKED" in msg
        assert "Canonical target:\n127.0.0.1" in msg


def test_out_of_scope_target_blocking():
    """Verify out-of-scope external targets are explicitly blocked without rewriting."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    
    is_valid, msg, res = TargetValidator.validate_target("http://unauthorized-domain.org/api", ctx)
    assert not is_valid
    assert res == TargetValidationResult.BLOCKED_OUT_OF_SCOPE
    assert "TARGET_OUT_OF_SCOPE" in msg
    assert "unauthorized-domain.org" in msg


def test_canonical_target_allowed():
    """Verify canonical target and authorized scope targets are allowed."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    
    is_valid, msg, res = TargetValidator.validate_target("127.0.0.1", ctx)
    assert is_valid
    assert res == TargetValidationResult.ALLOWED

    is_valid, msg, res = TargetValidator.validate_target("http://localhost:8080/test", ctx)
    assert is_valid
    assert res == TargetValidationResult.ALLOWED


def test_candidate_action_validator_rejects_placeholders():
    """Verify CandidateActionValidator intercepts placeholder arguments before execution."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    state = AssessmentState(context=ctx)
    
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="http_probe",
        args={"url": "<target>"},
        state=state
    )
    assert not is_valid
    assert "INVALID_TARGET_PLACEHOLDER" in reason
    assert "<target>" in state.blocked_targets
    assert len(state.target_drift_log) == 1


def test_http_tools_eligibility_with_closed_and_open_ports():
    """
    Verify HTTP tools are blocked when port 80 is closed/refused,
    but allowed when port 8080 is verified open as HTTP.
    """
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    state = AssessmentState(context=ctx)
    
    # 1. Initially record port 80 refused
    state.record_action_attempt(
        tool_name="http_probe",
        args={"url": "http://127.0.0.1:80/"},
        target="127.0.0.1",
        success=False,
        failure_type=FailureClassification.CONNECTION_REFUSED,
        output_snippet="ERR_CONNECTION_REFUSED"
    )
    
    # HTTP probe against port 80 should now be blocked
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="http_probe",
        args={"url": "http://127.0.0.1:80/"},
        state=state
    )
    assert not is_valid
    assert "HTTP_SERVICE_NOT_ESTABLISHED" in reason

    # 2. Discover port 8080 as open HTTP service
    state.record_service(
        host="127.0.0.1",
        port=8080,
        service="http",
        state=ServiceState.OPEN
    )
    
    # HTTP probe against port 8080 should now be VALID and ELIGIBLE
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="http.request",
        args={"url": "http://127.0.0.1:8080/health"},
        state=state
    )
    assert is_valid


def test_connection_refused_discovery_recovery():
    """Verify connection refusal triggers state transition to DISCOVERY and enqueues nmap_scan."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.TARGETED_ENUMERATION
    
    state.record_action_attempt(
        tool_name="http_probe",
        args={"url": "http://127.0.0.1:80/"},
        target="127.0.0.1",
        success=False,
        failure_type=FailureClassification.CONNECTION_REFUSED,
        output_snippet="ERR_CONNECTION_REFUSED"
    )
    
    # Must transition back to DISCOVERY
    assert state.current_phase == AssessmentPhase.DISCOVERY
    
    # Must have enqueued discovery action at top of pending actions
    assert len(state.pending_actions) > 0
    top_action = state.pending_actions[0]
    assert top_action["tool"] == "nmap_scan"
    assert top_action["args"]["host"] == "127.0.0.1"


def test_format_planner_status():
    """Verify format_planner_status outputs clean canonical sections."""
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    state = AssessmentState(context=ctx)
    
    state.record_service(host="127.0.0.1", port=631, service="ipp", state=ServiceState.OPEN)
    state.record_target_drift(requested_target="target.com", tool_name="whois_lookup", validation_result="BLOCKED_OUT_OF_SCOPE")
    
    summary = state.format_planner_status()
    assert "CANONICAL TARGET:\n127.0.0.1" in summary
    assert "AUTHORIZED SCOPE:\n127.0.0.1, localhost" in summary
    assert "631/tcp (ipp)" in summary
    assert "target.com" in summary
    assert "CURRENT PHASE:" in summary
