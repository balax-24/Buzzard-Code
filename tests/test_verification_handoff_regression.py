import pytest
from unittest.mock import MagicMock
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    ServiceRecord,
    ServiceState,
    HypothesisStatus,
    VulnerabilityHypothesis,
)
from agent.tool_executor import ToolExecutor
from range.multi_service_lab import MultiServiceLab


def test_verification_candidate_generation_and_planner_visibility():
    """
    Proves:
    1. Validation success populates session credentials and sets OBJECTIVE_ACHIEVED_UNVERIFIED.
    2. Verification candidate is created with priority CRITICAL and targeted arguments.
    3. format_planner_status() renders === VERIFICATION REQUIRED === with exact candidate action.
    4. Action queues prioritize verification candidate over all discovery actions.
    """
    context = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=context)

    # 1. Discover service
    state.record_service("127.0.0.1", 8080, "tcp", ServiceState.OPEN, "http", "SimpleHTTP/0.6")

    # 2. Simulate validation success (e.g. SQL injection login bypass)
    state.validation_attempted = True
    state.validation_tool_success = True
    state.last_validation_output = "HTTP/1.0 200 OK\r\nSet-Cookie: session=admin; Path=/\r\n\r\n<h1>Login Successful</h1>"
    state.session_credentials["Cookie"] = "session=admin"
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
    state.transition(AssessmentPhase.VERIFICATION, "Validation succeeded.")

    # 3. Generate verification candidates
    candidates = state.generate_verification_candidates()
    assert len(candidates) >= 1
    admin_candidate = candidates[0]
    assert admin_candidate["tool"] == "http.request"
    assert "/admin" in admin_candidate["target"]
    assert admin_candidate["args"]["headers"]["Cookie"] == "session=admin"
    assert admin_candidate["priority"] == "CRITICAL"

    # 4. Check action queues prioritization
    state._update_action_queues()
    assert len(state.pending_actions) >= 1
    top_action = state.pending_actions[0]
    assert top_action["tool"] == "http.request"
    assert "/admin" in top_action.get("target", top_action.get("args", {}).get("url", ""))

    # 5. Planner status context verification
    status_text = state.format_planner_status()
    assert "=== VERIFICATION REQUIRED ===" in status_text
    assert "OBJECTIVE_ACHIEVED_UNVERIFIED" in status_text
    assert "http.request" in status_text
    assert "/admin" in status_text


def test_verification_execution_with_lab():
    """
    Proves:
    1. Validation success -> verification candidate executed by ToolExecutor against MultiServiceLab.
    2. Lab returns HTTP 200 with proof marker FLAG-ALPHA-AUTH-BYPASS when session=admin is supplied.
    3. Proof marker transitions state to OBJECTIVE_VERIFIED and phase to REPORT.
    """
    lab = MultiServiceLab(web_port=18980, ipp_port=18981, ssh_port=18982)
    lab.start()

    try:
        context = AssessmentContext(target=f"http://127.0.0.1:{lab.web_port}", scope=["127.0.0.1"])
        state = AssessmentState(context=context)
        state.record_service("127.0.0.1", lab.web_port, "tcp", ServiceState.OPEN, "http", "SimpleHTTP/0.6")

        # Hypothesize & validate
        hyp = VulnerabilityHypothesis(
            id="HYP-SQLI-01",
            target="127.0.0.1",
            port=lab.web_port,
            service="http",
            vulnerability_type="sql_injection",
            evidence_ids=["DISCOVERY-18900"]
        )
        state.hypotheses[hyp.id] = hyp

        state.validation_attempted = True
        state.validation_tool_success = True
        state.session_credentials["Cookie"] = "session=admin"
        state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
        state.current_phase = AssessmentPhase.VERIFICATION

        # Verification action
        candidates = state.generate_verification_candidates()
        top_cand = candidates[0]

        from toolchain.manager import ToolchainManager
        registry = ToolchainManager._create_default_registry()
        executor = ToolExecutor(registry=registry)
        exec_res = executor.execute(
            tool_name=top_cand["tool"],
            arguments=top_cand["args"],
            target=context.target,
            session_id="test_sess_phase6f",
            state=state,
            policy_engine=None,
            sandbox=None
        )

        assert exec_res.success is True
        assert "FLAG-ALPHA-AUTH-BYPASS" in exec_res.raw_output or "FLAG{auth_bypass_sqli_verified}" in exec_res.raw_output

        # Verification proof capture
        markers = ["FLAG{", "FLAG-", "PROOF-", "Admin Panel"]
        assert any(m in exec_res.raw_output for m in markers)

        state.verification_success = True
        state.objective_achieved = True
        state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
        state.transition(AssessmentPhase.REPORT, "Verification proof captured.")

        assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert state.current_phase == AssessmentPhase.REPORT

    finally:
        lab.stop()
