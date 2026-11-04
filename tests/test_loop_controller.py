"""
Unit tests for LoopRecoveryController, StuckLoopDetector, and Evidence-Grounded Exploitation Lifecycle.

Verifies:
1. Stuck loop detection (repeated 3x identical calls)
2. Failure loop detection
3. Discovered vulnerable lab service transitions to EXPLOITATION
4. Target with no vulnerability/service evidence does not trigger arbitrary exploitation (returns to DISCOVERY)
5. Open uninvestigated service transitions to ENUMERATION
6. Exploitation results must be verified (premature completion guarded)
7. Failed exploitation classifies failure and recovers to alternative strategy
8. Identical exploit attempts are blocked by CandidateActionValidator
9. Out-of-scope exploitation is blocked by TargetValidator and CandidateActionValidator
10. Completion cannot occur before required verification
"""

import json
import pytest
from security_agent.agent.loop_controller import StuckLoopDetector, LoopRecoveryController
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ServiceState,
    HypothesisStatus,
    ExploitStatus,
    CandidateActionValidator,
    TargetValidator,
    TargetValidationResult
)


def test_stuck_loop_detector():
    detector = StuckLoopDetector(window_size=3)

    detector.record_call("nmap_scan", {"host": "127.0.0.1", "ports": "1-1000"})
    is_loop, _ = detector.is_loop_detected()
    assert not is_loop

    detector.record_call("nmap_scan", {"host": "127.0.0.1", "ports": "1-1000"})
    is_loop, _ = detector.is_loop_detected()
    assert not is_loop

    detector.record_call("nmap_scan", {"host": "127.0.0.1", "ports": "1-1000"})
    is_loop, tool = detector.is_loop_detected()
    assert is_loop
    assert tool == "nmap_scan"


def test_failure_loop_detector():
    detector = StuckLoopDetector(window_size=3)

    detector.record_failure("sqlmap_attack", "CONNECTION_REFUSED", 1)
    detector.record_failure("sqlmap_attack", "CONNECTION_REFUSED", 1)
    is_fail_loop, _ = detector.is_failure_loop_detected()
    assert not is_fail_loop

    detector.record_failure("sqlmap_attack", "CONNECTION_REFUSED", 1)
    is_fail_loop, sig = detector.is_failure_loop_detected()
    assert is_fail_loop
    assert "CONNECTION_REFUSED" in sig


def test_recovery_no_attack_surface_returns_discovery():
    """When no open services exist, stuck loop returns to DISCOVERY, NOT EXPLOITATION."""
    controller = LoopRecoveryController(max_redirects=3)
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))

    # Loop detected with no discovered services
    phase, prompt, action = controller.handle_stuck_state(
        state=state,
        target="127.0.0.1",
        last_tool="ping_host"
    )

    assert phase == AssessmentPhase.DISCOVERY
    assert "DISCOVERY phase" in prompt
    assert "Arbitrary exploitation is FORBIDDEN" in prompt
    assert action is not None
    assert action["tool"] == "nmap_scan"


def test_recovery_uninvestigated_service_returns_enumeration():
    """When open service is uninvestigated, stuck loop returns to ENUMERATION."""
    controller = LoopRecoveryController(max_redirects=3)
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    state.record_service(host="127.0.0.1", port=8080, protocol="tcp", service="http", version="UNKNOWN", state=ServiceState.OPEN)

    phase, prompt, action = controller.handle_stuck_state(
        state=state,
        target="127.0.0.1",
        last_tool="ping_host"
    )

    assert phase == AssessmentPhase.ENUMERATION
    assert "ENUMERATION phase" in prompt
    assert "8080" in prompt
    assert action is not None
    assert action["tool"] in ("whatweb_scan", "grab_banner")


def test_recovery_vulnerable_service_transitions_to_exploitation():
    """When attack surface supports a concrete hypothesis, stuck loop transitions to EXPLOITATION."""
    controller = LoopRecoveryController(max_redirects=3)
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    srv = state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", version="Apache", state=ServiceState.OPEN)
    srv.investigated = True

    # Record verified hypothesis
    hyp = state.record_hypothesis(
        target="http://127.0.0.1:80",
        service="http",
        port=80,
        vulnerability_type="auth_bypass_sqli",
        rationale="Login page accepts unvalidated SQL strings",
        suggested_tools=["sqlmap_attack", "http.request"]
    )

    phase, prompt, action = controller.handle_stuck_state(
        state=state,
        target="127.0.0.1",
        last_tool="whatweb_scan"
    )

    assert phase == AssessmentPhase.EXPLOITATION
    assert "EXPLOITATION PHASE" in prompt
    assert hyp.id in prompt
    assert action is not None
    assert action["tool"] == "sqlmap_attack"


def test_exploit_failure_classification_and_recovery():
    """Failed exploit classifies error and offers alternative strategy."""
    controller = LoopRecoveryController()
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    srv = state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN)
    srv.investigated = True

    # Two hypotheses
    hyp1 = state.record_hypothesis(target="http://127.0.0.1:80", service="http", port=80, vulnerability_type="sqli", suggested_tools=["sqlmap_attack"])
    hyp2 = state.record_hypothesis(target="http://127.0.0.1:80", service="http", port=80, vulnerability_type="path_traversal", suggested_tools=["web_fetch"])

    advice = controller.classify_exploit_failure(
        state=state,
        hypothesis_id=hyp1.id,
        tool_name="sqlmap_attack",
        raw_output="401 Unauthorized / WAF Blocked",
        exit_code=1
    )

    assert "EXPLOITATION ATTEMPT FAILED" in advice
    assert hyp2.id in advice
    assert "path_traversal" in advice
    assert len(state.exploitation_records) == 1
    assert state.exploitation_records[0].status == ExploitStatus.FAILED


def test_candidate_action_validator_blocks_duplicate_exploit():
    """Duplicate exploit executions are blocked by CandidateActionValidator."""
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN)

    # First attempt valid
    valid, _, _ = CandidateActionValidator.validate_candidate(
        tool_name="sqlmap_attack",
        args={"url": "http://127.0.0.1:80/login", "data": "user=admin"},
        state=state
    )
    assert valid

    # Record failed attempt
    state.record_action_attempt(
        tool_name="sqlmap_attack",
        args={"url": "http://127.0.0.1:80/login", "data": "user=admin"},
        target="127.0.0.1",
        success=False,
        failure_type="COMMAND_ERROR"
    )
    # Mark in attempted_action_keys
    call_sig = f"sqlmap_attack:{json.dumps({'data': 'user=admin', 'url': 'http://127.0.0.1:80/login'}, sort_keys=True)}"
    state.attempted_action_keys.add(call_sig)

    # Second identical attempt blocked
    valid2, msg2, _ = CandidateActionValidator.validate_candidate(
        tool_name="sqlmap_attack",
        args={"url": "http://127.0.0.1:80/login", "data": "user=admin"},
        state=state
    )
    assert not valid2
    assert "DUPLICATE_EXPLOIT_ATTEMPT" in msg2


def test_candidate_action_validator_blocks_exploit_on_closed_port():
    """Exploitation targeting a closed/unverified port is blocked."""
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN)

    # Targeting port 8080 which is not open
    valid, msg, _ = CandidateActionValidator.validate_candidate(
        tool_name="sqlmap_attack",
        args={"url": "http://127.0.0.1:8080/login"},
        state=state
    )
    assert not valid
    assert "8080" in msg
    assert ("TARGET_PORT_NOT_OPEN" in msg or "TARGET_NOT_SUPPORTED_BY_EVIDENCE" in msg)


def test_out_of_scope_exploit_blocked():
    """Exploitation targeting out-of-scope host is blocked."""
    context = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    valid, msg, res = TargetValidator.validate_target("http://192.168.1.100/login", context)
    assert not valid
    assert res == TargetValidationResult.BLOCKED_OUT_OF_SCOPE
    assert "TARGET_OUT_OF_SCOPE" in msg


def test_premature_completion_guarded_when_verification_required():
    """Premature completion is blocked when an exploit was executed but unverified."""
    controller = LoopRecoveryController()
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    state.current_phase = AssessmentPhase.EXPLOITATION
    srv = state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN)
    srv.investigated = True

    # Record unverified pending exploit
    state.record_exploit_attempt(
        hypothesis_id="HYP-SQLI-80",
        tool_name="sqlmap_attack",
        target="http://127.0.0.1:80",
        port=80,
        arguments={},
        status=ExploitStatus.PENDING,
        verified=False
    )

    continuation = controller.check_premature_completion(
        content="I am done.",
        observations=["Executed sqlmap_attack"],
        iteration=3,
        max_iterations=10,
        state=state,
        task_goal="Perform security audit and exploit vulnerable parameters",
        target="127.0.0.1"
    )
    assert continuation is not None
    assert "EXPLOITATION VERIFICATION REQUIRED" in continuation
    assert state.current_phase == AssessmentPhase.VERIFICATION


def test_exploit_candidate_preconditions_evaluation():
    """Explicitly tests ExploitCandidate precondition evaluation against AssessmentState."""
    from security_agent.agent.assessment_state import ExploitCandidate, ExploitPrecondition

    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    srv = state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN)

    hyp = state.record_hypothesis(
        target="http://127.0.0.1:80",
        service="http",
        port=80,
        vulnerability_type="auth_bypass_sqli",
        rationale="Unsanitized login POST endpoint",
        evidence_ids=["DISCOVERY-80"],
        suggested_tools=["http.request"]
    )

    candidate = ExploitCandidate(
        target="http://127.0.0.1:80",
        service="http",
        port=80,
        vulnerability_hypothesis=hyp,
        evidence_ids=["DISCOVERY-80"],
        required_conditions=ExploitPrecondition(
            require_open_port=True,
            require_service_match="http",
            disallow_if_failed_before=True
        ),
        allowed_tool="http.request",
        tool_arguments={"url": "http://127.0.0.1:80/login", "method": "POST"},
        verification_plan="Verify HTTP 302 redirect or auth cookie."
    )

    # 1. Valid preconditions pass
    valid, msg = candidate.evaluate_preconditions(state)
    assert valid
    assert "satisfied" in msg

    # 2. Closed port fails precondition
    bad_port_cand = ExploitCandidate(
        target="http://127.0.0.1:8080",
        service="http",
        port=8080,
        vulnerability_hypothesis=hyp,
        required_conditions=ExploitPrecondition(require_open_port=True)
    )
    valid_bad, msg_bad = bad_port_cand.evaluate_preconditions(state)
    assert not valid_bad
    assert "Port 8080 is not open" in msg_bad

    # 3. Service mismatch fails precondition
    mismatched_cand = ExploitCandidate(
        target="http://127.0.0.1:80",
        service="ssh",
        port=80,
        vulnerability_hypothesis=hyp,
        required_conditions=ExploitPrecondition(require_service_match="ssh")
    )
    valid_mis, msg_mis = mismatched_cand.evaluate_preconditions(state)
    assert not valid_mis
    assert "does not match required 'ssh'" in msg_mis
