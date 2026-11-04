"""
Phase 14 Tests: Failure Recovery Controller.
Verifies failure classification, bounded retry logic, action pivoting, and terminal escalation.
"""

from agent.recovery import (
    FailureRecoveryController,
    ToolFailureType,
    ModelFailureType,
    RecoveryAction,
)


def test_tool_failure_classification():
    ctrl = FailureRecoveryController()

    # Timeout
    assert ctrl.classify_tool_failure("nmap", "127.0.0.1", "Connection timed out after 30s") == ToolFailureType.TIMEOUT

    # Malformed Output
    assert ctrl.classify_tool_failure("nmap", "127.0.0.1", "JSONDecodeError: Unterminated string") == ToolFailureType.MALFORMED_OUTPUT

    # Schema Error
    assert ctrl.classify_tool_failure("nmap", "127.0.0.1", "missing required field: target") == ToolFailureType.SCHEMA_ERROR

    # Sandbox Failure
    assert ctrl.classify_tool_failure("nmap", "127.0.0.1", "sandbox killed by OOM", exit_code=137) == ToolFailureType.SANDBOX_FAILURE


def test_model_failure_classification():
    ctrl = FailureRecoveryController()

    # Empty Output
    assert ctrl.classify_model_failure("   ", None) == ModelFailureType.EMPTY_OUTPUT

    # Invalid JSON
    assert ctrl.classify_model_failure("I think we should scan port 80", None) == ModelFailureType.INVALID_JSON

    # Repeated Identical Action
    assert ctrl.classify_model_failure("{}", {}, is_duplicate=True) == ModelFailureType.REPEATED_IDENTICAL_ACTION

    # Truncation
    assert ctrl.classify_model_failure("```json\n{\"action\": \"scan\"", None) == ModelFailureType.REASONING_TRUNCATION


def test_tool_recovery_action_progression_and_pivoting():
    ctrl = FailureRecoveryController(max_tool_retries=2)
    tool_name = "http_request"
    target = "http://127.0.0.1:8080/admin"

    # Attempt 1: Timeout -> RETRY
    plan1 = ctrl.plan_tool_recovery(tool_name, target, ToolFailureType.TIMEOUT, "Connection timed out")
    assert plan1.action == RecoveryAction.RETRY
    assert plan1.current_retry_count == 1

    # Attempt 2: Timeout -> RETRY
    plan2 = ctrl.plan_tool_recovery(tool_name, target, ToolFailureType.TIMEOUT, "Connection timed out")
    assert plan2.action == RecoveryAction.RETRY
    assert plan2.current_retry_count == 2

    # Attempt 3: Exhausted retries -> PIVOT
    plan3 = ctrl.plan_tool_recovery(tool_name, target, ToolFailureType.TIMEOUT, "Connection timed out")
    assert plan3.action == RecoveryAction.PIVOT


def test_repeated_identical_action_recovery():
    ctrl = FailureRecoveryController()

    plan = ctrl.plan_model_recovery(
        failure_type=ModelFailureType.REPEATED_IDENTICAL_ACTION,
        context_prompt="Select next action"
    )
    assert plan.action == RecoveryAction.PIVOT
