"""
Phase 15 Tests: Context-Change Action Reconsideration.
Verifies that acquiring a capability justifies re-evaluating previously failed actions.
"""

from security_agent.intelligence.action_history import ActionHistoryStore, ActionOutcome
from security_agent.intelligence.failure_memory import FailureAwareMemory
from security_agent.intelligence.reconsideration import ReconsiderationEngine, ReconsiderationTrigger


def test_context_change_reconsiders_auth_endpoint():
    history = ActionHistoryStore()
    failure_mem = FailureAwareMemory()

    # 1. Action executed and failed with 401
    failure_mem.record_failure(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/admin/settings"},
        target="127.0.0.1",
        status_code=401,
        error_message="Unauthorized",
    )
    history.record_action(
        action_id="act-01",
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/admin/settings"},
        target="127.0.0.1",
        expected_gain=2.0,
        actual_gain=0.0,
        cost=1.0,
        outcome=ActionOutcome.BLOCKED_AUTH,
    )

    # 2. Acquire AUTHENTICATED capability
    reconsidered = ReconsiderationEngine.evaluate_capability_transition(
        new_capability="AUTHENTICATED",
        history=history,
        failure_memory=failure_mem,
        current_capabilities={"AUTHENTICATED"},
    )

    assert len(reconsidered) >= 1
    rec = reconsidered[0]
    assert "admin/settings" in rec.canonical_action_key
    assert rec.trigger == ReconsiderationTrigger.CAPABILITY_ACQUIRED
    assert rec.refreshed_expected_gain > 3.0
