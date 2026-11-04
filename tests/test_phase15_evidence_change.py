"""
Phase 15 Tests: Evidence-Change Action Reconsideration.
Verifies that newly discovered evidence unblocks and justifies re-evaluating targets.
"""

from intelligence.action_history import ActionHistoryStore, ActionOutcome
from intelligence.failure_memory import FailureAwareMemory
from intelligence.reconsideration import ReconsiderationEngine, ReconsiderationTrigger


def test_new_evidence_unblocks_target_reconsideration():
    history = ActionHistoryStore()
    failure_mem = FailureAwareMemory()

    # Initial probe failed
    failure_mem.record_failure(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/api/v1/debug"},
        target="127.0.0.1",
        status_code=404,
        error_message="Not found",
    )
    history.record_action(
        action_id="act-01",
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/api/v1/debug"},
        target="127.0.0.1",
        expected_gain=1.5,
        actual_gain=0.0,
        cost=1.0,
        outcome=ActionOutcome.FAILURE,
    )

    # Later new evidence reveals API route mapping
    reconsidered = ReconsiderationEngine.evaluate_evidence_transition(
        target="127.0.0.1",
        new_evidence_content="Swagger documentation exposed with /api/v1/debug route active under dev header",
        history=history,
        failure_memory=failure_mem,
    )

    assert len(reconsidered) >= 1
    assert reconsidered[0].trigger == ReconsiderationTrigger.EVIDENCE_DISCOVERED
