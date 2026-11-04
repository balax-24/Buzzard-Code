from security_agent.intelligence.action_history import ActionHistoryStore, ActionOutcome
from security_agent.intelligence.failure_memory import FailureAwareMemory
from security_agent.intelligence.reconsideration import ReconsiderationEngine, ReconsiderationTrigger


def test_evidence_change_triggers_reconsideration():
    history = ActionHistoryStore()
    failure_memory = FailureAwareMemory()

    # Record previously failed / unpromising action
    failure_memory.record_failure("http_request", {"url": "http://127.0.0.1:8080/api/v1/auth"}, "127.0.0.1", status_code=500)
    history.record_action(
        "act-1", "http_request", {"url": "http://127.0.0.1:8080/api/v1/auth"}, "127.0.0.1",
        expected_gain=2.0, actual_gain=0.0, cost=1.0, outcome=ActionOutcome.FAILURE
    )

    recons = ReconsiderationEngine.evaluate_evidence_transition(
        target="127.0.0.1",
        new_evidence_content="Discovered debug endpoint exposing internal authentication token in body",
        history=history,
        failure_memory=failure_memory,
    )

    assert len(recons) >= 1
    top = recons[0]
    assert top.trigger == ReconsiderationTrigger.EVIDENCE_DISCOVERED
    assert top.canonical_action_key == "HTTP:GET:http://127.0.0.1:8080/api/v1/auth"
