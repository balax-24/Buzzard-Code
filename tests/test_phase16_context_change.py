"""
Phase 16 Tests: Justified Reconsideration via Capability Context Change.
Proves that GET /admin + UNAUTHENTICATED is different from GET /admin + AUTHENTICATED.
"""

from security_agent.intelligence.action_history import ActionHistoryStore, ActionOutcome
from security_agent.intelligence.action_identity import ActionIdentity
from security_agent.intelligence.gain_predictor import GainPredictor


def test_capability_context_change_rejuvenates_action():
    history = ActionHistoryStore()

    # Attempt 1: Unauthenticated
    ctx_unauth = ActionIdentity.create_context_signature([])
    history.record_action(
        "act-1", "http_request", {"url": "http://127.0.0.1/admin"}, "127.0.0.1",
        expected_gain=2.0, actual_gain=0.0, cost=1.0, outcome=ActionOutcome.FAILURE,
        capability_context=ctx_unauth
    )

    # Re-predict in same context: decayed
    pred_decayed = GainPredictor.predict_expected_gain(
        "http_request", {"url": "http://127.0.0.1/admin"}, "127.0.0.1",
        history=history, current_capabilities=set()
    )
    assert pred_decayed.expected_gain < 0.2

    # Context Change: Acquire AUTHENTICATED
    pred_rejuvenated = GainPredictor.predict_expected_gain(
        "http_request", {"url": "http://127.0.0.1/admin"}, "127.0.0.1",
        history=history, current_capabilities={"AUTHENTICATED"}
    )
    assert pred_rejuvenated.expected_gain >= 1.0
    assert pred_rejuvenated.repetition_decay_factor >= 0.8
