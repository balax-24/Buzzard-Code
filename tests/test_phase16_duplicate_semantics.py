"""
Phase 16 Tests: Semantic Duplicate Detection & Decay.
Verifies repeated action with no state change decays gain to 0.
"""

from security_agent.intelligence.action_history import ActionHistoryStore, ActionOutcome
from security_agent.intelligence.gain_predictor import GainPredictor


def test_repeated_identical_action_decays_gain():
    history = ActionHistoryStore()

    # 1st attempt: novel action
    pred1 = GainPredictor.predict_expected_gain("http_request", {"url": "http://127.0.0.1/login"}, "127.0.0.1", history=history)
    assert pred1.expected_gain >= 1.0

    history.record_action("a1", "http_request", {"url": "http://127.0.0.1/login"}, "127.0.0.1", pred1.expected_gain, 1.0, 1.0, ActionOutcome.SUCCESS)

    # 2nd attempt: reduced gain
    pred2 = GainPredictor.predict_expected_gain("http_request", {"url": "http://127.0.0.1/login"}, "127.0.0.1", history=history)
    assert pred2.expected_gain < pred1.expected_gain

    history.record_action("a2", "http_request", {"url": "http://127.0.0.1/login"}, "127.0.0.1", pred2.expected_gain, 0.0, 1.0, ActionOutcome.NO_OP)

    # 3rd & 4th attempt: zero/negligible gain
    pred3 = GainPredictor.predict_expected_gain("http_request", {"url": "http://127.0.0.1/login"}, "127.0.0.1", history=history)
    assert pred3.expected_gain < 0.1
