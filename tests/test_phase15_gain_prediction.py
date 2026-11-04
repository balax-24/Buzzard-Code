"""
Phase 15 Tests: Information Gain Prediction & Calibration.
Verifies predictive gain calculation, novelty scoring, and calibration adjustment.
"""

from intelligence.gain_predictor import GainPredictor
from intelligence.action_history import ActionHistoryStore, ActionOutcome
from intelligence.attack_graph import AttackGraph, NodeKind


def test_gain_prediction_on_novel_vs_explored():
    graph = AttackGraph()
    history = ActionHistoryStore()

    # Predict for novel endpoint
    novel_pred = GainPredictor.predict_expected_gain(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/api/v1/auth"},
        target="127.0.0.1",
        graph=graph,
        history=history,
        hypothesis_confidence="HIGH",
    )
    assert novel_pred.expected_gain >= 2.0
    assert novel_pred.novelty_score >= 0.8

    # Record 2 prior attempts with 0 gain
    for i in range(2):
        history.record_action(
            action_id=f"act-{i}",
            tool_name="http_request",
            parameters={"url": "http://127.0.0.1:8080/api/v1/auth"},
            target="127.0.0.1",
            expected_gain=2.0,
            actual_gain=0.0,
            cost=1.0,
            outcome=ActionOutcome.NO_OP,
        )

    # Predict again for same endpoint
    decayed_pred = GainPredictor.predict_expected_gain(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/api/v1/auth"},
        target="127.0.0.1",
        graph=graph,
        history=history,
        hypothesis_confidence="HIGH",
    )
    assert decayed_pred.expected_gain < novel_pred.expected_gain
    assert decayed_pred.novelty_score < 0.2
    assert decayed_pred.repetition_decay_factor < 0.3
