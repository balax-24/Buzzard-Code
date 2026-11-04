"""
Phase 15 Tests: Action History & Empirical Outcome Store.
Verifies queryable action auditing, outcome retrieval, and serialization.
"""

from security_agent.intelligence.action_history import ActionHistoryStore, ActionOutcome


def test_record_action_and_repetition_count():
    store = ActionHistoryStore()
    
    rec1 = store.record_action(
        action_id="act-01",
        tool_name="nmap",
        parameters={"target": "127.0.0.1", "ports": "80"},
        target="127.0.0.1",
        expected_gain=2.0,
        actual_gain=2.0,
        cost=1.0,
        outcome=ActionOutcome.SUCCESS,
    )
    assert rec1.repeated_count == 1
    assert store.get_repetition_count(rec1.canonical_action_key) == 1

    rec2 = store.record_action(
        action_id="act-02",
        tool_name="nmap",
        parameters={"target": "127.0.0.1", "ports": "80"},
        target="127.0.0.1",
        expected_gain=0.5,
        actual_gain=0.0,
        cost=1.0,
        outcome=ActionOutcome.NO_OP,
    )
    assert rec2.repeated_count == 2
    assert store.get_repetition_count(rec1.canonical_action_key) == 2
    assert store.get_last_outcome(rec1.canonical_action_key) == ActionOutcome.NO_OP


def test_history_metrics_and_calibration():
    store = ActionHistoryStore()
    
    store.record_action(
        action_id="act-01",
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1/api"},
        target="127.0.0.1",
        expected_gain=3.0,
        actual_gain=1.0,
        cost=2.0,
        outcome=ActionOutcome.SUCCESS,
    )
    store.record_action(
        action_id="act-02",
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1/admin"},
        target="127.0.0.1",
        expected_gain=2.0,
        actual_gain=0.0,
        cost=1.0,
        outcome=ActionOutcome.NO_OP,
    )

    assert store.get_recent_noop_rate() == 0.5
    # Avg pred error = (|3.0 - 1.0| + |2.0 - 0.0|) / 2 = (2.0 + 2.0)/2 = 2.0
    assert store.get_average_prediction_error() == 2.0


def test_history_serialization_roundtrip():
    store = ActionHistoryStore()
    store.record_action(
        action_id="act-01",
        tool_name="sqlmap",
        parameters={"url": "http://127.0.0.1/login", "param": "user"},
        target="127.0.0.1",
        expected_gain=5.0,
        actual_gain=4.5,
        cost=3.0,
        outcome=ActionOutcome.SUCCESS,
        evidence_created=["evi-sqli-01"],
        why_this_action="Investigate SQLi on login parameter",
    )

    data = store.to_dict()
    restored = ActionHistoryStore.from_dict(data)

    assert len(restored.records) == 1
    assert restored.records[0].action_id == "act-01"
    assert restored.records[0].evidence_created == ["evi-sqli-01"]
    assert restored.records[0].why_this_action == "Investigate SQLi on login parameter"
