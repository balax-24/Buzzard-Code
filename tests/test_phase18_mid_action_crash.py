import pytest
from intelligence.action_history import ActionHistoryStore, ActionOutcome

def test_mid_action_crash_unknown_outcome():
    store = ActionHistoryStore()
    store.record_action(
        action_id="act-crash-1",
        tool_name="http_request",
        parameters={"url": "http://10.0.0.1/api"},
        target="10.0.0.1",
        expected_gain=5.0,
        actual_gain=0.0,
        cost=1.0,
        outcome=ActionOutcome.FAILURE,
        why_this_action="Crash test",
    )
    rec = store.records[0]
    assert rec.outcome == ActionOutcome.FAILURE
