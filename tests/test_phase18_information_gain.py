import pytest
from intelligence.action_history import ActionHistoryStore
from agent.assessment_state import AssessmentContext, AssessmentState
from persistence.engagement_store import EngagementStore

def test_information_gain_history_persistence(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-gain", scope=["target-gain"]))
    hist = ActionHistoryStore()
    hist.record_action(
        action_id="act-1",
        tool_name="http_request",
        parameters={"url": "http://10.0.0.1/a"},
        target="10.0.0.1",
        expected_gain=5.0,
        actual_gain=8.0,
        cost=1.0,
    )

    store.checkpoint("eng-gain", state, history=hist)
    _, _, loaded_hist, _, _, _ = store.load("eng-gain")

    assert len(loaded_hist.records) == 1
    assert loaded_hist.records[0].actual_gain == 8.0
