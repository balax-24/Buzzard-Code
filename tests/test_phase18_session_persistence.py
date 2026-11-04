import pytest
from agent.assessment_state import AssessmentContext, AssessmentState
from persistence.engagement_store import EngagementStore

def test_session_persistence_isolation(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state1 = AssessmentState(context=AssessmentContext(target="host-a", scope=["host-a"]))
    state1.sessions = {"host-a": "session_cookie_a_123"}
    store.checkpoint("eng-a", state1)

    state2 = AssessmentState(context=AssessmentContext(target="host-b", scope=["host-b"]))
    state2.sessions = {"host-b": "session_cookie_b_456"}
    store.checkpoint("eng-b", state2)

    l1, _, _, _, _, _ = store.load("eng-a")
    l2, _, _, _, _, _ = store.load("eng-b")

    assert l1.sessions.get("host-a") == "session_cookie_a_123"
    assert "host-b" not in l1.sessions
    assert l2.sessions.get("host-b") == "session_cookie_b_456"
    assert "host-a" not in l2.sessions
