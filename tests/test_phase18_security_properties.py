import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_cross_engagement_security_isolation(tmp_path):
    store = EngagementStore(base_dir=tmp_path)

    # Engagement 1
    state1 = AssessmentState(context=AssessmentContext(target="target1", scope=["target1"]))
    state1.credentials = {"secret_key": "KEY_1"}
    store.checkpoint("eng-1", state1)

    # Engagement 2
    state2 = AssessmentState(context=AssessmentContext(target="target2", scope=["target2"]))
    state2.credentials = {"secret_key": "KEY_2"}
    store.checkpoint("eng-2", state2)

    l1, _, _, _, _, _ = store.load("eng-1")
    l2, _, _, _, _, _ = store.load("eng-2")

    assert l1.credentials["secret_key"] == "KEY_1"
    assert l2.credentials["secret_key"] == "KEY_2"
