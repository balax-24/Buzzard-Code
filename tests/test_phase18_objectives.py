import pytest
from agent.assessment_state import AssessmentContext, AssessmentState, ObjectiveStatus
from persistence.engagement_store import EngagementStore

def test_objective_state_persistence(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-obj", scope=["target-obj"]))
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True

    store.checkpoint("eng-obj", state)
    loaded, _, _, _, _, _ = store.load("eng-obj")

    assert loaded.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert loaded.verification_success is True
