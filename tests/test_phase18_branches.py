import pytest
from agent.assessment_state import AssessmentContext, AssessmentState
from intelligence.branches import BranchManager, BranchPriority
from persistence.engagement_store import EngagementStore

def test_branch_state_persistence(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-br", scope=["target-br"]))
    branch_mgr = BranchManager()
    b1 = branch_mgr.create_branch("Host A Branch", "192.168.1.10", BranchPriority.HIGH)
    b1.total_gain = 50.0
    b1.cost_incurred = 10.0

    store.checkpoint("eng-br", state, branch_mgr=branch_mgr)
    _, _, _, _, loaded_bm, _ = store.load("eng-br")

    assert len(loaded_bm.branches) == 1
    loaded_b = list(loaded_bm.branches.values())[0]
    assert loaded_b.name == "Host A Branch"
    assert loaded_b.roi == 5.0
