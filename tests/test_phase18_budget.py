import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_budget_accounting_persistence(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-bgt", scope=["target-bgt"]))
    budget_data = {
        "iterations_used": 70,
        "max_iterations": 100,
        "tool_calls_used": 140,
        "max_tool_calls": 200,
        "cost_incurred": 70.0,
    }
    store.checkpoint("eng-bgt", state, budget_info=budget_data)
    _, _, _, _, _, raw = store.load("eng-bgt")

    b_loaded = raw.get("budget", {})
    assert b_loaded["iterations_used"] == 70
    assert b_loaded["max_iterations"] - b_loaded["iterations_used"] == 30
