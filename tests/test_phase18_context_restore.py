import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind
from security_agent.intelligence.branches import BranchManager
from security_agent.intelligence.failure_memory import FailureAwareMemory
from security_agent.persistence.engagement_store import ResumeContextBuilder

def test_resume_context_builder_decision_relevance():
    state = AssessmentState(context=AssessmentContext(target="192.168.1.10", scope=["192.168.1.10"]))
    state.add_capability("AUTHENTICATED", "Test")
    state.credentials = {"jwt": "ey..."}

    graph = AttackGraph()
    graph.add_node(NodeKind.HOST, "192.168.1.10")

    branch_mgr = BranchManager()
    fail_mem = FailureAwareMemory()

    ctx = ResumeContextBuilder.build_resume_context(
        state=state,
        graph=graph,
        branch_mgr=branch_mgr,
        failure_mem=fail_mem,
        budget={"max_iterations": 100, "iterations_used": 20, "max_tool_calls": 200, "tool_calls_used": 40},
    )

    assert ctx["target"] == "192.168.1.10"
    assert "AUTHENTICATED" in ctx["active_capabilities"]
    assert "jwt" in ctx["credentials_available"]
    assert ctx["budget_remaining"]["iterations_left"] == 80
    assert ctx["budget_remaining"]["tool_calls_left"] == 160
