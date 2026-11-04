"""
Phase 15 Tests: Targeted Mode Assessment Completion.
Verifies that TARGETED mode concludes promptly once primary objective is verified.
"""

from agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus
from agent.completion_engine import CompletionEngine, AssessmentMode, CompletionAction, BudgetSnapshot
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus


def test_targeted_mode_completion_on_verified_objective():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    graph = AttackGraph()
    engine = CompletionEngine(mode=AssessmentMode.TARGETED)

    # Set state as verified
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.add_evidence("Flag found", "exploit", "127.0.0.1")
    state.verification_started = True
    state.verification_success = True

    # Graph has 1 explored node
    h = graph.add_node(NodeKind.HOST, "127.0.0.1")
    h.status = NodeStatus.EXPLORED

    budget = BudgetSnapshot(iteration=5, tool_calls_used=5)
    decision = engine.evaluate(state, graph, budget, observations=[{"tool": "exploit"}], target="127.0.0.1")

    assert decision.action == CompletionAction.CONCLUDE_SUCCESS
    assert "objective verified" in decision.rationale.lower()
