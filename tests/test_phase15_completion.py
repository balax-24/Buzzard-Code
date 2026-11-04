"""
Phase 15 Tests: Completion Engine Decision Integration.
Verifies completion decisions under various frontier, verification, and budget conditions.
"""

from agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus
from agent.completion_engine import CompletionEngine, AssessmentMode, CompletionAction, BudgetSnapshot
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus


def test_completion_engine_demands_verification_before_conclusion():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    graph = AttackGraph()
    engine = CompletionEngine(mode=AssessmentMode.TARGETED)

    # Finding discovered in state, but independent verification not completed
    state.add_evidence("Vulnerability observed", "sqli_probe", "127.0.0.1")
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
    state.verification_started = False
    state.verification_success = False

    budget = BudgetSnapshot(iteration=4, tool_calls_used=4)
    decision = engine.evaluate(state, graph, budget, observations=[{"tool": "sqli_probe"}], target="127.0.0.1")

    assert decision.action == CompletionAction.VERIFY
    assert decision.requires_verification is True
