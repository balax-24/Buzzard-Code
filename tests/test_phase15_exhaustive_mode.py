"""
Phase 15 Tests: Exhaustive Mode Assessment Surface Coverage.
Verifies that EXHAUSTIVE mode continues exploring remaining authorized surface before terminating.
"""

from agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus, ServiceState, ServiceRecord
from agent.completion_engine import CompletionEngine, AssessmentMode, CompletionAction, BudgetSnapshot
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus


def test_exhaustive_mode_continues_until_surface_exhausted():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    graph = AttackGraph()
    engine = CompletionEngine(mode=AssessmentMode.EXHAUSTIVE)

    # 1. Objective is verified, BUT an uninvestigated service exists
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_started = True
    state.verification_success = True
    state.services[80] = ServiceRecord(host="127.0.0.1", port=80, protocol="tcp", service="http", state=ServiceState.OPEN, investigated=True)
    state.services[8080] = ServiceRecord(host="127.0.0.1", port=8080, protocol="tcp", service="http-proxy", state=ServiceState.OPEN, investigated=False)

    budget = BudgetSnapshot(iteration=6, tool_calls_used=6)
    decision = engine.evaluate(state, graph, budget, observations=[{"tool": "exploit"}], target="127.0.0.1")

    # Must CONTINUE to explore port 8080
    assert decision.action == CompletionAction.CONTINUE
    assert "8080" in decision.rationale or "open service" in decision.rationale or "exhaustive" in decision.rationale.lower()

    # 2. Now investigate port 8080
    state.services[8080].investigated = True
    decision2 = engine.evaluate(state, graph, budget, observations=[{"tool": "exploit"}], target="127.0.0.1")

    # Now concludes surface exhausted!
    assert decision2.action == CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED
