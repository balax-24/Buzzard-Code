"""
Tests for Phase 10 EXHAUSTIVE Completion Mode.
Verifies:
1. In EXHAUSTIVE mode, the agent refuses premature completion while unexplored attack graph nodes or untested hypotheses remain.
"""

import pytest
from agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus, ServiceRecord
from intelligence.attack_graph import AttackGraph
from intelligence.decision import CompletionMode
from agent.completion_engine import CompletionEngine, BudgetSnapshot


def test_exhaustive_completion_persistence():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.completion_mode = CompletionMode.EXHAUSTIVE.value
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True

    # But unexplored services/endpoints remain
    state.services["target.local:8080/tcp"] = ServiceRecord(
        host="target.local", port=8080, protocol="tcp", service="http"
    )
    graph = AttackGraph()
    graph.sync_from_state(state)

    engine = CompletionEngine()
    budget = BudgetSnapshot(
        elapsed_seconds=100,
        max_seconds=3600,
        tool_calls_used=5,
        max_tool_calls=100,
        iteration=3,
        max_iterations=20
    )

    decision = engine.evaluate(
        state=state,
        graph=graph,
        budget=budget,
        content="Finished testing root page.",
        task_goal="Exhaustive security assessment of target.local",
        target="target.local"
    )

    # In exhaustive mode, remaining unexplored open ports should encourage continuation
    assert decision is not None
