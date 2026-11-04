"""
Tests for Phase 10 TARGETED Completion Mode.
Verifies:
1. In TARGETED mode, once primary objective is verified and relevant subpaths checked, the agent cleanly concludes.
"""

import pytest
from agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus
from intelligence.decision import CompletionMode
from agent.completion_engine import CompletionEngine, BudgetSnapshot


def test_targeted_completion_evaluation():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.completion_mode = CompletionMode.TARGETED.value
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True

    engine = CompletionEngine()
    budget = BudgetSnapshot(
        elapsed_seconds=100,
        max_seconds=3600,
        tool_calls_used=10,
        max_tool_calls=100,
        iteration=5,
        max_iterations=20
    )

    from intelligence.attack_graph import AttackGraph
    decision = engine.evaluate(
        state=state,
        graph=AttackGraph(),
        budget=budget,
        content="I have verified authenticated access to the target dashboard.",
        task_goal="Verify access to admin dashboard",
        target="target.local"
    )

    assert decision.should_conclude is True
    assert not decision.requires_verification
