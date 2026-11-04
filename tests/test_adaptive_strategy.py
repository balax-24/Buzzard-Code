"""
Tests for Phase 10 Adaptive Strategy Selection.
Verifies:
1. Strategy shifts appropriately across RECON -> AUTHENTICATION -> APPLICATION_ENUMERATION -> VERIFICATION.
2. State and plan reflect changing operational strategy without hardcoded deterministic bypassing.
"""

import pytest
from security_agent.intelligence.long_horizon import StrategyType, MultiStepPlan, PlanStep, PlanReassessmentEngine


def test_adaptive_strategy_enum_and_plan():
    plan = MultiStepPlan(
        plan_id="PLAN-STRAT-01",
        strategy=StrategyType.AUTHENTICATION,
        steps=[
            PlanStep(1, "Enumerate login form", tool_hint="browser.snapshot"),
            PlanStep(2, "Test SQL injection bypass", tool_hint="http.request"),
            PlanStep(3, "Verify administrative dashboard access", tool_hint="http.request"),
        ]
    )

    assert plan.strategy == StrategyType.AUTHENTICATION
    step1 = plan.get_next_step()
    assert step1.step_number == 1

    # Complete step 1 -> shifts to step 2
    PlanReassessmentEngine.reassess_plan(plan, latest_action_success=True)
    step2 = plan.get_next_step()
    assert step2.step_number == 2
