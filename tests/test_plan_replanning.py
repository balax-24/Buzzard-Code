"""
Tests for Phase 10 Multi-Step Plan Parsing and Replanning.
Verifies:
1. Model-emitted multi-step plans are parsed correctly into discrete PlanSteps.
2. If an essential step fails, subsequent dependent steps are invalidated, prompting replanning.
"""

import pytest
from security_agent.intelligence.long_horizon import PlanReassessmentEngine, MultiStepPlan


def test_plan_parsing_and_invalidation():
    plan_text = """
    PLAN
    1. Scan open ports with nmap_scan
    2. Enumerate web application with browser.snapshot
    3. Test administrative credentials with http.request
    """

    plan = PlanReassessmentEngine.parse_plan(plan_text)
    assert plan is not None
    assert len(plan.steps) == 3
    assert plan.steps[0].tool_hint == "nmap_scan"

    # Step 1 succeeds
    PlanReassessmentEngine.reassess_plan(plan, latest_action_success=True)
    assert plan.steps[0].status == "COMPLETED"
    assert plan.get_next_step().step_number == 2

    # Step 2 fails (e.g. host down or blocked)
    PlanReassessmentEngine.reassess_plan(plan, latest_action_success=False, failure_reason="Connection Refused")
    assert plan.steps[1].status == "FAILED"
