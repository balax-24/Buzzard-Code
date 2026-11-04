"""
Tests for budget enforcement and loop retry limits with browser operations.
"""

from agent.assessment_state import AssessmentStateMachine, AssessmentPhase


def test_browser_budget_and_retry_limits():
    sm = AssessmentStateMachine(max_tool_retries=2)
    tool_name = "browser.snapshot"

    # 1st failure -> retry
    msg1, phase1 = sm.record_tool_failure(tool_name, "Navigation Timeout")
    assert "Retry attempt 1/2" in msg1

    # 2nd failure -> threshold reached, pivot to alternative capability
    msg2, phase2 = sm.record_tool_failure(tool_name, "Navigation Timeout")
    assert "unavailable after 2 attempts" in msg2
    assert phase2 == AssessmentPhase.IDENTIFICATION
    assert sm.current_phase == AssessmentPhase.IDENTIFICATION
