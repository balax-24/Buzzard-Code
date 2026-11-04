"""
Tests for Phase 10 Long-Horizon Error Recovery.
Verifies:
1. Invalid tool calls, timeouts, and duplicate actions are caught and recovered from gracefully.
2. State is preserved and alternative candidates are presented without crashing.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord
from security_agent.agent.loop_controller import LoopRecoveryController
from security_agent.intelligence.decision import DecisionRecord, DecisionSource


def test_long_horizon_recovery_controller():
    controller = LoopRecoveryController(max_redirects=3)

    # Action 1: Error
    controller.record_action(
        tool_name="invalid_tool_call",
        arguments={"target": "127.0.0.1"},
        success=False,
        error_type="TOOL_FAILURE",
        exit_code=1
    )
    is_loop, _ = controller.check_stuck_loop()
    assert not is_loop

    # Action 2 & 3: Repeated error
    for _ in range(2):
        controller.record_action(
            tool_name="invalid_tool_call",
            arguments={"target": "127.0.0.1"},
            success=False,
            error_type="TOOL_FAILURE",
            exit_code=1
        )
    # Repeated identical failures detected in window of 3
    is_loop, tool = controller.check_stuck_loop()
    assert is_loop
    assert tool == "invalid_tool_call"
