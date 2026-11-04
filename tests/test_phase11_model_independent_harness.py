"""
Tests for Phase 11 Model-Independent Scripted Harness.
Verifies the end-to-end flow from candidate selection -> tool validation -> self-repair -> verification.
"""

import pytest
from agent.assessment_state import AssessmentState, AssessmentContext
from intelligence.tool_reliability import ToolCallParser, ToolCallValidator
from intelligence.planner_prompt import PlannerPromptBuilder
from intelligence.decision import DecisionRecord, DecisionSource, AutonomyEvaluator, AutonomyMode


def test_scripted_model_decision_and_self_repair_flow():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.autonomy_mode = "RAW_MODEL"

    # Step 1: Model outputs malformed/synonym arguments (target_url instead of url)
    mock_raw_output_1 = """
    I will scan for SQL injection.
    ```json
    {
      "thought": "Testing login endpoint",
      "tool": "sqlmap_attack",
      "arguments": {"target_url": "http://127.0.0.1:8080/login"}
    }
    ```
    """
    parsed_1 = ToolCallParser.parse(mock_raw_output_1)
    assert parsed_1 is not None
    is_valid, error = ToolCallValidator.validate(parsed_1)
    assert not is_valid
    assert "Expected canonical parameter name 'url'" in error

    # Step 2: System feeds back structured error and Model self-repairs
    feedback_prompt = PlannerPromptBuilder.build_user_prompt(state=state, validation_error=error)
    assert "TOOL_ARGUMENT_ERROR" in feedback_prompt

    mock_raw_output_2 = """
    Correcting parameter to canonical 'url'.
    ```json
    {
      "thought": "Repaired parameter to canonical 'url'",
      "tool": "sqlmap_attack",
      "arguments": {"url": "http://127.0.0.1:8080/login"}
    }
    ```
    """
    parsed_2 = ToolCallParser.parse(mock_raw_output_2)
    assert parsed_2 is not None
    is_valid_2, error_2 = ToolCallValidator.validate(parsed_2)
    assert is_valid_2
    assert error_2 is None

    # Step 3: Record Decision with full MODEL provenance
    state.record_decision(DecisionRecord(
        iteration=1,
        source=DecisionSource.MODEL,
        selected_tool=parsed_2.tool_name,
        target="http://127.0.0.1:8080/login",
        arguments=parsed_2.arguments
    ))

    score = AutonomyEvaluator.evaluate(
        decisions=state.decision_records,
        information_gains=[1.8],
        hypotheses_proposed=2,
        hypotheses_verified=1,
        verification_passed=True,
        mode=AutonomyMode.RAW_MODEL
    )
    assert score.decision_independence_pct == 100.0
    assert score.overall_autonomy_score >= 75.0
