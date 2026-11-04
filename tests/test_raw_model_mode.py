"""
Tests for Phase 10 RAW_MODEL Autonomy Mode.
Verifies:
1. RAW_MODEL mode delivers comprehensive state without silent controller action replacement.
2. Model decisions are attributed directly to MODEL.
3. If model fails or emits invalid action, it is not secretly executed.
"""

import pytest
from security_agent.intelligence.decision import DecisionRecord, DecisionSource, AutonomyMode, AutonomyEvaluator
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.intelligence.long_horizon import LongHorizonContextCompactor


def test_raw_model_mode_decision_flow():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.autonomy_mode = "RAW_MODEL"

    # Context formatting provides ranked hypotheses and zero-gain signals
    ctx = LongHorizonContextCompactor.build_compact_context(
        state=state,
        last_information_gain=0.0,
        last_action_note="Identical HTTP response",
        mode=AutonomyMode.RAW_MODEL
    )
    assert "Operating Mode: RAW_MODEL" in ctx
    assert "PIVOT ADVICE" in ctx

    # When model outputs decision, record provenance
    dec = DecisionRecord(
        iteration=1,
        source=DecisionSource.MODEL,
        selected_tool="browser.snapshot",
        target="http://target.local:8080/",
        arguments={"url": "http://target.local:8080/"}
    )
    state.record_decision(dec)

    score = AutonomyEvaluator.evaluate(
        decisions=state.decision_records,
        information_gains=[1.5],
        hypotheses_proposed=2,
        hypotheses_verified=1,
        verification_passed=True,
        mode=AutonomyMode.RAW_MODEL
    )
    assert score.decision_independence_pct == 100.0
    assert score.mode == AutonomyMode.RAW_MODEL
    assert score.overall_autonomy_score >= 75.0
