"""
Tests for Phase 10 ASSISTED Mode.
Verifies:
1. ASSISTED mode records CONTROLLER / FALLBACK provenance when assisting the model.
2. Evaluator distinguishes between model-driven and assisted actions.
"""

import pytest
from intelligence.decision import DecisionRecord, DecisionSource, AutonomyMode, AutonomyEvaluator
from agent.assessment_state import AssessmentState, AssessmentContext


def test_assisted_mode_attribution():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.autonomy_mode = "ASSISTED"

    # Action 1: Model picked
    state.record_decision(DecisionRecord(
        iteration=1,
        source=DecisionSource.MODEL,
        selected_tool="nmap_scan",
        target="target.local"
    ))

    # Action 2: Controller assisted (verification requirement)
    state.record_decision(DecisionRecord(
        iteration=2,
        source=DecisionSource.CONTROLLER,
        selected_tool="http.request",
        target="http://target.local:8080/admin",
        override_reason="VERIFICATION_REQUIRED"
    ))

    # Action 3: Fallback assisted (timeout)
    state.record_decision(DecisionRecord(
        iteration=3,
        source=DecisionSource.FALLBACK,
        selected_tool="web_fetch",
        target="http://target.local:8080/",
        override_reason="TIMEOUT_RECOVERY"
    ))

    score = AutonomyEvaluator.evaluate(
        decisions=state.decision_records,
        information_gains=[1.0, 0.8, 0.2],
        hypotheses_proposed=3,
        hypotheses_verified=1,
        verification_passed=True,
        mode=AutonomyMode.ASSISTED
    )
    assert score.model_decisions == 1
    assert score.controller_decisions == 1
    assert score.fallback_decisions == 1
    assert score.decision_independence_pct == pytest.approx(33.33, 0.1)
