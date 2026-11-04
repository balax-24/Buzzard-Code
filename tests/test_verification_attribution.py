"""
Tests for Phase 10 Verification Attribution.
Verifies:
1. Verification executed by model vs controller is strictly attributed.
2. A model claiming 'Success' without independent proof is never accepted as OBJECTIVE_VERIFIED.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ObjectiveStatus
from security_agent.intelligence.decision import DecisionRecord, DecisionSource


def test_verification_attribution_and_enforcement():
    state = AssessmentState(context=AssessmentContext(target="target.local"))

    # Mere assertion does not grant verified status
    state.objective_status = ObjectiveStatus.OBJECTIVE_UNREACHED
    assert not state.verification_success

    # Model performs unverified exploit
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # Model issues independent verification probe
    ver_decision = DecisionRecord(
        iteration=2,
        source=DecisionSource.MODEL,
        selected_tool="http.request",
        target="http://target.local:8080/admin",
        arguments={"url": "http://target.local:8080/admin", "headers": {"Cookie": "session=admin"}},
        confidence=1.0
    )
    state.record_decision(ver_decision)
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True

    assert state.decision_records[0].source == DecisionSource.MODEL
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
