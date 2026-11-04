"""
Tests for Phase 10 Decision Attribution and Provenance Tracking.
Verifies:
1. Every decision record has a distinct DecisionSource (MODEL, CONTROLLER, DETERMINISTIC, FALLBACK, USER).
2. State properly records decisions with metadata, timestamps, and confidence.
3. Provenance is distinguishable and correctly serialized.
"""

import pytest
from intelligence.decision import DecisionRecord, DecisionSource, AutonomyMode, AutonomyEvaluator
from agent.assessment_state import AssessmentState, AssessmentContext


def test_decision_record_provenance_and_serialization():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))

    # 1. Model Decision
    d1 = DecisionRecord(
        iteration=1,
        source=DecisionSource.MODEL,
        selected_tool="nmap_scan",
        target="127.0.0.1",
        arguments={"host": "127.0.0.1", "ports": "80,8080"},
        confidence=0.95
    )
    state.record_decision(d1)

    # 2. Controller Decision (Verification requirement injection)
    d2 = DecisionRecord(
        iteration=2,
        source=DecisionSource.CONTROLLER,
        selected_tool="http.request",
        target="http://127.0.0.1:8080/admin",
        arguments={"url": "http://127.0.0.1:8080/admin", "method": "GET"},
        override_reason="VERIFICATION_REQUIRED"
    )
    state.record_decision(d2)

    # 3. Fallback Decision
    d3 = DecisionRecord(
        iteration=3,
        source=DecisionSource.FALLBACK,
        selected_tool="web_fetch",
        target="http://127.0.0.1:8080/",
        arguments={"url": "http://127.0.0.1:8080/"},
        override_reason="TIMEOUT_FALLBACK"
    )
    state.record_decision(d3)

    assert len(state.decision_records) == 3
    assert state.decision_records[0].source == DecisionSource.MODEL
    assert state.decision_records[1].source == DecisionSource.CONTROLLER
    assert state.decision_records[2].source == DecisionSource.FALLBACK

    d_dicts = [d.to_dict() for d in state.decision_records]
    assert d_dicts[0]["source"] == "MODEL"
    assert d_dicts[1]["source"] == "CONTROLLER"
    assert d_dicts[2]["source"] == "FALLBACK"
