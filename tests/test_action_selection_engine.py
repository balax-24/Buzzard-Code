"""
Tests for Phase 11 Action Selection Engine.
Verifies:
1. Multi-attribute candidate generation from proposals.
2. Information gain decay and recommendation badge assignment.
3. Candidate comparison formatting for prompt exposure.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.intelligence.action_selection import (
    ActionSelectionEngine,
    GainRecommendation,
)
from security_agent.intelligence.decision import DecisionRecord, DecisionSource


def test_action_selection_candidate_generation():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.record_service("127.0.0.1", 8080, "http", evidence_id="EVI-001")

    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, max_proposals=3)

    candidates = ActionSelectionEngine.generate_candidates(state, proposals=proposals)
    assert len(candidates) >= 1
    
    top = candidates[0]
    assert top.gain_recommendation == GainRecommendation.HIGH_GAIN
    assert top.expected_information_gain > 1.0
    summary = top.to_prompt_summary()
    assert "Tool:" in summary
    assert "Gain Rating:" in summary


def test_action_selection_decays_repeated_actions():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.record_service("127.0.0.1", 8080, "http", evidence_id="EVI-001")

    # Record 2 prior attempts of sqlmap_attack on 127.0.0.1:8080
    for i in range(2):
        state.record_decision(DecisionRecord(
            iteration=i+1,
            source=DecisionSource.MODEL,
            selected_tool="sqlmap_attack",
            target="http://127.0.0.1:8080"
        ))

    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, max_proposals=3)
    candidates = ActionSelectionEngine.generate_candidates(state, proposals=proposals)
    
    repeated = next((c for c in candidates if c.tool == "sqlmap_attack"), None)
    if repeated:
        assert repeated.previous_attempts >= 2
        assert repeated.gain_recommendation == GainRecommendation.ZERO_GAIN
        assert repeated.expected_information_gain < 0.1
