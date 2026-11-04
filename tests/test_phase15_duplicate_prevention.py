"""
Phase 15 Tests: Duplicate Prevention & Decay.
Verifies that redundant probes on already explored assets decay sharply while novel actions rank high.
"""

from agent.assessment_state import AssessmentState, AssessmentContext
from intelligence.action_selection import ActionSelectionEngine, GainRecommendation
from intelligence.action_history import ActionHistoryStore, ActionOutcome
from intelligence.hypothesis_engine import HypothesisProposal, ProposalConfidence


def test_repeated_action_decay_in_candidate_selection():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    history = ActionHistoryStore()

    # Record 3 identical probes with 0 gain
    for i in range(3):
        history.record_action(
            action_id=f"act-{i}",
            tool_name="http_request",
            parameters={"url": "http://127.0.0.1:8080/home"},
            target="127.0.0.1",
            expected_gain=1.0,
            actual_gain=0.0,
            cost=1.0,
            outcome=ActionOutcome.NO_OP,
        )

    # Now create 2 proposals: 1 repeated (/home) and 1 completely novel (/admin/upload)
    p_repeated = HypothesisProposal(
        hypothesis_id="hyp-repeated",
        vulnerability_type="PROBE",
        target="127.0.0.1",
        port=8080,
        tool_name="http_request",
        tool_args={"url": "http://127.0.0.1:8080/home"},
        rationale="Probe home page again",
        evidence_ids=[],
        confidence=ProposalConfidence.LOW,
        priority=50,
        verification_plan="none"
    )
    p_novel = HypothesisProposal(
        hypothesis_id="hyp-novel",
        vulnerability_type="UNAUTHENTICATED_UPLOAD",
        target="127.0.0.1",
        port=8080,
        tool_name="http_request",
        tool_args={"url": "http://127.0.0.1:8080/admin/upload"},
        rationale="Discover file upload endpoint",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        priority=50,
        verification_plan="none"
    )

    candidates = ActionSelectionEngine.generate_candidates(
        state=state,
        proposals=[p_repeated, p_novel],
        history=history,
    )

    assert len(candidates) == 2
    # The novel candidate must be ranked first with higher utility score
    best = ActionSelectionEngine.select_best_candidate(candidates)
    assert best is not None
    assert best.hypothesis_id == "hyp-novel"
    assert best.novelty_score > 0.7
    assert best.gain_recommendation in (GainRecommendation.HIGH_GAIN, GainRecommendation.MEDIUM_GAIN)

    # The repeated candidate should have low novelty and low expected gain
    repeated_cand = next(c for c in candidates if c.hypothesis_id == "hyp-repeated")
    assert repeated_cand.novelty_score < 0.1
    assert repeated_cand.gain_recommendation == GainRecommendation.ZERO_GAIN
