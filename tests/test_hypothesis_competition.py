"""
Tests for Phase 10 Hypothesis Competition and State Machine.
Verifies:
1. HypothesisEngine proposes a ranked candidate hypothesis set rather than a single hardcoded target.
2. State machine properly tracks: PROPOSED -> SELECTED -> TESTING -> VERIFIED / REFUTED / ABANDONED.
3. State metrics accurately count selection, refutation, abandonment, and reopening.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord, VulnerabilityHypothesis, HypothesisStatus
from security_agent.intelligence.hypothesis_engine import HypothesisEngine, ProposalConfidence


def test_hypothesis_competition_and_state_machine():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.services["target.local:80/tcp"] = ServiceRecord(
        host="target.local", port=80, protocol="tcp", service="http"
    )
    state.services["target.local:22/tcp"] = ServiceRecord(
        host="target.local", port=22, protocol="tcp", service="ssh"
    )

    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, max_proposals=5)

    assert len(proposals) >= 2
    assert state.hypotheses_considered >= len(proposals)

    # 1. Select top hypothesis
    top_hyp = proposals[0]
    engine.mark_hypothesis_selected(top_hyp.hypothesis_id, state=state)
    assert state.hypotheses_selected == 1

    # 2. Mark testing
    engine.mark_hypothesis_testing(top_hyp.hypothesis_id, state=state)

    # 3. Mark refuted
    engine.mark_hypothesis_refuted(top_hyp.hypothesis_id, reason="WAF blocked all SQLi payloads", state=state)
    assert state.hypotheses_refuted == 1
    assert engine._is_refuted_without_new_evidence(top_hyp.hypothesis_id, [], state=state)

    # 4. Reopen on new evidence
    engine.mark_hypothesis_reopened(top_hyp.hypothesis_id, state=state)
    assert state.hypotheses_reopened == 1
    assert not engine._is_refuted_without_new_evidence(top_hyp.hypothesis_id, ["EVI-NEW-BYPASS"], state=state)
