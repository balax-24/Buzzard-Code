"""
Phase 15 Tests: Model-Independent Action Selection Fixture.
Verifies that the engine deterministically ranks and selects the highest-quality candidate
without LLM invocation.
"""

from agent.assessment_state import AssessmentState, AssessmentContext
from intelligence.action_selection import ActionSelectionEngine
from intelligence.action_history import ActionHistoryStore, ActionOutcome
from intelligence.failure_memory import FailureAwareMemory
from intelligence.hypothesis_engine import HypothesisProposal, ProposalConfidence


def test_deterministic_candidate_ranking_fixture():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    history = ActionHistoryStore()
    failure_memory = FailureAwareMemory()

    # Candidate A: Blocked by 401 failure
    failure_memory.record_failure("http_request", {"url": "http://127.0.0.1/admin"}, "127.0.0.1", status_code=401)
    prop_a = HypothesisProposal(
        hypothesis_id="hyp-A",
        vulnerability_type="ADMIN_ACCESS",
        target="127.0.0.1",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://127.0.0.1/admin"},
        rationale="Probe blocked admin",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        priority=50,
        verification_plan="none"
    )

    # Candidate B: Repeated 3 times with 0 gain (low novelty)
    for i in range(3):
        history.record_action(
            action_id=f"act-b-{i}",
            tool_name="http_request",
            parameters={"url": "http://127.0.0.1/about"},
            target="127.0.0.1",
            expected_gain=1.0,
            actual_gain=0.0,
            cost=1.0,
            outcome=ActionOutcome.NO_OP,
        )
    prop_b = HypothesisProposal(
        hypothesis_id="hyp-B",
        vulnerability_type="INFO_LEAK",
        target="127.0.0.1",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://127.0.0.1/about"},
        rationale="Probe about page again",
        evidence_ids=[],
        confidence=ProposalConfidence.LOW,
        priority=50,
        verification_plan="none"
    )

    # Candidate C: Brand new endpoint with high confidence (High novelty, high efficiency)
    prop_c = HypothesisProposal(
        hypothesis_id="hyp-C",
        vulnerability_type="API_DISCOVERY",
        target="127.0.0.1",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://127.0.0.1/api/v1/products"},
        rationale="Discover product API catalog",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        priority=50,
        verification_plan="none"
    )

    candidates = ActionSelectionEngine.generate_candidates(
        state=state,
        proposals=[prop_a, prop_b, prop_c],
        history=history,
        failure_memory=failure_memory,
    )

    # Assert selection
    best = ActionSelectionEngine.select_best_candidate(candidates)
    assert best is not None
    assert best.hypothesis_id == "hyp-C"
    assert best.is_blocked_by_failure is False

    # Verify candidate A is marked blocked
    cand_a = next(c for c in candidates if c.hypothesis_id == "hyp-A")
    assert cand_a.is_blocked_by_failure is True
    assert "Missing AUTHENTICATED" in cand_a.block_reason
