"""
Phase 16 Tests: Model Independence & Deterministic Candidate Ranking.
Proves that candidates are ranked by multi-attribute utility without relying on raw model bias.
"""

from agent.assessment_state import AssessmentContext, AssessmentState
from intelligence.action_history import ActionHistoryStore, ActionOutcome
from intelligence.action_selection import ActionSelectionEngine
from intelligence.attack_graph import AttackGraph
from intelligence.failure_memory import FailureAwareMemory
from intelligence.hypothesis_engine import HypothesisProposal, ProposalConfidence


def test_deterministic_candidate_ranking_filters_blocked_and_promotes_novel():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
    graph = AttackGraph()
    history = ActionHistoryStore()
    failure_memory = FailureAwareMemory()

    # Candidate 1: Blocked by 401
    failure_memory.record_failure("http_request", {"url": "http://127.0.0.1/admin"}, "127.0.0.1", status_code=401)
    prop1 = HypothesisProposal(
        hypothesis_id="h1", vulnerability_type="ADMIN_PROBE", target="127.0.0.1", port=80,
        tool_name="http_request", tool_args={"url": "http://127.0.0.1/admin"},
        rationale="Blocked admin probe", evidence_ids=[], confidence=ProposalConfidence.HIGH, priority=50, verification_plan="none"
    )

    # Candidate 2: Novel API endpoint
    prop2 = HypothesisProposal(
        hypothesis_id="h2", vulnerability_type="API_PROBE", target="127.0.0.1", port=80,
        tool_name="http_request", tool_args={"url": "http://127.0.0.1/api/v1/auth"},
        rationale="Novel auth endpoint probe", evidence_ids=[], confidence=ProposalConfidence.HIGH, priority=50, verification_plan="none"
    )

    candidates = ActionSelectionEngine.generate_candidates(
        state=state, graph=graph, proposals=[prop1, prop2], history=history, failure_memory=failure_memory
    )

    best = ActionSelectionEngine.select_best_candidate(candidates)
    assert best is not None
    assert best.arguments.get("url") == "http://127.0.0.1/api/v1/auth"
