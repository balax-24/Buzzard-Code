"""
Phase 1-3 Tests: Action Selection Engine Utility Ranking & Sensitivity.

Validates that ActionSelectionEngine:
1. Produces deterministic, explainable rankings with machine-readable 'why_this_action' justifications.
2. Ranking changes appropriately with:
   - expected information gain changes
   - novelty changes (unseen vs repeated targets)
   - precondition failures (unmet capabilities block action and drop utility)
   - hypothesis relevance / confidence changes (HIGH vs LOW)
   - verification potential changes (verification bonus boosts ranking)
   - previous failure penalty increases (accumulated failures penalize utility)
   - operational cost changes (higher cost tools have lower efficiency and utility)
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
)
from security_agent.intelligence.action_selection import (
    ActionSelectionEngine,
    ActionCandidate,
    GainRecommendation,
)
from security_agent.intelligence.hypothesis_engine import (
    HypothesisProposal,
    ProposalConfidence,
)
from security_agent.intelligence.decision import DecisionRecord, DecisionSource
from security_agent.intelligence.action_history import ActionHistoryStore, ActionHistoryRecord
from security_agent.intelligence.attack_graph import AttackGraph, NodeStatus, NodeKind


def test_ranking_deterministic_and_explainable():
    """Ranking is strictly identical across multiple runs and contains explainable justifications."""
    state = AssessmentState(context=AssessmentContext(target="192.168.1.50"))
    state.record_service("192.168.1.50", 80, "http", evidence_id="EVI-001")
    state.record_service("192.168.1.50", 22, "ssh", evidence_id="EVI-002")

    proposals = [
        HypothesisProposal(
            hypothesis_id="HYP-WEB",
            vulnerability_type="WEB_PROBE",
            target="http://192.168.1.50:80/api",
            port=80,
            tool_name="http_request",
            tool_args={"method": "GET", "url": "http://192.168.1.50:80/api"},
            rationale="Probe API endpoint",
            evidence_ids=["EVI-001"],
            confidence=ProposalConfidence.HIGH,
        ),
        HypothesisProposal(
            hypothesis_id="HYP-SSH",
            vulnerability_type="SSH_ENUM",
            target="192.168.1.50",
            port=22,
            tool_name="nmap",
            tool_args={"target": "192.168.1.50", "ports": "22"},
            rationale="Enum SSH service",
            evidence_ids=["EVI-002"],
            confidence=ProposalConfidence.LOW,
        ),
    ]

    cands_1 = ActionSelectionEngine.generate_candidates(state, proposals=proposals)
    cands_2 = ActionSelectionEngine.generate_candidates(state, proposals=proposals)

    assert len(cands_1) == len(cands_2) == 2
    assert [c.candidate_id for c in cands_1] == [c.candidate_id for c in cands_2]
    assert [c.utility_score for c in cands_1] == [c.utility_score for c in cands_2]

    # Explainability: check why_this_action contains key decision dimensions
    for c in cands_1:
        assert c.why_this_action != ""
        assert "exp_gain=" in c.why_this_action
        assert "novelty=" in c.why_this_action
        assert "eff=" in c.why_this_action
        assert "stage=" in c.why_this_action


def test_ranking_sensitivity_to_information_gain():
    """Actions with higher expected information gain are ranked higher."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.1"))
    state.record_service("10.0.0.1", 80, "http", evidence_id="EVI-1")

    # High gain hypothesis proposal (high confidence on fresh surface)
    prop_high_gain = HypothesisProposal(
        hypothesis_id="HYP-HIGH",
        vulnerability_type="SQLI",
        target="http://10.0.0.1:80/search",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.1:80/search?q=test"},
        rationale="Probe high confidence sql injection",
        evidence_ids=["EVI-1"],
        confidence=ProposalConfidence.HIGH,
    )

    # Low gain hypothesis proposal (low confidence)
    prop_low_gain = HypothesisProposal(
        hypothesis_id="HYP-LOW",
        vulnerability_type="INFO_LEAK",
        target="http://10.0.0.1:80/search",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.1:80/search?q=info"},
        rationale="Generic low confidence check",
        evidence_ids=["EVI-1"],
        confidence=ProposalConfidence.LOW,
    )

    candidates = ActionSelectionEngine.generate_candidates(state, proposals=[prop_low_gain, prop_high_gain])
    assert len(candidates) == 2
    # The high gain proposal should be ranked first
    assert candidates[0].hypothesis_id == "HYP-HIGH"
    assert candidates[0].expected_information_gain >= candidates[1].expected_information_gain
    assert candidates[0].utility_score > candidates[1].utility_score


def test_ranking_sensitivity_to_novelty():
    """Unseen targets receive higher novelty and rank above already-probed targets."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.5"))
    history = ActionHistoryStore()

    # Record that /admin has already been probed 3 times
    for i in range(3):
        history.record_action(
            action_id=f"act-admin-{i}",
            tool_name="http_request",
            parameters={"url": "http://10.0.0.5/admin"},
            target="http://10.0.0.5/admin",
            expected_gain=1.0,
            actual_gain=0.1,
        )

    prop_seen = HypothesisProposal(
        hypothesis_id="HYP-SEEN",
        vulnerability_type="AUTH_BYPASS",
        target="http://10.0.0.5/admin",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.5/admin"},
        rationale="Repeated probe on /admin",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    prop_fresh = HypothesisProposal(
        hypothesis_id="HYP-FRESH",
        vulnerability_type="AUTH_BYPASS",
        target="http://10.0.0.5/api/v2/tokens",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.5/api/v2/tokens"},
        rationale="Fresh probe on unseen endpoint",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    candidates = ActionSelectionEngine.generate_candidates(
        state, proposals=[prop_seen, prop_fresh], history=history
    )
    assert len(candidates) == 2
    # Fresh candidate must rank first with higher novelty
    assert candidates[0].hypothesis_id == "HYP-FRESH"
    assert candidates[0].novelty_score > candidates[1].novelty_score
    assert candidates[0].utility_score > candidates[1].utility_score


def test_ranking_sensitivity_to_preconditions():
    """Unmet capability preconditions block the candidate and heavily penalize its utility."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.10"))

    # Proposal requiring AUTHENTICATED capability
    prop_gated = HypothesisProposal(
        hypothesis_id="HYP-GATED",
        vulnerability_type="PRIV_ESC",
        target="http://10.0.0.10/admin/settings",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.10/admin/settings"},
        rationale="Privilege escalation requiring admin auth",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        capability_context="CAP-ADMIN-AUTH",
    )

    # Proposal with no required capabilities
    prop_open = HypothesisProposal(
        hypothesis_id="HYP-OPEN",
        vulnerability_type="RECON",
        target="http://10.0.0.10/robots.txt",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.10/robots.txt"},
        rationale="Public recon",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    # State has no capabilities yet
    candidates = ActionSelectionEngine.generate_candidates(state, proposals=[prop_gated, prop_open])
    gated_cand = next(c for c in candidates if c.hypothesis_id == "HYP-GATED")
    open_cand = next(c for c in candidates if c.hypothesis_id == "HYP-OPEN")

    assert gated_cand.is_blocked_by_failure is True
    assert "missing capability" in gated_cand.block_reason
    assert gated_cand.utility_score < -50.0  # -100 penalty applied

    best = ActionSelectionEngine.select_best_candidate(candidates)
    assert best is not None
    assert best.hypothesis_id == "HYP-OPEN"

    # Now grant the capability to state and regenerate
    state.record_capability(
        capability_id="CAP-ADMIN-AUTH",
        capability_type=CapabilityType.AUTHENTICATED,
        source_evidence_id="EVI-AUTH",
        description="Admin auth token",
    )
    unblocked_cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop_gated, prop_open])
    new_gated = next(c for c in unblocked_cands if c.hypothesis_id == "HYP-GATED")
    assert new_gated.is_blocked_by_failure is False
    assert new_gated.utility_score > 0.0


def test_ranking_sensitivity_to_hypothesis_relevance():
    """Higher hypothesis confidence produces higher utility score."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.20"))

    prop_high = HypothesisProposal(
        hypothesis_id="HYP-HIGH-CONF",
        vulnerability_type="LFI",
        target="http://10.0.0.20/view",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.20/view?file=test"},
        rationale="Strong evidence LFI",
        evidence_ids=["EVI-LFI"],
        confidence=ProposalConfidence.HIGH,
    )

    prop_low = HypothesisProposal(
        hypothesis_id="HYP-LOW-CONF",
        vulnerability_type="LFI",
        target="http://10.0.0.20/view",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.20/view?file=other"},
        rationale="Speculative LFI",
        evidence_ids=[],
        confidence=ProposalConfidence.LOW,
    )

    cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop_low, prop_high])
    high_c = next(c for c in cands if c.hypothesis_id == "HYP-HIGH-CONF")
    low_c = next(c for c in cands if c.hypothesis_id == "HYP-LOW-CONF")

    assert high_c.utility_score > low_c.utility_score


def test_ranking_sensitivity_to_verification_potential():
    """Actions with verification plans receive a significant verification priority boost (+5.0)."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.30"))

    prop_exploratory = HypothesisProposal(
        hypothesis_id="HYP-EXP",
        vulnerability_type="RCE",
        target="http://10.0.0.30/cmd",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.30/cmd"},
        rationale="Explore command endpoint",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        verification_plan="",
    )

    prop_verifying = HypothesisProposal(
        hypothesis_id="HYP-VERIF",
        vulnerability_type="RCE",
        target="http://10.0.0.30/cmd",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.30/cmd?c=id"},
        rationale="Verify objective flag via command execution",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
        verification_plan="verify_command_execution_proof",
    )

    cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop_exploratory, prop_verifying])
    exp_c = next(c for c in cands if c.hypothesis_id == "HYP-EXP")
    verif_c = next(c for c in cands if c.hypothesis_id == "HYP-VERIF")

    assert verif_c.verification_value == "FULL"
    assert verif_c.utility_score > exp_c.utility_score + 4.0  # +5.0 bonus applied


def test_ranking_sensitivity_to_previous_failures():
    """Repeated failures on an action penalize its utility score (-5.0 per failure)."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.40"))

    # Record 2 failures for sqlmap_attack on 10.0.0.40
    state.record_action_attempt(
        tool_name="sqlmap_attack",
        args={"target": "http://10.0.0.40/db"},
        output_snippet="Failed: Target not injectable",
        success=False,
        target="http://10.0.0.40/db",
    )
    state.record_action_attempt(
        tool_name="sqlmap_attack",
        args={"target": "http://10.0.0.40/db"},
        output_snippet="Failed: WAF detected connection dropped",
        success=False,
        target="http://10.0.0.40/db",
    )

    prop_failed = HypothesisProposal(
        hypothesis_id="HYP-SQLI",
        vulnerability_type="SQLI",
        target="http://10.0.0.40/db",
        port=80,
        tool_name="sqlmap_attack",
        tool_args={"target": "http://10.0.0.40/db"},
        rationale="Retry SQL injection",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    prop_clean = HypothesisProposal(
        hypothesis_id="HYP-NOSQL",
        vulnerability_type="NOSQLI",
        target="http://10.0.0.40/search",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.40/search"},
        rationale="Fresh NoSQL probe",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop_failed, prop_clean])
    failed_c = next(c for c in cands if c.hypothesis_id == "HYP-SQLI")
    clean_c = next(c for c in cands if c.hypothesis_id == "HYP-NOSQL")

    assert failed_c.previous_failures >= 2
    assert clean_c.previous_failures == 0
    # Clean candidate should be prioritized far above the doubly-failed candidate
    assert clean_c.utility_score > failed_c.utility_score


def test_ranking_sensitivity_to_cost():
    """Higher cost tools yield lower expected efficiency and rank lower than lightweight equivalents."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.50"))

    # Lightweight tool (http_request has base cost ~0.5)
    prop_light = HypothesisProposal(
        hypothesis_id="HYP-LIGHT",
        vulnerability_type="ENUM",
        target="http://10.0.0.50/check",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.50/check"},
        rationale="Lightweight probe",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    # Heavyweight tool (sqlmap has base cost ~3.0)
    prop_heavy = HypothesisProposal(
        hypothesis_id="HYP-HEAVY",
        vulnerability_type="ENUM",
        target="http://10.0.0.50/check",
        port=80,
        tool_name="sqlmap",
        tool_args={"target": "http://10.0.0.50/check"},
        rationale="Heavy probe",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop_heavy, prop_light])
    heavy_c = next(c for c in cands if c.hypothesis_id == "HYP-HEAVY")
    light_c = next(c for c in cands if c.hypothesis_id == "HYP-LIGHT")

    assert light_c.estimated_cost_value < heavy_c.estimated_cost_value
    assert light_c.expected_efficiency > heavy_c.expected_efficiency
    assert light_c.utility_score > heavy_c.utility_score


def test_ranking_exhausted_candidates_not_selected():
    """Candidates on exhausted frontier nodes or with blocked failure states are not selected."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.60"))
    graph = AttackGraph()
    # Add an exhausted service node in the attack graph
    node = graph.add_node(
        kind=NodeKind.SERVICE,
        label="http://10.0.0.60/exhausted",
        metadata={"target": "http://10.0.0.60/exhausted"},
    )
    node.status = NodeStatus.EXHAUSTED

    prop_exhausted = HypothesisProposal(
        hypothesis_id="HYP-EXHAUSTED",
        vulnerability_type="ENUM",
        target="http://10.0.0.60/exhausted",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.60/exhausted"},
        rationale="Probe on exhausted surface",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    prop_active = HypothesisProposal(
        hypothesis_id="HYP-ACTIVE",
        vulnerability_type="ENUM",
        target="http://10.0.0.60/fresh",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.60/fresh"},
        rationale="Probe on active fresh surface",
        evidence_ids=[],
        confidence=ProposalConfidence.MEDIUM,
    )

    cands = ActionSelectionEngine.generate_candidates(state, graph=graph, proposals=[prop_exhausted, prop_active])
    exh_c = next(c for c in cands if c.hypothesis_id == "HYP-EXHAUSTED")
    act_c = next(c for c in cands if c.hypothesis_id == "HYP-ACTIVE")

    assert exh_c.frontier_stage == "EXHAUSTED"
    assert exh_c.is_blocked_by_failure is True
    assert "EXHAUSTED" in exh_c.block_reason

    # select_best_candidate must never choose the exhausted candidate
    best = ActionSelectionEngine.select_best_candidate(cands)
    assert best is not None
    assert best.hypothesis_id == "HYP-ACTIVE"

    # If only exhausted candidates remain, select_best_candidate returns None
    only_exhausted = ActionSelectionEngine.generate_candidates(state, graph=graph, proposals=[prop_exhausted])
    assert ActionSelectionEngine.select_best_candidate(only_exhausted) is None


def test_ranking_does_not_create_duplicate_actions():
    """Identical action proposals are deduplicated and do not produce duplicate candidates."""
    state = AssessmentState(context=AssessmentContext(target="10.0.0.70"))

    # Two identical proposals for the same tool, target, and arguments
    prop1 = HypothesisProposal(
        hypothesis_id="HYP-DUP-1",
        vulnerability_type="SQLI",
        target="http://10.0.0.70/api/users",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.70/api/users", "method": "GET"},
        rationale="First probe",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
    )
    prop2 = HypothesisProposal(
        hypothesis_id="HYP-DUP-2",
        vulnerability_type="SQLI",
        target="http://10.0.0.70/api/users",
        port=80,
        tool_name="http_request",
        tool_args={"url": "http://10.0.0.70/api/users", "method": "GET"},
        rationale="Duplicate probe",
        evidence_ids=[],
        confidence=ProposalConfidence.HIGH,
    )

    cands = ActionSelectionEngine.generate_candidates(state, proposals=[prop1, prop2])
    # Must contain only 1 candidate, deduplicated
    assert len(cands) == 1
    assert cands[0].target == "http://10.0.0.70/api/users"
    assert cands[0].tool == "http_request"
