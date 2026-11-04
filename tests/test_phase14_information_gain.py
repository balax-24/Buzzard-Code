"""
Phase 14 Tests: Information Gain & Action Decay.
Verifies computation of information gain, action normalization, decay on repeated probes, and branch ROI ranking.
"""

from intelligence.information_gain import (
    InformationGainEngine,
)
from intelligence.branches import BranchManager, BranchPriority


def test_action_normalization():
    # HTTP requests across tool syntaxes
    k1 = InformationGainEngine.normalize_action("http_request", {"url": "http://127.0.0.1:8080/api/v1/users?page=1", "method": "GET"})
    k2 = InformationGainEngine.normalize_action("http_client", {"url": "http://127.0.0.1:8080/api/v1/users?page=1", "method": "GET"})
    assert k1 == k2 == "HTTP:GET:http://127.0.0.1:8080/api/v1/users?page=1"

    # Scans
    k3 = InformationGainEngine.normalize_action("nmap", {"target": "127.0.0.1", "ports": "80,443"})
    assert k3 == "SCAN:127.0.0.1:80,443"


def test_information_gain_decay():
    engine = InformationGainEngine()

    # First execution: Discovered 2 new nodes and 1 evidence
    delta_1 = {"new_nodes": 2, "new_edges": 2, "new_evidence": 1, "new_capabilities": 0, "new_findings": 0}
    gain_1 = engine.calculate_and_record_gain(
        tool_name="nmap",
        target="127.0.0.1",
        parameters={"target": "127.0.0.1"},
        state_delta=delta_1,
        cost=1.0,
        branch_id="branch-1"
    )
    assert gain_1 > 0.0

    # Second execution of same action: Identical or no new info
    delta_2 = {"new_nodes": 0, "new_edges": 0, "new_evidence": 0, "new_capabilities": 0, "new_findings": 0}
    gain_2 = engine.calculate_and_record_gain(
        tool_name="nmap",
        target="127.0.0.1",
        parameters={"target": "127.0.0.1"},
        state_delta=delta_2,
        cost=1.0,
        branch_id="branch-1"
    )
    assert gain_2 == 0.0

    # Verify repetition count and decay factor
    canon_key = InformationGainEngine.normalize_action("nmap", {"target": "127.0.0.1"})
    assert engine.seen_action_keys[canon_key] == 2
    assert engine.get_decay_factor("nmap", {"target": "127.0.0.1"}) < 1.0


def test_branch_prioritization_by_roi():
    bm = BranchManager()
    b1 = bm.create_branch("Web Frontend", "http://127.0.0.1:80", BranchPriority.HIGH, expected_gain="HIGH")
    b2 = bm.create_branch("SSH Port", "127.0.0.1:22", BranchPriority.LOW, expected_gain="LOW")

    # Web frontend produced high gain with low cost
    b1.total_gain = 15.0
    b1.cost_incurred = 3.0
    b1.turns_spent = 3

    # SSH produced 0 gain with high cost
    b2.total_gain = 0.0
    b2.cost_incurred = 5.0
    b2.turns_spent = 5

    best = bm.get_best_next_branch()
    assert best is not None
    assert best.branch_id == b1.branch_id
    assert bm.calculate_branch_priority_score(b1) > bm.calculate_branch_priority_score(b2)
