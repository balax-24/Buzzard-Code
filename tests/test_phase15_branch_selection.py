"""
Phase 15 Tests: Branch Prioritization & 3-Branch Convergence.
Verifies that the branch manager selects branches with highest ROI and information gain rather than round-robin.
"""

from security_agent.intelligence.branches import BranchManager, BranchPriority


def test_3_branch_roi_convergence():
    bm = BranchManager()

    # Branch A: Low information, high cost
    b_a = bm.create_branch("Branch A (Low Gain)", "127.0.0.1:22", BranchPriority.LOW, expected_gain="LOW")
    b_a.total_gain = 0.5
    b_a.cost_incurred = 10.0
    b_a.tool_calls_used = 10

    # Branch B: Medium information
    b_b = bm.create_branch("Branch B (Medium Gain)", "127.0.0.1:443", BranchPriority.MEDIUM, expected_gain="MEDIUM")
    b_b.total_gain = 4.0
    b_b.cost_incurred = 4.0
    b_b.tool_calls_used = 4

    # Branch C: High information, low cost
    b_c = bm.create_branch("Branch C (High Gain)", "127.0.0.1:80", BranchPriority.HIGH, expected_gain="HIGH")
    b_c.total_gain = 18.0
    b_c.cost_incurred = 3.0
    b_c.tool_calls_used = 3

    # Calculate scores
    score_a = bm.calculate_branch_priority_score(b_a)
    score_b = bm.calculate_branch_priority_score(b_b)
    score_c = bm.calculate_branch_priority_score(b_c)

    assert score_c > score_b > score_a

    # Manager must choose Branch C
    best = bm.get_best_next_branch()
    assert best is not None
    assert best.branch_id == b_c.branch_id
