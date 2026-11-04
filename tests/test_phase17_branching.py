import pytest
from security_agent.intelligence.branches import BranchManager, BranchPriority
from security_agent.benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_branching_graph_creation_and_roi():
    mgr = BranchManager()
    b1 = mgr.create_branch("Host A Web", "192.168.1.10", BranchPriority.HIGH)
    b2 = mgr.create_branch("Host B Admin", "192.168.1.20", BranchPriority.MEDIUM)

    b1.total_gain = 40.0
    b1.cost_incurred = 10.0
    assert b1.roi == 4.0

    b2.total_gain = 10.0
    b2.cost_incurred = 20.0
    assert b2.roi == 0.5
    assert b1.roi > b2.roi
