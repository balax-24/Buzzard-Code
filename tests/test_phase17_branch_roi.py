import pytest
from security_agent.benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_branch_roi_measurement():
    report, _ = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    assert "Host A Web" in report.branch_rois
    assert "Host B Admin" in report.branch_rois
    assert "Host C DevOps" in report.branch_rois
    assert "Host D Vault" in report.branch_rois
