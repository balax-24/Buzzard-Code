"""
Phase 16 Tests: Long-Horizon 100-Action & 500-Action Horizon Verification.
"""

from security_agent.benchmark.phase16_bench import Phase16InvestigationBenchmark


def test_100_action_benchmark_execution():
    metrics, traces = Phase16InvestigationBenchmark.run_100_action_benchmark()
    assert metrics.is_success is True
    assert metrics.turns_completed == 100
    assert metrics.false_useful_count == 0
    assert len(traces) == 100


def test_500_action_benchmark_execution():
    metrics, traces = Phase16InvestigationBenchmark.run_500_action_benchmark()
    assert metrics.is_success is True
    assert metrics.turns_completed == 500
    assert metrics.false_useful_count == 0
    assert len(traces) == 500
