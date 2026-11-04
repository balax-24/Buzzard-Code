"""
Phase 15 Tests: 100-Action Efficiency & 500-Action Long Horizon.
Verifies decision quality, evolving action distribution, and metrics over long horizons.
"""

from benchmark.phase15_bench import Phase15InvestigationBenchmark


def test_100_action_efficiency_benchmark():
    metrics = Phase15InvestigationBenchmark.run_100_action_efficiency_test()
    assert metrics.status == "PASS"
    assert metrics.turns_completed == 50
    assert metrics.useful_actions_count >= 10
    assert metrics.unique_action_rate > 0.70
    assert metrics.duplicate_action_rate < 0.30
    assert metrics.total_actual_gain > 20.0


def test_500_action_long_horizon_benchmark():
    metrics = Phase15InvestigationBenchmark.run_500_action_long_horizon()
    assert metrics.status == "PASS"
    assert metrics.turns_completed == 500
    assert metrics.unique_actions_count >= 100
    assert metrics.best_branch_roi > 0.5
    assert metrics.total_actual_gain > 100.0
