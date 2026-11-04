"""
Phase 16 Tests: Benchmark Metrics Validation & Sanity Constraints.
Proves that no metric inconsistencies exist between unique, duplicate, and useful action rates.
"""

from benchmark.phase16_bench import Phase16InvestigationBenchmark


def test_metric_consistency():
    m100, _ = Phase16InvestigationBenchmark.run_100_action_benchmark()

    # Sum of unique and duplicate rates must equal 100%
    assert round(m100.unique_action_rate + m100.duplicate_action_rate, 1) == 100.0

    # Useful actions + no-info actions must equal completed turns
    assert m100.useful_actions_count + m100.no_information_actions_count == m100.turns_completed

    # Actual gain must be >= 0
    assert m100.total_actual_gain >= 0.0

    # No false useful actions
    assert m100.false_useful_count == 0
