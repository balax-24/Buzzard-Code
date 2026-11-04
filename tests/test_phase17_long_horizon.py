import pytest
from benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_long_horizon_1000_actions():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    assert report.turns_completed == 1000
    assert report.total_actual_gain > 0.0
    assert len(traces) == 1000
    assert report.false_useful_count == 0
