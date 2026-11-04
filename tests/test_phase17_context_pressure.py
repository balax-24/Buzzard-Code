import pytest
from benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_context_pressure_simulation():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    # At turn 1000, state retention should remain intact
    assert len(traces) == 1000
    assert report.hosts_compromised == 4
