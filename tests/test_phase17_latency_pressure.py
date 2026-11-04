import pytest
from security_agent.benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_latency_pressure_simulation():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    assert report.execution_time_seconds > 0.0
    assert report.is_success
