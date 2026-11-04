import pytest
from security_agent.agent.completion_engine import AssessmentMode
from security_agent.benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_exhaustive_mode_execution():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark(mode=AssessmentMode.EXHAUSTIVE)
    assert report.turns_completed == 1000
    assert report.unique_actions_count > 50
    assert report.hosts_compromised == 4
