import pytest
from agent.completion_engine import AssessmentMode
from benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_targeted_mode_execution():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark(mode=AssessmentMode.TARGETED)
    assert report.turns_completed == 1000
    assert report.is_success
