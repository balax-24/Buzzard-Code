import pytest
from intelligence.noop_detector import ActionDelta
from benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_information_gain_strictly_delta_based():
    delta_zero = ActionDelta()
    gain_zero = Phase17LongHorizonBenchmark.calculate_delta_gain(delta_zero, "NO_INFORMATION")
    assert gain_zero == 0.0

    delta_findings = ActionDelta(new_findings_count=1)
    gain_findings = Phase17LongHorizonBenchmark.calculate_delta_gain(delta_findings, "NEW_FINDING")
    assert gain_findings > 0.0
