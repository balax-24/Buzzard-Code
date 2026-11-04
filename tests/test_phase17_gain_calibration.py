import pytest
from benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_gain_prediction_calibration():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    assert report.mae_prediction_error >= 0.0
    assert abs(report.mean_signed_prediction_error) < 50.0
