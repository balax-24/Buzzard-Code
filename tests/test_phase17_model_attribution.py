import pytest
from security_agent.benchmark.phase17_bench import Phase17LongHorizonBenchmark

def test_model_decision_attribution():
    report, traces = Phase17LongHorizonBenchmark.run_1000_action_benchmark()
    for tr in traces[:10]:
        assert hasattr(tr, "selected_by_model")
        assert hasattr(tr, "selected_by_backend")
        assert hasattr(tr, "backend_fallback")
        assert hasattr(tr, "schema_repaired")
        assert hasattr(tr, "duplicate_blocked")
