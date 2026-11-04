import pytest
from benchmark.phase18_bench import Phase18PersistenceBenchmark

def test_model_independent_resumption():
    # Exact resumption benchmark executes deterministically without LLM calls
    report, base_payload, res_payload = Phase18PersistenceBenchmark.run_exact_resumption_benchmark()
    assert report.is_success
    assert report.canonical_state_match
    assert base_payload["schema_version"] == "1.1"
    assert res_payload["schema_version"] == "1.1"
