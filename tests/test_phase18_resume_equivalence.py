import pytest
from benchmark.phase18_bench import Phase18PersistenceBenchmark

def test_exact_resumption_equivalence(tmp_path):
    report, base_st, res_st = Phase18PersistenceBenchmark.run_exact_resumption_benchmark(
        temp_workspace_dir=str(tmp_path / "resume_ws")
    )
    assert report.is_success
    assert report.canonical_state_match
    assert report.capabilities_match
    assert report.objectives_match
    assert report.action_history_match
