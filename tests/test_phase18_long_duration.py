import pytest
from benchmark.phase18_bench import Phase18PersistenceBenchmark

def test_10_checkpoint_long_duration_benchmark(tmp_path):
    report, chk_count = Phase18PersistenceBenchmark.run_long_duration_10_checkpoint_benchmark(
        temp_workspace_dir=str(tmp_path / "long_ws")
    )
    assert report.is_success
    assert chk_count == 10
    assert report.uninterrupted_turns == 100
    assert report.capabilities_match
    assert report.objectives_match
