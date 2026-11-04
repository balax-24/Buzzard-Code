"""
Phase 14 Tests: Long-Horizon Deterministic Trajectory Execution.
Evaluates agent state preservation across 128 turns with periodic checkpoints and crash recoveries.
"""

from benchmark.phase14_bench import Phase14DeterministicBenchmark


def test_128_turn_trajectory_with_crash_injection():
    bench = Phase14DeterministicBenchmark(turns=128, checkpoint_interval=16, inject_crashes=True)
    summary = bench.run()

    assert summary.status == "PASS"
    assert summary.turns_executed == 128
    assert summary.checkpoints_created == 8
    assert summary.checkpoints_restored == 4
    assert summary.crashes_recovered == 4
    assert summary.invariant_violations == 0
    assert summary.total_information_gain > 15.0
