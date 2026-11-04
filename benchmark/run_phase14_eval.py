"""
CLI Runner for Phase 14 Reliability & Production Hardening Benchmark.
Runs 128, 256, and 512-turn deterministic evaluations with state invariant checks.
"""

from __future__ import annotations

import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from benchmark.phase14_bench import Phase14DeterministicBenchmark


def run_evaluation():
    console = Console()
    console.print(Panel("[bold cyan]Qwythos Phase 14 Long-Running Agent Reliability & Invariants Benchmark[/bold cyan]\n"
                        "Evaluating 128, 256, and 512-turn deterministic trajectories with crash injection and state invariants."))

    table = Table(title="Phase 14 Reliability Benchmark Results", show_header=True, header_style="bold magenta")
    table.add_column("Horizon (Turns)", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Checkpoints (Save/Restore)", justify="center")
    table.add_column("Invariants Violated", justify="center")
    table.add_column("Total Info Gain", justify="right")
    table.add_column("Avg Gain/Action", justify="right")
    table.add_column("Dup Action Rate", justify="right")
    table.add_column("Execution Time", justify="right")

    horizons = [128, 256, 512]
    all_passed = True

    for h in horizons:
        console.print(f"[bold yellow]Running {h}-turn deterministic evaluation...[/bold yellow]")
        bench = Phase14DeterministicBenchmark(turns=h, checkpoint_interval=16, inject_crashes=True)
        res = bench.run()

        status_str = "[bold green]PASS[/bold green]" if res.is_success else "[bold red]FAIL[/bold red]"
        if not res.is_success:
            all_passed = False

        table.add_row(
            str(res.turns_completed),
            status_str,
            f"{res.checkpoints_created} / {res.checkpoints_restored}",
            f"{res.invariant_violations_count} (0 tolerated)",
            f"{res.total_information_gain:.1f}",
            f"{res.average_gain_per_action:.2f}",
            f"{res.duplicate_action_rate:.1%}",
            f"{res.execution_time_seconds:.2f}s"
        )

    console.print("\n")
    console.print(table)

    if all_passed:
        console.print("\n[bold green]ALL PHASE 14 BENCHMARKS COMPLETED WITH ZERO INVARIANT VIOLATIONS![/bold green]")
        return 0
    else:
        console.print("\n[bold red]SOME BENCHMARKS FAILED![/bold red]")
        return 1


if __name__ == "__main__":
    sys.exit(run_evaluation())
