"""
Phase 11 Benchmark Evaluation Runner.
Executes A/B testing between Phase 10 Baseline and Phase 11 Optimized architectures.
Saves results and raw traces to benchmarks/phase11/.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import asdict
from rich.console import Console

from benchmark.phase11_bench import (
    Phase11BenchmarkHarness,
    Phase11TrialResult,
    format_phase11_table,
)
from intelligence.decision import AutonomyMode


def run_phase11_evaluation():
    console = Console()
    console.print("[bold yellow]Starting Phase 11 Cognitive & Planner Optimization Benchmark...[/bold yellow]")

    models = ["qwythos:latest", "qwen-cyber:latest", "k3-sec:latest"]
    architectures = ["BASELINE_PHASE10", "OPTIMIZED_PHASE11"]
    modes = [AutonomyMode.RAW_MODEL, AutonomyMode.ASSISTED]

    harness = Phase11BenchmarkHarness()
    results: list[Phase11TrialResult] = []

    out_dir = Path("benchmarks/phase11")
    out_dir.mkdir(parents=True, exist_ok=True)

    for model in models:
        for arch in architectures:
            for mode in modes:
                console.print(f"[cyan]Testing [bold]{model}[/bold] | [bold]{arch}[/bold] | [bold]{mode.value}[/bold]...[/cyan]")
                try:
                    res = harness.run_trial(model_name=model, architecture=arch, mode=mode)
                    results.append(res)
                except Exception as e:
                    console.print(f"[red]Error evaluating {model} on {arch}: {e}[/red]")

    console.print("\n")
    table = format_phase11_table(results)
    console.print(table)

    # Save results and traces
    results_path = out_dir / "phase11_results.json"
    traces_path = out_dir / "phase11_traces.json"

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    traces_data = {
        f"{r.model_name}_{r.architecture}_{r.mode}": {
            "autonomy_score": r.autonomy_score,
            "decision_independence": r.decision_independence_pct,
            "raw_trace": r.raw_trace
        }
        for r in results
    }
    with open(traces_path, "w", encoding="utf-8") as f:
        json.dump(traces_data, f, indent=2)

    console.print(f"\n[green]Saved benchmark results to {results_path.resolve()}[/green]")
    console.print(f"[green]Saved raw model traces to {traces_path.resolve()}[/green]")


if __name__ == "__main__":
    run_phase11_evaluation()
