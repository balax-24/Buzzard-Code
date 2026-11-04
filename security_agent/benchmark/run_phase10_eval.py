"""
Phase 10 Benchmark Evaluation Runner.
Executes trials across local models in both RAW_MODEL and ASSISTED modes.
Saves results to phase10_results.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import asdict
from rich.console import Console

from security_agent.benchmark.autonomy_bench import (
    Phase10AutonomyBenchmarkHarness,
    Phase10TrialResult,
    format_phase10_table,
)
from security_agent.intelligence.decision import AutonomyMode


def run_phase10_evaluation():
    console = Console()
    console.print("[bold yellow]Starting Phase 10 Autonomy & Reasoning Benchmark...[/bold yellow]")

    models = ["qwythos:latest", "qwen-cyber:latest", "k3-sec:latest"]
    modes = [AutonomyMode.RAW_MODEL, AutonomyMode.ASSISTED]

    harness = Phase10AutonomyBenchmarkHarness()
    results = []

    for model in models:
        for mode in modes:
            console.print(f"[cyan]Evaluating model [bold]{model}[/bold] in [bold]{mode.value}[/bold] mode...[/cyan]")
            try:
                res = harness.run_benchmark_trial(model_name=model, mode=mode)
                results.append(res)
            except Exception as e:
                console.print(f"[red]Error evaluating {model} in {mode.value}: {e}[/red]")

    console.print("\n")
    table = format_phase10_table(results)
    console.print(table)

    # Save to phase10_results.json
    out_dir = Path("benchmarks/phase10")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "phase10_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    console.print(f"\n[green]Saved benchmark trial results to {out_path.resolve()}[/green]")


if __name__ == "__main__":
    run_phase10_evaluation()
