"""
Focused Benchmark Runner for Qwythos on Buzzard Code.

Evaluates qwythos:latest under:
1. RAW_MODEL vs BACKEND_ASSISTED
2. CONFIG_ALPHA (Nexus Gateway) vs CONFIG_BETA (Omni Ingest)
3. Horizon A (4 iterations) vs Horizon B (8 iterations)
"""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import List

from rich.panel import Panel
from rich.table import Table

from benchmark.p5_autonomy_bench import (
    P5AutonomyBenchmarkHarness,
    P5TrialMetrics,
)
from cli.renderer import console
from range.p5_unfamiliar_lab import (
    CONFIG_ALPHA,
    CONFIG_BETA,
    P5LabConfiguration,
)


def run_qwythos_matrix(
    output_path: str = "benchmarks/p5_qwythos_focused_results.json",
    horizons: List[int] = None,
    configs: List[P5LabConfiguration] = None,
    conditions: List[str] = None,
):
    if horizons is None:
        horizons = [4, 8]
    if configs is None:
        configs = [CONFIG_ALPHA, CONFIG_BETA]
    if conditions is None:
        conditions = ["RAW_MODEL", "BACKEND_ASSISTED"]

    model_name = "qwythos:latest"
    harness = P5AutonomyBenchmarkHarness()
    results: List[P5TrialMetrics] = []

    # Resume from existing if present
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                raw = json.load(f)
                console.print(f"[yellow]Loaded {len(raw)} existing results from {output_path}[/yellow]")
        except Exception:
            pass

    total_runs = len(conditions) * len(configs) * len(horizons)
    run_idx = 0

    console.print(
        Panel(
            f"[bold bright_white]QWYTHOS FOCUSED AUTONOMY & HORIZON BENCHMARK[/bold bright_white]\n\n"
            f"[cyan]Model:[/]        {model_name}\n"
            f"[cyan]Conditions:[/]   {', '.join(conditions)}\n"
            f"[cyan]Configs:[/]      {', '.join(c.config_id for c in configs)}\n"
            f"[cyan]Horizons:[/]     {', '.join(str(h) for h in horizons)} iterations\n"
            f"[cyan]Total Trials:[/] {total_runs}\n"
            f"[cyan]Output:[/]       {output_path}",
            title="[bold bright_yellow]QWYTHOS BENCHMARK INITIALIZATION[/bold bright_yellow]",
            border_style="bright_yellow",
        )
    )

    for horizon in horizons:
        for condition in conditions:
            for cfg in configs:
                run_idx += 1
                console.print(
                    f"\n[bold bright_cyan]═══════════════════════════════════════════════════════════════[/bold bright_cyan]\n"
                    f"[bold bright_yellow]▶ [{run_idx}/{total_runs}] Running: {model_name} | {condition} | {cfg.config_id} | Horizon: {horizon}[/bold bright_yellow]"
                )
                try:
                    metric = harness.run_trial(
                        model_name=model_name,
                        condition=condition,
                        lab_config=cfg,
                        trial_num=run_idx,
                        max_iterations=horizon,
                        quiet=True,
                    )
                    results.append(metric)

                    status_color = "green" if metric.objective_verified else ("yellow" if metric.objective_unverified else "red")
                    console.print(
                        f"  Result: [{status_color}]{metric.final_objective_status}[/{status_color}] | "
                        f"Proof Found: {metric.ground_truth_proof_found} | "
                        f"Tools: {metric.tool_calls_total} (failed: {metric.execution_failures}) | "
                        f"Model Dec: {metric.model_decisions_count} | Back Dec: {metric.backend_decisions_count} | "
                        f"Indep: {metric.decision_independence_pct:.1f}% | "
                        f"Gain: {metric.information_gain_total:.1f} | "
                        f"Time: {metric.total_runtime_s:.1f}s"
                    )
                except Exception as ex:
                    console.print(f"[bold red]Trial failed with exception: {ex}[/bold red]")
                    failed_metric = P5TrialMetrics(
                        model_name=model_name,
                        condition=condition,
                        config_id=cfg.config_id,
                        trial_num=run_idx,
                        max_iterations=horizon,
                        objective_failed=True,
                        failure_notes=str(ex),
                    )
                    results.append(failed_metric)

                # Persist intermediate results after each trial
                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
                with open(output_path, "w") as f:
                    json.dump([m.to_dict() for m in results], f, indent=2)

    console.print("\n[bold bright_green]✓ Qwythos Focused Benchmark Completed[/bold bright_green]")
    harness.render_scorecard(results)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Focused Qwythos Autonomy Benchmark")
    parser.add_argument("--output", default="benchmarks/p5_qwythos_focused_results.json")
    parser.add_argument("--horizons", nargs="+", type=int, default=[4, 8])
    args = parser.parse_args()

    run_qwythos_matrix(output_path=args.output, horizons=args.horizons)
