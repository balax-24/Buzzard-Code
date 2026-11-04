"""
Controlled Horizon Study Runner for Qwythos on Buzzard Code.

Varies decision horizon budget (e.g. 8, 16, 24 iterations) under identical:
- Model: qwythos:latest (8.95B)
- Hardware: NVIDIA RTX 4050 Laptop GPU (CUDA offloaded)
- Tool registry: Focused assessment registry (21 tools)
- Prompt template: Canonical DerivedContextView
- Lab topology: P5 Unfamiliar Lab (CONFIG_ALPHA / CONFIG_BETA)

Determines whether task failure is due to decision budget exhaustion
or a fundamental multi-hop reasoning ceiling.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import List

from rich.panel import Panel
from rich.table import Table

from security_agent.benchmark.p5_autonomy_bench import (
    P5AutonomyBenchmarkHarness,
    P5TrialMetrics,
)
from security_agent.cli.renderer import console
from security_agent.range.p5_unfamiliar_lab import (
    CONFIG_ALPHA,
    CONFIG_BETA,
    P5LabConfiguration,
)


def run_horizon_study(
    horizons: List[int] = None,
    config: P5LabConfiguration = None,
    output_path: str = "benchmarks/qwythos_horizon_study_results.json",
    condition: str = "BACKEND_ASSISTED",
):
    if horizons is None:
        horizons = [8, 16, 24]
    if config is None:
        config = CONFIG_ALPHA

    model_name = "qwythos:latest"
    harness = P5AutonomyBenchmarkHarness()
    results: List[P5TrialMetrics] = []

    console.print(
        Panel(
            f"[bold bright_white]QWYTHOS CONTROLLED HORIZON STUDY (8 vs 16 vs 24)[/bold bright_white]\n\n"
            f"[cyan]Model:[/]      {model_name}\n"
            f"[cyan]Condition:[/]  {condition}\n"
            f"[cyan]Topology:[/]   {config.config_id}\n"
            f"[cyan]Horizons:[/]   {', '.join(str(h) for h in horizons)} iterations\n"
            f"[cyan]Output:[/]     {output_path}",
            title="[bold bright_yellow]HORIZON STUDY INITIALIZATION[/bold bright_yellow]",
            border_style="bright_yellow",
        )
    )

    for idx, horizon in enumerate(horizons, 1):
        console.print(
            f"\n[bold bright_cyan]═══════════════════════════════════════════════════════════════[/bold bright_cyan]\n"
            f"[bold bright_yellow]▶ [{idx}/{len(horizons)}] Running Horizon: {horizon} Iterations[/bold bright_yellow]"
        )
        try:
            metric = harness.run_trial(
                model_name=model_name,
                condition=condition,
                lab_config=config,
                trial_num=idx,
                max_iterations=horizon,
                quiet=True,
            )
            results.append(metric)

            status_color = "green" if metric.objective_verified else ("yellow" if metric.objective_unverified else "red")
            console.print(
                f"  Horizon {horizon} Result: [{status_color}]{metric.final_objective_status}[/{status_color}] | "
                f"Proof Found: {metric.ground_truth_proof_found} | "
                f"Tools: {metric.tool_calls_total} | "
                f"Redundant Actions: {metric.redundant_actions} | "
                f"Info Gain: {metric.information_gain_total:.1f} | "
                f"Primary Failure: {metric.primary_failure_category} | "
                f"Runtime: {metric.total_runtime_s:.1f}s"
            )
        except Exception as ex:
            console.print(f"[bold red]Trial failed with exception: {ex}[/bold red]")
            failed_metric = P5TrialMetrics(
                model_name=model_name,
                condition=condition,
                config_id=config.config_id,
                trial_num=idx,
                max_iterations=horizon,
                objective_failed=True,
                failure_notes=str(ex),
            )
            results.append(failed_metric)

        # Save incremental progress
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            json.dump([m.to_dict() for m in results], f, indent=2)

    console.print("\n[bold bright_green]✓ Horizon Study Execution Complete[/bold bright_green]")
    harness.render_scorecard(results)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Qwythos Controlled Horizon Study")
    parser.add_argument("--horizons", nargs="+", type=int, default=[8, 16, 24])
    parser.add_argument("--output", default="benchmarks/qwythos_horizon_study_results.json")
    args = parser.parse_args()

    run_horizon_study(horizons=args.horizons, output_path=args.output)
