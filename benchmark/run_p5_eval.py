"""
CLI Runner for the P5 Real Model-Driven Autonomy Benchmark.

Executes trials across local models:
- Qwythos (qwythos:latest)
- Qwen Cyber (qwen-cyber:latest)
- K3-Sec (k3-sec:latest)

Under both conditions:
- RAW_MODEL
- BACKEND_ASSISTED

Across both unfamiliar configurations:
- CONFIG_ALPHA (Nexus Gateway)
- CONFIG_BETA (Omni Ingest)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
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


def parse_args():
    parser = argparse.ArgumentParser(description="P5 Real Model-Driven Autonomy Benchmark")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["qwythos:latest", "qwen-cyber:latest", "k3-sec:latest"],
        help="List of model names in Ollama",
    )
    parser.add_argument(
        "--conditions",
        nargs="+",
        default=["RAW_MODEL", "BACKEND_ASSISTED"],
        help="Conditions to test: RAW_MODEL, BACKEND_ASSISTED",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=3,
        help="Trials per model/condition",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Max iterations per trial",
    )
    parser.add_argument(
        "--configs",
        nargs="+",
        default=["alpha", "beta"],
        help="Lab configurations to test (alpha, beta)",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/p5_benchmark_results.json",
        help="Path to save JSON benchmark results",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    configs: List[P5LabConfiguration] = []
    if "alpha" in args.configs:
        configs.append(CONFIG_ALPHA)
    if "beta" in args.configs:
        configs.append(CONFIG_BETA)
    if not configs:
        configs = [CONFIG_ALPHA]

    console.print(
        Panel(
            f"[bold bright_white]BUZZARD CODE — P5 REAL MODEL-DRIVEN AUTONOMY BENCHMARK[/bold bright_white]\n\n"
            f"[cyan]Models:[/]     {', '.join(args.models)}\n"
            f"[cyan]Conditions:[/] {', '.join(args.conditions)}\n"
            f"[cyan]Trials:[/]     {args.trials} per configuration\n"
            f"[cyan]Configs:[/]    {', '.join(c.config_id for c in configs)}\n"
            f"[cyan]Output:[/]     {args.output}",
            title="[bold bright_yellow]BENCHMARK MATRIX INITIALIZATION[/bold bright_yellow]",
            border_style="bright_yellow",
        )
    )

    harness = P5AutonomyBenchmarkHarness()
    results: List[P5TrialMetrics] = []

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    total_runs = len(args.models) * len(args.conditions) * len(configs) * args.trials
    run_idx = 0

    for model in args.models:
        for condition in args.conditions:
            for cfg in configs:
                for trial_num in range(1, args.trials + 1):
                    run_idx += 1
                    console.print(
                        f"\n[bold bright_cyan]═══════════════════════════════════════════════════════════════[/bold bright_cyan]\n"
                        f"[bold bright_yellow]▶ [{run_idx}/{total_runs}] Running Trial: {model} | {condition} | {cfg.config_id} | Trial {trial_num}[/bold bright_yellow]"
                    )
                    t0 = time.time()
                    try:
                        metric = harness.run_trial(
                            model_name=model,
                            condition=condition,
                            lab_config=cfg,
                            trial_num=trial_num,
                            max_iterations=args.iterations,
                            quiet=True,
                        )
                        results.append(metric)

                        # Live feedback
                        status_color = "green" if metric.objective_verified else ("yellow" if metric.objective_unverified else "red")
                        console.print(
                            f"  Result: [{status_color}]{metric.final_objective_status}[/{status_color}] | "
                            f"Proof Found: {metric.ground_truth_proof_found} | "
                            f"Tools: {metric.tool_calls_total} (failed: {metric.execution_failures}) | "
                            f"Info Gain: {metric.information_gain_total:.1f} | "
                            f"Duration: {metric.total_runtime_s:.1f}s"
                        )
                    except Exception as ex:
                        console.print(f"[bold red]Trial failed with exception: {ex}[/bold red]")
                        failed_metric = P5TrialMetrics(
                            model_name=model,
                            condition=condition,
                            config_id=cfg.config_id,
                            trial_num=trial_num,
                            objective_failed=True,
                            failure_notes=str(ex),
                        )
                        results.append(failed_metric)

                    # Persist intermediate results after each trial
                    with open(args.output, "w") as f:
                        json.dump([m.to_dict() for m in results], f, indent=2)

    # Render final Rich Scorecards
    console.print("\n[bold bright_green]✓ Benchmark Matrix Execution Completed[/bold bright_green]")
    harness.render_scorecard(results)


if __name__ == "__main__":
    main()
