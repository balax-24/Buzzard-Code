"""
Phase 7C Execution Script.
Runs all three local models in both Baseline and Recursive prompt modes, collects metrics,
and outputs the results to JSON and stdout.
"""

import sys
import json
import time
from pathlib import Path
from rich.console import Console
from security_agent.benchmark.recursive_bench import (
    RealModelRecursiveBenchmarkHarness,
    format_results_table,
    asdict,
)

console = Console()

MODELS = [
    "qwythos:latest",
    "qwen-cyber:latest",
    "k3-sec:latest",
]

PROMPT_MODES = [
    "baseline",
    "recursive",
]


def main():
    console.print("\n[bold cyan]════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold yellow]       PHASE 7C — REAL-MODEL RECURSIVE AUTONOMY BENCHMARK          [/bold yellow]")
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    harness = RealModelRecursiveBenchmarkHarness(
        host="127.0.0.1",
        web_port=8080,
        ipp_port=631,
        ssh_port=2222,
        max_iterations=8,
        timeout_seconds=60,
    )

    console.print("[green]Starting deterministic isolated multi-service lab...[/green]")
    harness.setup_lab()

    all_results = []
    try:
        for model in MODELS:
            for mode in PROMPT_MODES:
                console.print(f"\n[bold magenta]► Running trial: Model={model} | PromptMode={mode}[/bold magenta]")
                res = harness.run_benchmark_trial(model_name=model, prompt_mode=mode)
                all_results.append(res)
                console.print(
                    f"  ✓ Depth: [bold green]{res.model_recursive_depth}/{res.backend_max_recursive_depth}[/bold green] "
                    f"({res.recursive_utilization_pct}%) | State: {res.final_objective_state} | StopReason: {res.stop_reason}"
                )
                time.sleep(1.0)
    finally:
        console.print("\n[yellow]Tearing down isolated lab...[/yellow]")
        harness.teardown_lab()

    # Display summary table
    table = format_results_table(all_results)
    console.print("\n")
    console.print(table)

    # Save to json
    out_dir = Path("benchmarks/phase7c")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "phase7c_results.json"
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in all_results], f, indent=2)
    console.print(f"\n[bold green]Saved benchmark results to {out_path}[/bold green]\n")


if __name__ == "__main__":
    main()
