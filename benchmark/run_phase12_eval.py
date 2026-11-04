#!/usr/bin/env python3
"""
Phase 12 Benchmark Runner: Long-Horizon Autonomy & Persistent Investigation.

Evaluates local real models against:
1. Long-horizon coherence (8 and 16 turns)
2. Mid-investigation crash and resume fidelity
3. Invariant retention (Capabilities, Active Sessions, Verified Findings)
4. Duplicate action prevention across process boundaries
"""

import sys
import json
import time
from pathlib import Path
from rich.console import Console
from dataclasses import asdict

repo_root = str(Path(__file__).resolve().parent.parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from intelligence.decision import AutonomyMode
from benchmark.phase12_bench import Phase12BenchmarkHarness, format_results_table


def main():
    console = Console()
    console.print("\n[bold cyan]=== STARTING PHASE 12 LONG-HORIZON & PERSISTENCE BENCHMARK ===[/bold cyan]\n")

    harness = Phase12BenchmarkHarness()
    models = ["qwythos:latest", "qwen-cyber:latest", "k3-sec:latest"]
    results = []
    traces = {}

    for model in models:
        console.print(f"[bold yellow]Evaluating model: {model} (RAW_MODEL Mode, Horizon: 8 turns with Crash & Resume)...[/bold yellow]")
        try:
            res_8 = harness.run_trial(model_name=model, horizon_turns=8, mode=AutonomyMode.RAW_MODEL)
            results.append(res_8)
            traces[f"{model}_RAW_8"] = res_8.raw_trace
            console.print(f"  [green]✓ Completed {model} (8 turns): Autonomy={res_8.autonomy_score:.2f}, Independence={res_8.decision_independence_pct:.1f}%, Recovery={res_8.recovery_fidelity_pct:.1f}%[/green]")
        except Exception as e:
            console.print(f"  [red]✗ Error evaluating {model}: {e}[/red]")

    console.print("\n")
    table = format_results_table(results)
    console.print(table)

    # Save output artifacts
    out_dir = Path("benchmarks/phase12")
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "phase12_results.json", "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    with open(out_dir / "phase12_traces.json", "w", encoding="utf-8") as f:
        json.dump(traces, f, indent=2)

    console.print(f"\n[bold green]✓ Benchmark data saved to {out_dir}/[/bold green]\n")


if __name__ == "__main__":
    main()
