"""
Phase 9 Benchmark Execution Script.
Runs all three local models through the Application-Surface Intelligence Benchmark Harness.
"""

import sys
import json
import time
from pathlib import Path
from rich.console import Console
from benchmark.browser_bench import (
    BrowserIntelligenceBenchmarkHarness,
    format_browser_results_table,
    asdict,
)

console = Console()

MODELS = [
    "qwythos:latest",
    "qwen-cyber:latest",
    "k3-sec:latest",
]


def main():
    console.print("\n[bold cyan]════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold yellow]      PHASE 9 — APPLICATION-SURFACE INTELLIGENCE BENCHMARK         [/bold yellow]")
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    harness = BrowserIntelligenceBenchmarkHarness()
    all_results = []

    for model in MODELS:
        console.print(f"[bold magenta]► Evaluating Model: {model}[/bold magenta]")
        res = harness.run_benchmark_trial(model_name=model)
        all_results.append(res)
        console.print(
            f"  ✓ Score: [bold green]{res.score_pct:.1f}%[/bold green] | "
            f"DOM Saved: {res.dom_reduction_pct}% ({res.raw_model_tokens_saved} tokens) | "
            f"Forms: {res.forms_discovered} | JS APIs: {res.js_apis_discovered} | WS: {res.websockets_discovered} | "
            f"Duration: {res.duration_seconds}s"
        )
        time.sleep(1.0)

    table = format_browser_results_table(all_results)
    console.print("\n")
    console.print(table)

    out_dir = Path("benchmarks/phase9")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "phase9_results.json"
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in all_results], f, indent=2)

    console.print(f"\n[green]Benchmark results written to {out_path}[/green]")


if __name__ == "__main__":
    main()
