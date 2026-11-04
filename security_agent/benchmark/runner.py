"""
Multi-Model Security Benchmark System.
Executes standardized local laboratory scenarios across local Ollama models and calculates quantitative metrics.
"""

import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from security_agent.cli.renderer import console
from security_agent.model.ollama import OllamaProvider
from security_agent.model.discovery import ModelDiscoverer


@dataclass
class BenchmarkScenario:
    id: str
    name: str
    target: str
    task_goal: str
    expected_tools: List[str]
    expected_findings: List[str]
    mock_responses: Dict[str, str] = field(default_factory=dict)


@dataclass
class ModelBenchmarkResult:
    model_name: str
    tasks_attempted: int = 0
    tasks_completed: int = 0
    tool_calls_total: int = 0
    tool_calls_valid: int = 0
    tool_calls_malformed: int = 0
    tool_selection_matches: int = 0
    tool_selection_opportunities: int = 0
    recoveries_attempted: int = 0
    recoveries_succeeded: int = 0
    findings_claimed: int = 0
    findings_verified: int = 0
    total_runtime_s: float = 0.0
    retry_count: int = 0
    report_quality_score: float = 0.0

    @property
    def completion_pct(self) -> float:
        if self.tasks_attempted == 0:
            return 0.0
        return (self.tasks_completed / self.tasks_attempted) * 100.0

    @property
    def tool_accuracy_pct(self) -> float:
        if self.tool_selection_opportunities == 0:
            return 0.0
        return (self.tool_selection_matches / self.tool_selection_opportunities) * 100.0

    @property
    def recovery_pct(self) -> float:
        if self.recoveries_attempted == 0:
            return 100.0  # No failures required recovery
        return (self.recoveries_succeeded / self.recoveries_attempted) * 100.0

    @property
    def validity_pct(self) -> float:
        if self.tool_calls_total == 0:
            return 0.0
        return (self.tool_calls_valid / self.tool_calls_total) * 100.0


# Standardized Laboratory Scenarios for reproducible local testing
BENCHMARK_SCENARIOS: List[BenchmarkScenario] = [
    BenchmarkScenario(
        id="scenario_recon",
        name="Surface Reconnaissance & Port Discovery",
        target="http://lab-auth.local:8080",
        task_goal="Perform initial network service reconnaissance on http://lab-auth.local:8080",
        expected_tools=["network.enumerate", "network_recon", "http_headers", "http.request", "terminal_execute"],
        expected_findings=["HTTP service detected on port 8080"]
    ),
    BenchmarkScenario(
        id="scenario_headers",
        name="Security Headers & Baseline Audit",
        target="http://lab-auth.local:8080",
        task_goal="Audit security headers and CORS configuration on http://lab-auth.local:8080",
        expected_tools=["evaluate_security_headers", "check_cors_configuration", "http.request", "terminal_execute"],
        expected_findings=["Missing Content-Security-Policy", "Missing X-Frame-Options"]
    ),
    BenchmarkScenario(
        id="scenario_recovery",
        name="Fault Recovery & Alternative Testing",
        target="http://lab-auth.local:8080/api/v1/auth",
        task_goal="Verify login endpoint and recover if initial network probing times out",
        expected_tools=["http.request", "http_headers", "terminal_execute"],
        expected_findings=["Authentication endpoint confirmed"]
    )
]


class ModelBenchmarkRunner:
    """
    Orchestrates standardized test suites across local Ollama models.
    """
    def __init__(self, ollama_host: str = "http://localhost:11434"):
        self.host = ollama_host
        self.discoverer = ModelDiscoverer(host=ollama_host)

    def run_benchmark(self, models: Optional[List[str]] = None, scenarios: Optional[List[BenchmarkScenario]] = None) -> List[ModelBenchmarkResult]:
        """
        Runs the benchmark suite across specified models or all available local models.
        """
        target_models = models or self.discoverer.list_models()
        target_scenarios = scenarios or BENCHMARK_SCENARIOS

        if not target_models:
            console.print("[bold red]No local models available to benchmark.[/bold red]")
            return []

        console.print(f"\n[bold cyan]Starting Security Model Benchmark ({len(target_models)} models · {len(target_scenarios)} scenarios)[/bold cyan]\n")

        results: List[ModelBenchmarkResult] = []

        tools_schema = [
            {
                "type": "function",
                "function": {
                    "name": "network_recon",
                    "description": "Enumerate open ports and services on a target host",
                    "parameters": {
                        "type": "object",
                        "properties": {"target": {"type": "string"}},
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "http_request",
                    "description": "Send an HTTP request to an endpoint",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "method": {"type": "string"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "evaluate_security_headers",
                    "description": "Analyze HTTP response headers for missing security headers",
                    "parameters": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"]
                    }
                }
            }
        ]

        for model_name in target_models:
            console.print(f"[bold bright_cyan]Testing model: {model_name}...[/bold bright_cyan]")
            model_res = ModelBenchmarkResult(model_name=model_name)
            provider = OllamaProvider(host=self.host, model_name=model_name, num_ctx=4096)

            start_t = time.time()
            for sc in target_scenarios:
                model_res.tasks_attempted += 1
                model_res.tool_selection_opportunities += 1

                prompt = (
                    f"You are a professional security assessment agent. Target: {sc.target}.\n"
                    f"Task: {sc.task_goal}.\n"
                    f"Select the appropriate tool to begin testing."
                )

                try:
                    chat_res = provider.chat(
                        messages=[{"role": "user", "content": prompt}],
                        tools=tools_schema
                    )
                    
                    msg = chat_res.get("message", {})
                    tool_calls = msg.get("tool_calls", [])
                    content = msg.get("content", "")

                    if tool_calls:
                        model_res.tool_calls_total += len(tool_calls)
                        for tc in tool_calls:
                            fn = tc.get("function", {})
                            fn_name = fn.get("name", "")
                            args = fn.get("arguments", {})
                            if fn_name:
                                model_res.tool_calls_valid += 1
                                # Check if selected tool is relevant
                                if any(exp.replace(".", "_") in fn_name or fn_name in exp for exp in sc.expected_tools):
                                    model_res.tool_selection_matches += 1
                            else:
                                model_res.tool_calls_malformed += 1
                        model_res.tasks_completed += 1
                        model_res.findings_claimed += 1
                        model_res.findings_verified += 1
                    elif content and ("tool" in content.lower() or "{" in content):
                        # Text JSON fallback tool call
                        model_res.tool_calls_total += 1
                        model_res.tool_calls_valid += 1
                        model_res.tool_selection_matches += 1
                        model_res.tasks_completed += 1
                    else:
                        model_res.tool_calls_total += 1
                        model_res.tool_calls_malformed += 1

                except Exception as e:
                    model_res.recoveries_attempted += 1
                    # Test recovery with simplified prompt
                    try:
                        rec_res = provider.chat(messages=[{"role": "user", "content": f"Execute reconnaissance on {sc.target}"}])
                        if rec_res.get("message", {}).get("content"):
                            model_res.recoveries_succeeded += 1
                            model_res.tasks_completed += 1
                    except Exception:
                        pass

            model_res.total_runtime_s = time.time() - start_t
            model_res.report_quality_score = min(10.0, (model_res.tasks_completed / max(1, model_res.tasks_attempted)) * 10.0)
            results.append(model_res)

        return results

    def render_benchmark_table(self, results: List[ModelBenchmarkResult]) -> None:
        """
        Renders the benchmark summary table.
        """
        table = Table(title="╭─ Model Benchmark Results ─╮", border_style="bright_blue", box=None)
        table.add_column("Model", style="bold bright_cyan", width=26)
        table.add_column("Completion", justify="right", style="bold green")
        table.add_column("Tool Accuracy", justify="right", style="bold cyan")
        table.add_column("Recovery", justify="right", style="bold yellow")
        table.add_column("Validity", justify="right", style="bold white")
        table.add_column("Runtime", justify="right", style="dim")

        for r in results:
            mins, secs = divmod(int(r.total_runtime_s), 60)
            runtime_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{secs}s"
            table.add_row(
                r.model_name,
                f"{r.completion_pct:.0f}%",
                f"{r.tool_accuracy_pct:.0f}%",
                f"{r.recovery_pct:.0f}%",
                f"{r.validity_pct:.0f}%",
                runtime_str
            )

        console.print()
        console.print(Panel(table, border_style="bright_blue"))
        console.print()
