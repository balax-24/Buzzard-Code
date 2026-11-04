import sys
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED, DOUBLE_EDGE
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

console = Console(legacy_windows=False)

def render_header(model: str, runtime: str, mode: str, sandbox: str, browser: str, status: str):
    """
    Renders the startup header banner and configurations.
    """
    header_text = Text("\nBUZZARD CODE\n", style="bold bright_cyan", justify="center")
    header_text.append(f"{model.upper()} • LOCAL\n", style="cyan")
    
    console.print(Panel(header_text, box=DOUBLE_EDGE, border_style="bright_blue"))
    
    table = Table(box=ROUNDED, border_style="bright_blue", show_header=False)
    table.add_column("Key", style="dim cyan", width=15)
    table.add_column("Value", style="bright_white")
    
    table.add_row("Model", model)
    table.add_row("Runtime", runtime)
    table.add_row("Mode", mode)
    table.add_row("Sandbox", sandbox)
    table.add_row("Browser", browser)
    table.add_row("Status", f"[bold green]{status}[/bold green]" if status == "Ready" else f"[bold yellow]{status}[/bold yellow]")
    
    console.print(table)
    console.print()

def render_thinking(goal: str, why: str, expected: str):
    """
    Renders the agent's internal thinking panel.
    """
    text = Text()
    text.append("Goal: ", style="bold cyan").append(f"{goal}\n\n")
    text.append("Why: ", style="bold cyan").append(f"{why}\n\n")
    text.append("Expected: ", style="bold cyan").append(f"{expected}")
    
    console.print(Panel(text, title="THINKING", title_align="left", border_style="bright_magenta", box=ROUNDED))

def render_action(tool: str, arguments: Dict[str, Any]):
    """
    Renders the tool action block.
    """
    text = Text()
    text.append(f"{tool}\n", style="bold green")
    for k, v in arguments.items():
        text.append(f"  {k}: ", style="dim green").append(f"{v}\n")
        
    console.print(Panel(text, title="ACTION", title_align="left", border_style="bright_green", box=ROUNDED))

def render_result(output: str, duration: Optional[float] = None, exit_code: Optional[int] = None):
    """
    Renders the tool output/result panel.
    """
    text = Text()
    if exit_code is not None:
        style = "green" if exit_code == 0 else "red"
        text.append(f"exit code: {exit_code}\n", style=style)
    if duration is not None:
        text.append(f"duration: {duration:.2s}s\n", style="dim")
        
    text.append(output)
    console.print(Panel(text, title="RESULT", title_align="left", border_style="bright_yellow", box=ROUNDED))

def render_observation(observation: str, meaning: str, next_step: str):
    """
    Renders the observation panel.
    """
    text = Text()
    text.append(observation + "\n\n")
    text.append("Meaning: ", style="bold yellow").append(meaning + "\n\n")
    text.append("Next: ", style="bold cyan").append(next_step)
    
    console.print(Panel(text, title="OBSERVATION", title_align="left", border_style="bright_cyan", box=ROUNDED))

def render_plan(plan: List[str], current_index: int = 0):
    """
    Renders the current plan task status.
    """
    table = Table(title="CURRENT PLAN", title_justify="left", box=ROUNDED, border_style="dim", show_header=False)
    table.add_column("Status", width=5)
    table.add_column("Task")
    
    for idx, task in enumerate(plan):
        if idx < current_index:
            status = "[green]✓[/green]"
            style = "dim"
        elif idx == current_index:
            status = "[bright_yellow]●[/bright_yellow]"
            style = "bold bright_white"
        else:
            status = "[dim]○[/dim]"
            style = "dim"
        table.add_row(status, Text(task, style=style))
        
    console.print(table)
    console.print()

def render_doctor(checks: Dict[str, Any], model_name: str = "qwen3.8-27b-obl:latest"):
    """
    Renders diagnostics checklist for the doctor command.
    """
    console.print("[bold bright_cyan]BUZZARD CODE DIAGNOSTICS[/bold bright_cyan]\n")
    
    all_ok = True
    
    categories = {
        "Provider": ["Ollama reachable", f"Model {model_name} available", "Streaming available"],
        "Tool System": ["Tool registry populated", "Tool schemas valid", "Tool-call parser working", "Tool dispatcher working"],
        "Sandbox": ["Docker CLI installed", "Docker daemon running", "Sandbox container operational"],
        "Event System": ["Event emitter active", "Live rendering active"],
        "End-to-End": ["Model → Tool → Result → Model"]
    }
    
    for category, items in categories.items():
        console.print(f"[bold bright_blue]{category}[/bold bright_blue]")
        for item in items:
            status = checks.get(item, False)
            if isinstance(status, tuple):
                ok, msg = status
            else:
                ok, msg = status, ""
                
            if ok:
                marker = "[bold green]✓[/bold green]"
                detail = f" ({msg})" if msg else ""
                console.print(f"  {marker} {item}{detail}")
            else:
                marker = "[bold red]✗[/bold red]"
                detail = f" - {msg}" if msg else ""
                console.print(f"  {marker} {item}{detail}")
                all_ok = False
        console.print()
        
    if all_ok:
        console.print("[bold green]RESULT: System fully operational and ready for autonomous security tasks.[/bold green]\n")
    else:
        console.print("[bold red]RESULT: Diagnostics identified issues marked with ✗.[/bold red]\n")
        
    return all_ok

def render_findings(findings: List[Any]):
    """
    Renders the finding summary list.
    """
    if not findings:
        console.print("[dim]No findings recorded yet.[/dim]\n")
        return
        
    table = Table(title="FINDINGS", title_justify="left", box=ROUNDED, border_style="red")
    table.add_column("ID", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Confidence")
    
    for f in findings:
        sev_styles = {
            "critical": "bold red",
            "high": "bold orange3",
            "medium": "bold yellow",
            "low": "bold green",
            "info": "bold blue"
        }
        style = sev_styles.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower(), "white")
        table.add_row(
            f.id,
            Text(f.severity.upper() if hasattr(f.severity, "upper") else str(f.severity).upper(), style=style),
            f.title,
            f.confidence.upper() if hasattr(f.confidence, "upper") else str(f.confidence).upper()
        )
    console.print(table)
    console.print()

def render_evidence(evidence_list: List[Any]):
    """
    Renders the evidence list.
    """
    if not evidence_list:
        console.print("[dim]No evidence collected yet.[/dim]\n")
        return
        
    table = Table(title="EVIDENCE", title_justify="left", box=ROUNDED, border_style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="bold")
    table.add_column("Target")
    table.add_column("Description")
    
    for e in evidence_list:
        table.add_row(e.id, e.type.upper() if hasattr(e.type, "upper") else str(e.type).upper(), e.target, e.description)
    console.print(table)
    console.print()

def render_assessment_summary(
    duration_s: float,
    tools_executed: int,
    findings_count: int,
    verified_findings_count: int,
    failed_operations: int,
    retries: int,
    attack_surfaces: Optional[Dict[str, bool]] = None
) -> None:
    """
    Renders the final structured assessment summary box with attack surface checklist.
    """
    mins, secs = divmod(int(duration_s), 60)
    dur_str = f"{mins:02d}m {secs:02d}s"

    lines = [
        f"[bold white]Duration:[/] [bright_cyan]{dur_str}[/]",
        f"[bold white]Tools executed:[/] [bright_cyan]{tools_executed}[/]",
        f"[bold white]Findings:[/] [bold #f43f5e]{findings_count}[/]",
        f"[bold white]Verified findings:[/] [bold #10b981]{verified_findings_count}[/]",
        f"[bold white]Failed operations:[/] [bold #ef4444]{failed_operations}[/]",
        f"[bold white]Retries:[/] [bold #f59e0b]{retries}[/]",
        "",
        "[bold cyan]Attack Surface[/]"
    ]

    surfaces = attack_surfaces or {
        "Network": True,
        "HTTP": True,
        "Authentication": True,
        "Filesystem": True
    }
    
    keys = list(surfaces.keys())
    for i, k in enumerate(keys):
        is_last = (i == len(keys) - 1)
        prefix = "└── " if is_last else "├── "
        val = surfaces[k]
        icon = "[bold green]✓[/bold green]" if val else "[dim]○[/dim]"
        lines.append(f"  {prefix}{k:<18} {icon}")

    summary_text = Text.from_markup("\n".join(lines))
    console.print()
    console.print(Panel(summary_text, title="╭─ Assessment Summary ─╮", border_style="bright_blue"))
    console.print()

def render_execution_metrics(
    elapsed_seconds: float,
    tools_count: int,
    successful_count: int,
    failed_count: int,
    retries_count: int,
    tokens: int,
    budget_pct: float,
    duplicate_calls_blocked: int = 0,
    cache_hits: int = 0,
    avg_model_latency: Optional[float] = None
) -> None:
    """
    Renders live runtime, token, cache, and budget execution metrics.
    """
    hours, rem = divmod(int(elapsed_seconds), 3600)
    mins, secs = divmod(rem, 60)
    time_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
    
    console.print("[dim]────────────────────────────────────────────────────────────────────────[/dim]")
    console.print(f"[bold]Runtime:[/]    {time_str}")
    console.print(f"[bold]Tools:[/]      {tools_count}")
    console.print(f"[bold]Successful:[/] [green]{successful_count}[/green]")
    console.print(f"[bold]Failed:[/]     [red]{failed_count}[/red]")
    console.print(f"[bold]Retries:[/]    [yellow]{retries_count}[/yellow]")
    console.print(f"[bold]Tokens:[/]     {tokens:,}")
    console.print(f"[bold]Budget:[/]     [bold cyan]{budget_pct:.0f}%[/bold cyan]")
    if duplicate_calls_blocked > 0 or cache_hits > 0:
        console.print(f"[bold]Cache Hits:[/]   [green]{cache_hits}[/green] ([yellow]{duplicate_calls_blocked} duplicate calls blocked[/yellow])")
    if avg_model_latency is not None and avg_model_latency > 0:
        console.print(f"[bold]Model Latency:[/] [dim]{avg_model_latency:.1f}s avg/decision[/dim]")
    console.print()

def render_performance_profile(profile_data: Dict[str, float]) -> None:
    """
    Renders detailed performance breakdown table with latency shares.
    """
    total_time = sum(profile_data.values())
    if total_time <= 0:
        total_time = 0.001

    table = Table(title="PERFORMANCE PROFILE", title_justify="left", box=ROUNDED, border_style="bright_blue")
    table.add_column("Phase", style="bold cyan", width=20)
    table.add_column("Duration", style="bright_white", justify="right", width=12)
    table.add_column("Share", style="yellow", justify="right", width=10)

    label_map = {
        "startup_time": "Startup",
        "toolchain_time": "Toolchain",
        "planner_time": "Planner (LLM)",
        "tool_execution_time": "Tools",
        "parser_time": "Parsing",
        "render_time": "Rendering"
    }

    for key, label in label_map.items():
        dur = profile_data.get(key, 0.0)
        pct = (dur / total_time) * 100.0
        table.add_row(label, f"{dur:.1f}s", f"{pct:.1f}%")

    planner_share = (profile_data.get("planner_time", 0.0) / total_time) * 100.0
    tool_share = (profile_data.get("tool_execution_time", 0.0) / total_time) * 100.0

    console.print()
    console.print(table)
    console.print(f"[bold]Total Runtime:[/] {total_time:.1f}s | [bold cyan]Planner Share:[/] {planner_share:.1f}% | [bold green]Tool Share:[/] {tool_share:.1f}%")
    console.print()



