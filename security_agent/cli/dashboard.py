"""
Dashboard layout builder and UI themes for Buzzard Code.

Extracted from agent/loop.py to separate presentation concerns from orchestration.
The AgentLoop populates a DashboardState dataclass; this module renders it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED


# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------

THEMES: Dict[str, Dict[str, Any]] = {
    "default": {
        "header_border": "bright_blue",
        "title": "bold bright_cyan",
        "target_info": "dim cyan",
        "plan_border": "dim",
        "metrics_border": "red",
        "evidence": "bold cyan",
        "workspace_border": "bright_magenta",
        "workspace_headers": {
            "thinking": "bold bright_magenta",
            "action": "bold bright_green",
            "result": "bold bright_yellow",
            "observation": "bold bright_cyan",
        },
        "history_border": "dim",
        "history_headers": {
            "time": "dim",
            "tool": "bold green",
            "args": "dim",
            "result": "white",
        },
    },
    "emerald": {
        "header_border": "green",
        "title": "bold bright_green",
        "target_info": "dim green",
        "plan_border": "dim green",
        "metrics_border": "green",
        "evidence": "bold spring_green3",
        "workspace_border": "spring_green3",
        "workspace_headers": {
            "thinking": "bold spring_green3",
            "action": "bold green1",
            "result": "bold yellow1",
            "observation": "bold bright_green",
        },
        "history_border": "dim green",
        "history_headers": {
            "time": "dim green",
            "tool": "bold spring_green3",
            "args": "dim green",
            "result": "white",
        },
    },
    "cyberpunk": {
        "header_border": "bright_magenta",
        "title": "bold bright_yellow",
        "target_info": "bright_cyan",
        "plan_border": "bright_magenta",
        "metrics_border": "bright_yellow",
        "evidence": "bold bright_cyan",
        "workspace_border": "bright_cyan",
        "workspace_headers": {
            "thinking": "bold bright_magenta",
            "action": "bold bright_yellow",
            "result": "bold bright_magenta",
            "observation": "bold bright_cyan",
        },
        "history_border": "bright_magenta",
        "history_headers": {
            "time": "dim bright_magenta",
            "tool": "bold bright_cyan",
            "args": "dim bright_cyan",
            "result": "bright_yellow",
        },
    },
    "matrix": {
        "header_border": "green",
        "title": "bold green",
        "target_info": "green",
        "plan_border": "green",
        "metrics_border": "green",
        "evidence": "bold green",
        "workspace_border": "green",
        "workspace_headers": {
            "thinking": "bold green",
            "action": "bold green",
            "result": "bold green",
            "observation": "bold green",
        },
        "history_border": "green",
        "history_headers": {
            "time": "green",
            "tool": "bold green",
            "args": "green",
            "result": "green",
        },
    },
}


# ---------------------------------------------------------------------------
# DashboardState — typed snapshot of UI variables
# ---------------------------------------------------------------------------

@dataclass
class DashboardState:
    """All the mutable UI state the dashboard needs to render a frame."""

    # Session info
    session_id: str = ""
    model_name: str = ""
    iteration: int = 0
    max_iterations: int = 15
    start_time: float = 0.0

    # Task context
    task_goal: str = ""
    target: str = ""
    scope: List[str] = field(default_factory=list)
    status: str = "Initializing..."

    # Plan
    plan: List[str] = field(default_factory=lambda: ["Perform security audit"])
    current_plan_index: int = 0

    # Workspace
    thinking: str = ""
    action_tool: str = ""
    action_args: Dict[str, Any] = field(default_factory=dict)
    result: str = ""
    observation: str = ""
    observation_meaning: str = ""
    observation_next: str = ""

    # Metrics
    findings_count: Dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    evidence_count: int = 0

    # Tool history
    history: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Layout builder
# ---------------------------------------------------------------------------

def build_dashboard_layout(
    state: DashboardState,
    theme_name: str = "default",
    max_history_rows: int = 5,
) -> Table:
    """
    Builds the Rich Table/Panel dashboard layout from a DashboardState snapshot.
    Pure function — no side effects.
    """
    theme = THEMES.get(theme_name, THEMES["default"])

    # ── Header ──
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=3)
    header_table.add_column(justify="right", ratio=2)

    elapsed = time.time() - state.start_time
    mins, secs = divmod(int(elapsed), 60)
    time_str = f"{mins}m {secs:02d}s"

    title_text = Text("BUZZARD CODE 🚀", style=theme["title"])
    target_info = Text(
        f"\nTarget: {state.target} | Scope: {', '.join(state.scope)} | Goal: {state.task_goal}",
        style=theme["target_info"],
    )
    left_header = Text.assemble(title_text, target_info)

    status_style = (
        "bold green"
        if "complete" in state.status.lower() or "completed" in state.status.lower()
        else "bold yellow"
    )
    right_text = Text()
    right_text.append("Status: ", style="bold")
    right_text.append(f"{state.status}\n", style=status_style)
    right_text.append(
        f"Model: {state.model_name} | Iteration: {state.iteration}/{state.max_iterations} | Time: {time_str}",
        style="dim",
    )

    header_table.add_row(left_header, right_text)
    header_panel = Panel(header_table, border_style=theme["header_border"], box=ROUNDED)

    # ── Left side: Plan & Metrics ──
    left_grid = Table.grid(expand=True)

    plan_table = Table.grid(expand=True)
    plan_table.add_column(width=4)
    plan_table.add_column()

    for idx, task in enumerate(state.plan):
        if idx < state.current_plan_index:
            marker = "[green]✓[/green]"
            style = "dim"
        elif idx == state.current_plan_index:
            marker = "[bright_yellow]▶[/bright_yellow]"
            style = "bold bright_white"
        else:
            marker = "[dim]○[/dim]"
            style = "dim"
        plan_table.add_row(marker, Text(task, style=style))

    plan_panel = Panel(plan_table, title="ASSESSMENT PLAN", border_style=theme["plan_border"], box=ROUNDED)
    left_grid.add_row(plan_panel)

    # Metrics / Findings
    sev_text = Text()
    for sev, count in state.findings_count.items():
        color = {
            "critical": "red", "high": "orange3", "medium": "yellow",
            "low": "green", "info": "blue",
        }.get(sev, "white")
        sev_text.append(f"• {sev.upper()}: ", style=f"bold {color}")
        sev_text.append(f"{count}  ", style="white")

    evidence_text = Text(f"\nEvidence Collected: {state.evidence_count}", style=theme["evidence"])
    metrics_panel = Panel(
        Text.assemble(sev_text, evidence_text),
        title="METRICS & FINDINGS",
        border_style=theme["metrics_border"],
        box=ROUNDED,
    )
    left_grid.add_row(metrics_panel)

    # ── Right side: Agent Workspace ──
    right_grid = Table.grid(expand=True)
    workspace_text = Text()

    workspace_text.append("THINKING:\n", style=theme["workspace_headers"]["thinking"])
    if state.thinking:
        workspace_text.append(f"{state.thinking}\n\n", style="italic")
    else:
        workspace_text.append("No active reasoning.\n\n", style="dim")

    workspace_text.append("ACTION:\n", style=theme["workspace_headers"]["action"])
    if state.action_tool:
        workspace_text.append("Running tool: ", style="dim")
        workspace_text.append(f"{state.action_tool}\n", style="bold green")
        for k, v in state.action_args.items():
            workspace_text.append(f"  {k}: ", style="dim green").append(f"{v}\n")
        workspace_text.append("\n")
    else:
        workspace_text.append("No active tool execution.\n\n", style="dim")

    workspace_text.append("RESULT:\n", style=theme["workspace_headers"]["result"])
    if state.result:
        res_str = state.result
        if len(res_str) > 800:
            res_str = res_str[:797] + "..."
        workspace_text.append(f"{res_str}\n\n", style="dim")
    else:
        workspace_text.append("No result yet.\n\n", style="dim")

    workspace_text.append("OBSERVATION:\n", style=theme["workspace_headers"]["observation"])
    if state.observation:
        workspace_text.append(f"{state.observation}\n", style="white")
        if state.observation_meaning:
            workspace_text.append("Meaning: ", style="bold yellow").append(f"{state.observation_meaning}\n")
        if state.observation_next:
            workspace_text.append("Next Step: ", style="bold cyan").append(f"{state.observation_next}\n")
    else:
        workspace_text.append("No observation yet.\n", style="dim")

    workspace_panel = Panel(workspace_text, title="WORKSPACE", border_style=theme["workspace_border"], box=ROUNDED)
    right_grid.add_row(workspace_panel)

    # ── Body: Left + Right ──
    body_table = Table.grid(expand=True)
    body_table.add_column(ratio=2, style="bright_white")
    body_table.add_column(width=2)
    body_table.add_column(ratio=3, style="bright_white")
    body_table.add_row(left_grid, "", right_grid)

    # ── Footer: Tool History Log ──
    total_history = len(state.history)
    visible_history = state.history[-max_history_rows:]

    history_table = Table(box=ROUNDED, border_style=theme["history_border"], expand=True)
    history_table.add_column("Timestamp", width=12, style=theme["history_headers"]["time"])
    history_table.add_column("Tool Executed", width=25)
    history_table.add_column("Status", width=10)
    history_table.add_column("Arguments Used", width=40, style=theme["history_headers"]["args"])
    history_table.add_column("Result Excerpt", style=theme["history_headers"]["result"])

    for h in visible_history:
        h_status = h.get("status", "SUCCESS")
        h_style = h.get("status_style", "bold green")

        tool_style = "bold red" if h_status in ("DENIED", "ERROR") else theme["history_headers"]["tool"]
        tool_text = Text(h["tool"], style=tool_style)
        status_text = Text(h_status, style=h_style)

        history_table.add_row(
            h["time"],
            tool_text,
            status_text,
            str(h["args"]),
            h["result_summary"],
        )

    history_title = "TOOL EXECUTION LOG"
    history_subtitle = None
    if total_history > max_history_rows:
        history_subtitle = f"Showing last {max_history_rows} of {total_history} executions (auto-scrolling)"

    history_panel = Panel(
        history_table,
        title=history_title,
        subtitle=history_subtitle,
        border_style=theme["history_border"],
        box=ROUNDED,
    )

    # ── Assemble ──
    main_grid = Table.grid(expand=True)
    main_grid.add_row(header_panel)
    main_grid.add_row(body_table)
    main_grid.add_row(history_panel)

    return main_grid
