"""
Security UX and Policy Manager for Buzzard Code.

Exposes real runtime security controls:
- Policy & permission introspection
- Scope management (targets, networks, network toggles)
- Sandbox lifecycle (inspect, status, rebuild)
- Emergency kill-switch trigger and deliberate resume
"""

import sys
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.config import (
    load_merged_config,
    save_global_config,
    save_project_config,
    get_project_config_path,
)
from security.policy import PolicyEngine
from security.kill_switch import KillSwitch
from security.scope import is_in_scope, extract_host_and_port
from security.autonomy import AutonomyLevel, EnvironmentProfile
from sandbox.container import (
    is_docker_active,
    get_security_sandbox_image,
    get_sandbox,
)

def render_policy_and_permissions(config: Optional[Dict[str, Any]] = None) -> None:
    """Renders authoritative security policy and permission states."""
    console = Console()
    cfg = config or load_merged_config()
    sec_cfg = cfg.get("security", {})
    autonomy_level = sec_cfg.get("autonomy_level", 2)
    env_str = sec_cfg.get("environment", "lab").upper()

    pe = PolicyEngine(
        scope=sec_cfg.get("scope", ["localhost"]),
        autonomy_level=AutonomyLevel(autonomy_level) if autonomy_level in (1, 2, 3, 4) else AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
        environment=EnvironmentProfile.LAB if env_str.lower() == "lab" else EnvironmentProfile.PRODUCTION
    )

    table = Table(
        title=f"BUZZARD SECURITY POLICY [Environment: {env_str} | Autonomy: Level {autonomy_level}]",
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("Operation / Tool Category", style="bold")
    table.add_column("Policy Action", style="bold")
    table.add_column("Risk Threshold")

    # Policy matrix based on Autonomy Level and Risk classes
    policies = [
        ("Filesystem Read (Local workspace)", "[green]ALLOW[/green]", "R0 Passive"),
        ("Filesystem Write (Project code/reports)", "[yellow]ASK[/yellow]", "R1 Low"),
        ("Shell Execution (Sandbox container)", "[green]ALLOW[/green]" if autonomy_level >= 3 else "[yellow]ASK[/yellow]", "R2 Medium"),
        ("Network Request (In-scope targets)", "[green]ALLOW[/green]" if autonomy_level >= 2 else "[yellow]ASK[/yellow]", "R1 Low"),
        ("Security Scan (Port/vuln scan)", "[green]ALLOW[/green]" if autonomy_level >= 2 else "[yellow]ASK[/yellow]", "R2 Medium"),
        ("Exploit Execution (R3/R4 Tools)", "[yellow]ASK[/yellow]" if autonomy_level >= 4 else "[red]DENY[/red]", "R3-R4 High/Critical"),
        ("Docker Container Isolation", "[green]ENFORCED[/green]", "Mandatory"),
        ("Git Status / Diff Inspection", "[green]ALLOW[/green]", "R0 Passive"),
        ("Git Commit", "[yellow]ASK[/yellow]", "Operator Review"),
        ("Git Push", "[red]DENY[/red]", "Restricted"),
        ("Arbitrary Host File Deletion", "[red]DENY[/red]", "Hard Boundary"),
    ]

    for op, act, thresh in policies:
        table.add_row(op, act, thresh)

    console.print()
    console.print(table)
    console.print("[dim]Security policies are strictly enforced outside model reasoning by PolicyEngine.[/dim]\n")

def render_scope(config: Optional[Dict[str, Any]] = None) -> None:
    """Renders active authorized scope."""
    console = Console()
    cfg = config or load_merged_config()
    sec_cfg = cfg.get("security", {})
    scope = sec_cfg.get("scope", ["localhost", "127.0.0.1"])
    allow_net = sec_cfg.get("allow_network", True)
    env = sec_cfg.get("environment", "lab").capitalize()

    net_status = "[green]ENABLED[/green]" if allow_net else "[red]DISABLED (Strict Offline)[/red]"

    body = (
        f"[bold cyan]Environment:[/bold cyan] {env}\n"
        f"[bold cyan]Network Outbound:[/bold cyan] {net_status}\n\n"
        f"[bold cyan]Authorized Target Hosts / IPs:[/bold cyan]\n"
    )
    for s in scope:
        body += f"  • [green]{s}[/green]\n"

    body += (
        "\n[dim]Commands:\n"
        "  /scope add <host>     - Authorize new target IP or hostname\n"
        "  /scope remove <host>  - Revoke target authorization\n"
        "  /scope toggle-network - Toggle outbound network permission[/dim]"
    )
    console.print(Panel(body, title="AUTHORIZED SCOPE", border_style="cyan"))

def modify_scope(action: str, target: Optional[str] = None, config: Optional[Dict[str, Any]] = None) -> bool:
    """Adds, removes, or modifies target in authorized scope and persists to config."""
    console = Console()
    cfg = config or load_merged_config()
    sec_cfg = cfg.setdefault("security", {})
    scope = sec_cfg.setdefault("scope", ["localhost", "127.0.0.1"])

    action = action.lower()
    if action == "add":
        if not target:
            console.print("[bold red]Specify target to add: /scope add <host>[/bold red]")
            return False
        host, _ = extract_host_and_port(target)
        entry = host or target
        if entry not in scope:
            scope.append(entry)
            _persist_scope_update(cfg)
            console.print(f"[bold green]✓ Added '{entry}' to authorized scope.[/bold green]")
            return True
        else:
            console.print(f"[yellow]'{entry}' is already in scope.[/yellow]")
            return False

    elif action == "remove":
        if not target:
            console.print("[bold red]Specify target to remove: /scope remove <host>[/bold red]")
            return False
        host, _ = extract_host_and_port(target)
        entry = host or target
        if entry in scope:
            scope.remove(entry)
            _persist_scope_update(cfg)
            console.print(f"[bold yellow]✓ Removed '{entry}' from authorized scope.[/bold yellow]")
            return True
        else:
            console.print(f"[yellow]'{entry}' was not in scope.[/yellow]")
            return False

    elif action in ("toggle-network", "toggle_network", "network"):
        current = sec_cfg.get("allow_network", True)
        sec_cfg["allow_network"] = not current
        _persist_scope_update(cfg)
        status_str = "ENABLED" if sec_cfg["allow_network"] else "DISABLED"
        console.print(f"[bold cyan]Outbound network requests are now: {status_str}[/bold cyan]")
        return True

    return False

def _persist_scope_update(cfg: Dict[str, Any]) -> None:
    proj_path = get_project_config_path()
    if proj_path:
        save_project_config(cfg)
    else:
        save_global_config(cfg)

def render_sandbox_status() -> None:
    """Renders Docker sandbox configuration and operational isolation status."""
    console = Console()
    docker_ok = is_docker_active()
    image = get_security_sandbox_image()

    status_str = "[green]READY[/green]" if docker_ok else "[yellow]OFFLINE (Fallback to Native Runner)[/yellow]"

    body = (
        f"[bold cyan]Engine:[/bold cyan] Docker\n"
        f"[bold cyan]Image:[/bold cyan] {image}\n"
        f"[bold cyan]Status:[/bold cyan] {status_str}\n"
        f"[bold cyan]Network Isolation:[/bold cyan] Restricted internal network\n"
        f"[bold cyan]Filesystem:[/bold cyan] Isolated container rootfs + ephemeral workspace mount\n"
        f"[bold cyan]Privileges:[/bold cyan] Non-root security user\n\n"
        f"[dim]Commands:\n"
        f"  /sandbox inspect - Verify sandbox container connectivity\n"
        f"  /sandbox rebuild - Rebuild sandbox Docker container image[/dim]"
    )
    console.print(Panel(body, title="BUZZARD SECURITY SANDBOX", border_style="cyan"))

def trigger_kill_switch(reason: str = "Operator invoked /kill") -> None:
    """Triggers the thread-safe KillSwitch singleton."""
    console = Console()
    ks = KillSwitch.get_instance()
    ks.trigger(reason=reason)
    console.print(Panel(
        f"[bold white on red] !!! EMERGENCY KILL SWITCH ACTIVATED !!! [/bold white on red]\n\n"
        f"Reason: {reason}\n"
        f"Status: ALL TOOL EXECUTION HALTED\n\n"
        f"[bold yellow]To disarm and resume, run: /resume[/bold yellow]",
        border_style="red"
    ))

def resume_kill_switch(confirm: bool = False) -> bool:
    """Resets the KillSwitch singleton after operator confirmation."""
    console = Console()
    ks = KillSwitch.get_instance()
    if not ks.is_triggered():
        console.print("[dim]Kill switch is not currently triggered. System is operational.[/dim]")
        return True

    if not confirm:
        console.print("[bold yellow]To confirm resuming agent execution, use: /resume confirm[/bold yellow]")
        return False

    ks.reset()
    console.print("[bold green]✓ Kill switch disarmed. Agent execution resumed.[/bold green]")
    return True
