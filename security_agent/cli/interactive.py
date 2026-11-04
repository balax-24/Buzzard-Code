"""
Interactive Shell / REPL Interface for Buzzard Code.

Supports:
- Conversational chat with active LLM provider
- Autonomous tool execution through AgentLoop, ModelDecisionParser, and PolicyEngine
- Full slash-command suite (/help, /status, /doctor, /scope, /permissions, /sandbox, /kill, /resume, etc.)
- Dynamic custom commands (.buzzard/commands/*.md)
- Multi-provider support (Ollama, OpenAI, Gemini, Anthropic, OpenAI-compatible)
"""

import os
import sys
import re
import json
import uuid
from typing import List, Dict, Any, Optional

from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from security_agent.cli.renderer import (
    console,
    render_header,
    render_plan,
    render_findings,
    render_evidence,
)
from security_agent.core.config import (
    load_merged_config,
    save_global_config,
    save_project_config,
    get_project_config_path,
)
from security_agent.core.project import (
    init_project,
    load_custom_commands,
    render_custom_command_prompt,
)
from security_agent.model.factory import (
    get_model_provider,
    resolve_provider_and_model,
    list_supported_providers,
)
from security_agent.tools.inspector import render_tools, get_tool_details
from security_agent.security.manager import (
    render_policy_and_permissions,
    render_scope,
    modify_scope,
    render_sandbox_status,
    trigger_kill_switch,
    resume_kill_switch,
)
from security_agent.security.kill_switch import KillSwitch
from security_agent.security.scope import is_in_scope, extract_host_and_port
from security_agent.storage.db import StorageManager
from security_agent.agent.loop import AgentLoop
from security_agent.cli.commands import (
    run_doctor,
    run_status,
    run_models,
    run_config,
    run_connect,
    run_disconnect,
    list_tasks,
    get_task_status,
    resume_task,
    generate_report,
)

def print_help(custom_commands: Optional[Dict[str, Any]] = None):
    """Prints comprehensive slash command help menu."""
    console.print("[bold cyan]Interactive Commands:[/bold cyan]")
    table = Table(title="BUZZARD CODE COMMANDS REFERENCE", show_header=True, header_style="bold cyan")
    table.add_column("Command", style="bold green", width=26)
    table.add_column("Category", style="dim", width=12)
    table.add_column("Description")

    cmds = [
        # Session
        ("/help", "Session", "Show this help menu"),
        ("/clear", "Session", "Clear console screen"),
        ("/new", "Session", "Start a new assessment session"),
        ("/exit", "Session", "Exit interactive session"),
        # Models
        ("/connect <provider>", "Models", "Connect & configure model provider credentials"),
        ("/disconnect <provider>", "Models", "Remove stored credentials for provider"),
        ("/providers", "Models", "List supported providers (Ollama, OpenAI, Gemini, Anthropic)"),
        ("/models", "Models", "List available models dynamically from provider"),
        ("/model [name]", "Models", "Display current model or switch active model"),
        # Runtime
        ("/status [task_id]", "Runtime", "Display Buzzard Code status card or task details"),
        ("/doctor", "Runtime", "Run comprehensive environment diagnostics"),
        ("/config [show|path|valid]", "Runtime", "View, validate, or inspect configuration"),
        ("/tools [name]", "Runtime", "List registered tools or inspect parameters/schemas"),
        # Security
        ("/scope [list|add|rm]", "Security", "View or modify authorized target scope"),
        ("/permissions", "Security", "View security policy actions and risk levels"),
        ("/policy", "Security", "Alias for /permissions"),
        ("/sandbox [status|inspect]", "Security", "View sandbox container isolation state"),
        # Execution
        ("/approve", "Execution", "Approve pending sensitive tool execution"),
        ("/deny", "Execution", "Deny pending tool execution"),
        ("/stop", "Execution", "Halt current task loop"),
        ("/kill", "Execution", "Activate emergency kill switch (stops all execution)"),
        ("/resume [confirm]", "Execution", "Disarm kill switch or resume paused task"),
        # History
        ("/history", "History", "List recorded assessment sessions and tasks"),
        ("/logs [task_id]", "History", "View session event logs"),
        ("/export [task_id]", "History", "Export session markdown audit report"),
        # Project
        ("/init [--force]", "Project", "Initialize buzzard.json and .buzzard/ scaffolding"),
        ("/diff [path]", "Project", "Display readable git diff of working tree changes"),
    ]

    for c, cat, d in cmds:
        table.add_row(c, cat, d)

    console.print()
    console.print(table)

    if custom_commands:
        custom_table = Table(title="PROJECT CUSTOM COMMANDS (.buzzard/commands/*.md)", show_header=True, header_style="bold magenta")
        custom_table.add_column("Command", style="bold magenta", width=26)
        custom_table.add_column("Arguments", style="dim", width=20)
        custom_table.add_column("Description")

        for name, info in sorted(custom_commands.items()):
            args_str = " ".join(f"<{a}>" for a in info.get("args", []))
            custom_table.add_row(f"/{name}", args_str or "[None]", info.get("description", ""))

        console.print()
        console.print(custom_table)

    console.print("\n[dim]Natural Language Mode: Type any task in plain English to execute autonomously.[/dim]\n")

def _extract_targets_from_text(text: str) -> List[str]:
    targets = []
    url_pattern = r"https?://[^\s<>\"\'\)]+"
    urls = re.findall(url_pattern, text)
    for url in urls:
        host, _ = extract_host_and_port(url)
        if host:
            targets.append(host.lower())
    from security_agent.agent.intent import CODE_FILE_EXTENSIONS
    domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    for match in re.finditer(domain_pattern, text):
        domain = match.group(0)
        ext = domain.split(".")[-1].lower()
        if ext in CODE_FILE_EXTENSIONS:
            continue
        if domain == domain.lower() and domain not in targets:
            targets.append(domain)
    # Match IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        ip = match.group(0)
        if ip not in targets:
            targets.append(ip)
    return list(dict.fromkeys(targets))

def _is_actionable_audit_task(text: str) -> bool:
    from security_agent.agent.intent import is_actionable_task
    return is_actionable_task(text)

def start_interactive_session(skip_toolchain: bool = False, profile: bool = False):
    """
    Runs the main interactive REPL shell with multi-provider routing and full slash-command dispatch.
    """
    config = load_config()
    if profile:
        config["profile"] = True

    raw_model = config.get("model")
    if isinstance(raw_model, str):
        model_name = raw_model
        provider_name = "ollama"
    else:
        model_cfg = raw_model or {}
        provider_name = model_cfg.get("provider", "ollama")
        model_name = model_cfg.get("name", "qwen3:8b")

    provider = get_model_provider(config=config)
    storage = StorageManager()
    custom_commands = load_custom_commands()

    # Render header banner
    render_header(
        model=f"{provider_name}/{model_name}",
        runtime=provider_name.capitalize(),
        mode="Autonomous",
        sandbox="Docker",
        browser="Playwright",
        status="Ready"
    )

    # Normal startup is fast; full diagnostics belong in 'buzzard doctor'

    current_session_id = None
    console.print(f"[dim]Type [bold cyan]/help[/bold cyan] for commands, or enter a natural language security prompt.[/dim]\n")

    # Main REPL loop
    while True:
        try:
            # Refresh custom commands dynamically
            custom_commands = load_custom_commands()
            user_input = input("buzzard> ").strip()
            if not user_input:
                continue

            # Handle Slash Commands
            if user_input.startswith("/"):
                tokens = user_input.split()
                command = tokens[0].lower()
                cmd_name = command[1:]
                subparts = user_input.split(maxsplit=2)

                if command == "/exit":
                    console.print("[bold cyan]Exiting interactive session. Goodbye![/bold cyan]")
                    break

                elif command == "/help":
                    print_help(custom_commands)

                elif command == "/clear":
                    os.system("clear" if os.name != "nt" else "cls")

                elif command == "/new":
                    current_session_id = None
                    console.print("[bold green]✓ Started fresh assessment session.[/bold green]")

                elif command == "/status":
                    if len(tokens) > 1:
                        get_task_status(tokens[1])
                    elif current_session_id:
                        get_task_status(current_session_id)
                    else:
                        run_status(config)

                elif command == "/doctor":
                    run_doctor()

                elif command == "/config":
                    sub = tokens[1] if len(tokens) > 1 else "show"
                    run_config(action=sub)

                elif command == "/tools":
                    t_name = tokens[1] if len(tokens) > 1 else None
                    render_tools(tool_name=t_name)

                elif command == "/providers":
                    plist = list_supported_providers()
                    table = Table(title="SUPPORTED MODEL PROVIDERS", show_header=True, header_style="bold cyan")
                    table.add_column("Provider ID", style="bold green")
                    table.add_column("Name")
                    table.add_column("Type")
                    table.add_column("Auth Required")
                    table.add_column("Description")
                    for p in plist:
                        typ = "Local" if p["is_local"] else "Cloud API"
                        auth = "Yes" if p["requires_auth"] else "No"
                        table.add_row(p["id"], p["name"], typ, auth, p["description"])
                    console.print()
                    console.print(table)
                    console.print("\n[dim]Use '/connect <provider>' to configure credentials.[/dim]\n")

                elif command == "/connect":
                    if len(tokens) < 2:
                        console.print("[bold red]Usage: /connect <provider> [api_key][/bold red]")
                        continue
                    p_to_conn = tokens[1]
                    key_to_conn = tokens[2] if len(tokens) > 2 else None
                    run_connect(p_to_conn, api_key=key_to_conn)
                    # Re-instantiate provider
                    config = load_merged_config()
                    provider = get_model_provider(config=config)

                elif command == "/disconnect":
                    if len(tokens) < 2:
                        console.print("[bold red]Usage: /disconnect <provider>[/bold red]")
                        continue
                    run_disconnect(tokens[1])

                elif command == "/models":
                    run_models()

                elif command == "/model":
                    raw_model = config.get("model")
                    curr_m = raw_model.get("name", "qwen3:8b") if isinstance(raw_model, dict) else str(raw_model or "qwen3:8b")
                    curr_p = raw_model.get("provider", "ollama") if isinstance(raw_model, dict) else "ollama"
                    if len(tokens) == 1:
                        console.print(f"[bold cyan]Active Provider:[/bold cyan] {curr_p}")
                        console.print(f"[bold cyan]Active Model:[/bold cyan]    {curr_m}")
                        try:
                            avail = provider.get_available_models() if provider and hasattr(provider, "get_available_models") else []
                            for m in avail:
                                marker = " (active)" if m == curr_m else ""
                                console.print(f"  • {m}{marker}")
                        except Exception:
                            pass
                        console.print("\nType [bold cyan]/model <name>[/bold cyan] or [bold cyan]/model <provider>/<name>[/bold cyan] to switch.")
                    else:
                        spec = tokens[1]
                        resolved_p, resolved_m = resolve_provider_and_model(spec, config)
                        if isinstance(config.get("model"), dict):
                            config["model"]["provider"] = resolved_p
                            config["model"]["name"] = resolved_m
                        else:
                            config["model"] = resolved_m
                        save_config(config)
                        provider = get_model_provider(config=config)
                        console.print(f"[bold green]Model switched successfully to '{resolved_m}'.[/bold green]")

                elif command in ("/scope",):
                    if len(tokens) == 1 or tokens[1].lower() == "list":
                        render_scope(config)
                    elif tokens[1].lower() == "add" and len(tokens) >= 3:
                        modify_scope("add", tokens[2], config)
                    elif tokens[1].lower() == "remove" and len(tokens) >= 3:
                        modify_scope("remove", tokens[2], config)
                    elif tokens[1].lower() in ("toggle-network", "toggle_network", "network"):
                        modify_scope("toggle-network", config=config)
                    else:
                        console.print("[bold red]Usage: /scope [list|add <host>|remove <host>|toggle-network][/bold red]")

                elif command in ("/permissions", "/policy"):
                    render_policy_and_permissions(config)

                elif command == "/sandbox":
                    render_sandbox_status()

                elif command == "/kill":
                    trigger_kill_switch("Operator invoked /kill from CLI")

                elif command == "/resume":
                    confirm = (len(tokens) > 1 and tokens[1].lower() in ("confirm", "yes", "y", "true"))
                    ks = KillSwitch.get_instance()
                    if ks.is_triggered():
                        resume_kill_switch(confirm=confirm)
                    elif len(tokens) > 1 and not confirm:
                        resume_task(tokens[1])
                    else:
                        resume_kill_switch(confirm=True)

                elif command in ("/history", "/tasks"):
                    list_tasks()

                elif command == "/logs":
                    t_id = tokens[1] if len(tokens) > 1 else current_session_id
                    if not t_id:
                        console.print("[bold yellow]Specify task ID: /logs <task_id>[/bold yellow]")
                    else:
                        get_task_status(t_id)

                elif command == "/export":
                    t_id = tokens[1] if len(tokens) > 1 else current_session_id
                    if not t_id:
                        console.print("[bold yellow]Specify task ID: /export <task_id>[/bold yellow]")
                    else:
                        try:
                            rpt = generate_report(t_id)
                            console.print(f"[bold green]✓ Report exported:[/bold green] {rpt}")
                        except Exception as e:
                            console.print(f"[bold red]Export failed: {e}[/bold red]")

                elif command == "/init":
                    force_flag = ("--force" in tokens or "-f" in tokens)
                    ok, msg, _ = init_project(force=force_flag)
                    if ok:
                        console.print(f"[bold green]✓ {msg}[/bold green]")
                    else:
                        console.print(f"[bold yellow]! {msg}[/bold yellow]")

                elif command == "/pause":
                    t_id = tokens[1] if len(tokens) > 1 else current_session_id
                    if not t_id:
                        console.print("[bold yellow]No active task to pause.[/bold yellow]")
                    else:
                        from security_agent.storage.db import TaskStatus
                        storage.update_session_status(t_id, TaskStatus.PAUSED)
                        console.print(f"[bold yellow]Task '{t_id}' paused.[/bold yellow]")

                elif command == "/diff":
                    target_path = tokens[1] if len(tokens) > 1 else None
                    from security_agent.tools.git_tools import git_diff
                    diff_res = git_diff(path=target_path)
                    if diff_res.startswith("Error"):
                        console.print(f"[bold red]{diff_res}[/bold red]")
                    elif diff_res.startswith("No working tree changes") or diff_res.startswith("No staged changes"):
                        console.print("[dim]No uncommitted changes in current workspace repository.[/dim]")
                    else:
                        from rich.syntax import Syntax
                        console.print(Syntax(diff_res, "diff", theme="monokai", line_numbers=False))

                elif command in ("/stop", "/abort"):
                    t_id = tokens[1] if len(tokens) > 1 else current_session_id
                    if not t_id:
                        console.print("[bold yellow]No active task to stop.[/bold yellow]")
                    else:
                        from security_agent.storage.db import TaskStatus
                        storage.update_session_status(t_id, TaskStatus.FAILED)
                        if current_session_id == t_id:
                            current_session_id = None
                        console.print(f"[bold yellow]Task '{t_id}' stopped.[/bold yellow]")

                elif cmd_name in custom_commands:
                    # Execute custom command from .buzzard/commands/<cmd_name>.md
                    cmd_def = custom_commands[cmd_name]
                    args = tokens[1:]
                    rendered_prompt = render_custom_command_prompt(cmd_def, args)
                    console.print(f"[bold magenta]Executing custom command /{cmd_name}...[/bold magenta]")
                    _execute_agent_task(rendered_prompt, provider, storage, config)

                else:
                    console.print(f"[bold red]Unknown command: {command}. Type /help for all commands.[/bold red]")

                continue

            # Natural language processing
            if not _is_actionable_audit_task(user_input):
                # Conversational chat mode with LLM
                chat_prompt = [
                    {
                        "role": "system",
                        "content": (
                            "You are Buzzard Code, an expert security agent and penetration testing assistant. "
                            "You provide concise, highly technical offensive and defensive security analysis, "
                            "exploit mechanics, and assessment strategy."
                        )
                    },
                    {"role": "user", "content": user_input}
                ]
                with console.status(f"[bold cyan]Thinking with {provider_name}/{model_name}...[/bold cyan]", spinner="dots"):
                    try:
                        resp = provider.chat(chat_prompt)
                        msg_content = resp.get("message", {}).get("content", "")
                    except Exception as e:
                        console.print(f"[bold red]Provider error: {e}[/bold red]\n")
                        continue

                if msg_content:
                    console.print(Markdown(msg_content.strip()))
                    console.print()
                continue

            # Security audit task execution
            current_session_id = _execute_agent_task(user_input, provider, storage, config)

        except KeyboardInterrupt:
            console.print("\n[bold yellow]Session interrupted. Type /exit to quit.[/bold yellow]\n")
        except EOFError:
            console.print("\n[bold cyan]Exiting interactive session. Goodbye![/bold cyan]")
            break

def _execute_agent_task(
    task_goal: str,
    provider: Any,
    storage: StorageManager,
    config: Dict[str, Any]
) -> Optional[str]:
    """
    Internal runner for security audit tasks.
    Enforces KillSwitch, Scope, PolicyEngine, ToolRegistry, and DockerSandbox.
    """
    ks = KillSwitch.get_instance()
    if ks.is_triggered():
        console.print("[bold red]EXECUTION BLOCKED: Kill switch is currently triggered. Disarm via /resume before testing.[/bold red]")
        return None

    sec_cfg = config.get("security", {})
    scope = list(sec_cfg.get("scope", ["localhost", "127.0.0.1"]))
    from security_agent.agent.intent import is_coding_task
    is_coding = is_coding_task(task_goal)
    mentioned_targets = _extract_targets_from_text(task_goal)
    out_of_scope = [t for t in mentioned_targets if not is_in_scope(t, scope)] if not is_coding else []

    if out_of_scope:
        console.print(f"\n[bold yellow]⚠ The following target(s) are not in your authorized scope:[/bold yellow]")
        for t in out_of_scope:
            console.print(f"  • [red]{t}[/red]")
        console.print(f"[dim]Authorized scope: {', '.join(scope)}[/dim]")
        try:
            confirm = input("Add these target(s) to authorized scope and proceed? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Cancelled.[/yellow]")
            return None
        if confirm in ("y", "yes"):
            for t in out_of_scope:
                if t not in scope:
                    scope.append(t)
            sec_cfg["scope"] = scope
            save_global_config(config)
            console.print(f"[bold green]Scope updated: {', '.join(scope)}[/bold green]")
        else:
            console.print("[yellow]Assessment cancelled. Use '/scope add <host>' to authorize targets.[/yellow]")
            return None

    primary_target = mentioned_targets[0] if mentioned_targets else scope[0]
    session_id = f"task-{uuid.uuid4().hex[:8]}"

    if is_coding:
        console.print(f"\n[bold cyan]Launching Buzzard Code Coding Task [{session_id}]...[/bold cyan]")
        console.print(f"  Mode: Coding Agent | Goal: {task_goal[:70]}")
    else:
        console.print(f"\n[bold cyan]Launching Buzzard Code Assessment [{session_id}]...[/bold cyan]")
        console.print(f"  Target: {primary_target} | Goal: {task_goal[:70]}")

    loop = AgentLoop(
        provider=provider,
        storage_manager=storage,
        config=config,
    )

    try:
        result = loop.run(
            task_goal=task_goal,
            target=primary_target,
            scope=scope,
            session_id=session_id
        )
        status = result.get("status", "completed") if isinstance(result, dict) else "completed"
        console.print(f"\n[dim]Task {session_id} finished with status: {status}[/dim]\n")
        return session_id
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Agent task interrupted.[/bold yellow]\n")
        return session_id
    except Exception as e:
        console.print(f"\n[bold red]Agent error: {e}[/bold red]\n")
        return session_id

# Backward compatibility aliases for interactive tests
load_config = load_merged_config
save_config = save_global_config
