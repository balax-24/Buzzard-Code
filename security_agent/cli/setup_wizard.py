"""
First-Run Setup Wizard for Buzzard Code.

Guides new users through system verification, sandbox checks, provider selection, model choice,
and secure credential storage on fresh installations.
"""

from security_agent.cli.banner import render_banner
import sys
import os
import shutil
import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from security_agent.core.config import (
    get_global_config_file,
    save_global_config,
    load_merged_config,
    get_setup_state,
    save_setup_state,
    is_setup_completed,
    DEFAULT_CONFIG,
)
from security_agent.core.credentials import (
    set_credential,
    get_credential,
)
from security_agent.system.doctor import EnvironmentDoctor
from security_agent.model.factory import (
    get_model_provider,
    list_supported_providers,
)
from security_agent.sandbox.container import is_docker_active

console = Console()

def is_first_run() -> bool:
    """Checks if first-run setup has not yet been completed."""
    return not is_setup_completed()

def run_first_run_wizard(force: bool = False) -> bool:
    """
    Executes first-run interactive setup workflow.
    """
    if not force and not is_first_run():
        return True

    console.print()
    console.print(Panel.fit(
        "[bold cyan]BUZZARD CODE v1.0.0[/bold cyan]\n"
        "[dim]AI Security Agent Runtime — First-Time Setup[/dim]",
        border_style="cyan"
    ))
    console.print(render_banner(console.width))
    console.print("\n[bold]Welcome to Buzzard Code.[/bold]\n")

    # Docker / Sandbox check
    docker_cli = shutil.which("docker")
    docker_active = is_docker_active()
    sandbox_status = "ready" if docker_active else ("daemon_down" if docker_cli else "missing")

    if not docker_active:
        console.print(Panel(
            "[bold yellow]Buzzard security sandbox requires Docker.[/bold yellow]\n\n"
            "Docker is not currently running or not installed.\n"
            "Security tools (e.g. terminal execution, nmap, sqlmap) require Docker container isolation.\n"
            "Native-safe tools (e.g. calculator) remain available.\n"
            "[dim]Fail-closed security is always enforced: tools requiring sandbox will not execute without it.[/dim]",
            title="[yellow]Sandbox Advisory[/yellow]",
            border_style="yellow"
        ))

        if not sys.stdin.isatty():
            console.print("[dim]Non-interactive environment: Continuing without active Docker sandbox.[/dim]")
            sandbox_status = "unavailable"
        else:
            console.print("\n[bold]Choose an option:[/bold]")
            console.print("  [bold cyan]1[/bold cyan]) Install / Start Docker (view setup instructions)")
            console.print("  [bold cyan]2[/bold cyan]) Continue without sandbox (safe tools only)")
            console.print("  [bold cyan]3[/bold cyan]) Exit setup")

            docker_choice = Prompt.ask("\nChoose an option", choices=["1", "2", "3"], default="2")

            if docker_choice == "1":
                console.print("\n[bold cyan]Docker Installation Instructions:[/bold cyan]")
                if sys.platform == "win32":
                    console.print("  - Download Docker Desktop for Windows:")
                    console.print("    [bold underline]https://docs.docker.com/desktop/install/windows-install/[/bold underline]")
                    console.print("  - Or via winget: [bold cyan]winget install Docker.DockerDesktop[/bold cyan]")
                elif sys.platform == "darwin":
                    console.print("  - Download Docker Desktop for macOS:")
                    console.print("    [bold underline]https://docs.docker.com/desktop/install/mac-install/[/bold underline]")
                    console.print("  - Or via Homebrew: [bold cyan]brew install --cask docker[/bold cyan]")
                else:
                    console.print("  - Install Docker on Linux:")
                    console.print("    [bold cyan]sudo apt-get update && sudo apt-get install -y docker.io[/bold cyan]")
                    console.print("    [bold cyan]sudo usermod -aG docker $USER[/bold cyan]")

                if Confirm.ask("\nIs Docker running now?", default=False):
                    if is_docker_active():
                        console.print("[bold green]✓ Docker detected and running![/bold green]")
                        sandbox_status = "ready"
                    else:
                        console.print("[yellow]! Docker still not detected. Proceeding with sandbox disabled.[/yellow]")
                        sandbox_status = "unavailable"
                else:
                    sandbox_status = "unavailable"
            elif docker_choice == "3":
                console.print("\n[dim]Setup cancelled. Run 'buzzard' again after starting Docker.[/dim]\n")
                sys.exit(0)
            else:
                sandbox_status = "unavailable"
    else:
        console.print("[green]✓ Docker sandbox environment ready.[/green]")

    console.print("\n[bold cyan]Select Model Provider:[/bold cyan]")
    providers = [
        ("1", "ollama", "Ollama (Local default - localhost:11434)"),
        ("2", "openai", "OpenAI (GPT-4o, GPT-4o-mini, o1, o3)"),
        ("3", "gemini", "Google Gemini (Gemini 2.0 Flash, Gemini 1.5 Pro)"),
        ("4", "anthropic", "Anthropic (Claude 3.5 Sonnet, Claude 3.7)"),
        ("5", "openai-compatible", "OpenAI-Compatible Custom Endpoint (vLLM, Groq, LMStudio)"),
        ("6", "later", "Configure later (Default to local Ollama)"),
    ]

    for num, pid, desc in providers:
        console.print(f"  [bold cyan]{num}[/bold cyan]) {desc}")

    # If non-interactive environment (CI, pipeline, redirected stdin), select default
    if not sys.stdin.isatty():
        console.print("\n[dim]Non-interactive environment detected. Initializing with default Ollama configuration.[/dim]")
        save_global_config(DEFAULT_CONFIG)
        state = get_setup_state()
        state["installation_initialized"] = True
        state["setup_completed"] = True
        state["configured_provider"] = "ollama"
        state["configured_model"] = "qwen3:8b"
        state["sandbox_status"] = sandbox_status
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not state.get("installed_at"):
            state["installed_at"] = now_str
        state["updated_at"] = now_str
        save_setup_state(state)
        return True

    choice = Prompt.ask(
        "\nChoose an option",
        choices=["1", "2", "3", "4", "5", "6"],
        default="1"
    )

    config = dict(DEFAULT_CONFIG)

    if choice == "1":
        # Ollama
        config["model"]["provider"] = "ollama"
        host = Prompt.ask("Ollama server URL", default="http://localhost:11434")
        config["model"]["endpoint"] = host
        prov = get_model_provider(provider_name="ollama", host=host)
        if prov.is_available():
            models = prov.get_available_models()
            if models:
                console.print(f"[green]✓ Ollama reachable ({len(models)} models available)[/green]")
                model_name = Prompt.ask("Select default model", choices=models, default=models[0])
                config["model"]["name"] = model_name
            else:
                console.print("[yellow]! Ollama reachable, but no models installed.[/yellow]")
                model_name = Prompt.ask("Default model to configure", default="qwen3:8b")
                config["model"]["name"] = model_name
                console.print(f"[dim]Run 'ollama pull {model_name}' to download.[/dim]")
        else:
            console.print("[yellow]! Ollama service not currently detected. You can start it anytime with 'ollama serve'.[/yellow]")
            config["model"]["name"] = "qwen3:8b"

    elif choice in ("2", "3", "4"):
        provider_map = {"2": "openai", "3": "gemini", "4": "anthropic"}
        p_name = provider_map[choice]
        config["model"]["provider"] = p_name

        existing_key = get_credential(p_name)
        if existing_key:
            console.print(f"[green]✓ Detected {p_name.upper()}_API_KEY from environment or store.[/green]")
        else:
            key = Prompt.ask(f"Enter your {p_name.capitalize()} API key (stored securely in user config)", password=True)
            if key and key.strip():
                set_credential(p_name, key.strip())
                console.print(f"[green]✓ Credential saved securely.[/green]")

        if p_name == "openai":
            config["model"]["name"] = Prompt.ask("Select model", default="gpt-4o")
        elif p_name == "gemini":
            config["model"]["name"] = Prompt.ask("Select model", default="gemini-2.0-flash")
        elif p_name == "anthropic":
            config["model"]["name"] = Prompt.ask("Select model", default="claude-3-5-sonnet-20241022")

    elif choice == "5":
        # OpenAI compatible
        config["model"]["provider"] = "openai-compatible"
        endpoint = Prompt.ask("Base URL", default="http://localhost:8000/v1")
        config["model"]["endpoint"] = endpoint
        model_name = Prompt.ask("Model Name", default="default")
        config["model"]["name"] = model_name
        key = Prompt.ask("API Key (optional, press Enter if not required)", password=True, default="")
        if key.strip():
            set_credential("openai-compatible", key.strip())

    else:
        # Later
        console.print("[dim]Using default local Ollama settings. You can reconfigure anytime via 'buzzard /connect <provider>'.[/dim]")

    save_global_config(config)

    # Persist first-run state
    state = get_setup_state()
    state["installation_initialized"] = True
    state["setup_completed"] = True
    state["configured_provider"] = config.get("model", {}).get("provider", "ollama")
    state["configured_model"] = config.get("model", {}).get("name", "qwen3:8b")
    state["sandbox_status"] = sandbox_status
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if not state.get("installed_at"):
        state["installed_at"] = now_str
    state["updated_at"] = now_str
    save_setup_state(state)

    console.print("\n[bold green]✓ Buzzard Code initialized successfully![/bold green]\n")
    return True
