"""
First-Run Setup Wizard for Buzzard Code.

Guides new users through system verification, sandbox checks, provider selection, model choice,
and secure credential storage on fresh installations.
"""

from cli.banner import render_banner
import copy
import sys
import os
import shutil
import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from core.config import (
    get_global_config_file,
    save_global_config,
    load_merged_config,
    get_setup_state,
    save_setup_state,
    is_setup_completed,
    DEFAULT_CONFIG,
)
from core.credentials import (
    set_credential,
    get_credential,
)
from system.doctor import EnvironmentDoctor
from model.factory import (
    get_model_provider,
    list_supported_providers,
)
from sandbox.container import is_docker_active

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
    console.print(render_banner(console.width))
    console.print("\n[bold]Welcome to Buzzard Code.[/bold] Let's get you running.\n")

    # Docker / Sandbox check
    docker_cli = shutil.which("docker")
    docker_active = is_docker_active()
    sandbox_status = "ready" if docker_active else ("daemon_down" if docker_cli else "missing")

    if not docker_active:
        console.print(Panel(
            "[bold]Docker is optional.[/bold] It isn't running, and that's fine for most coding work.\n\n"
            "Without it, each command you approve runs on this machine with [bold]no isolation[/bold],\n"
            "so read every command. Use Docker for untrusted code. Security tools stay blocked without it.",
            title="[yellow]Sandbox[/yellow]",
            border_style="yellow"
        ))

        if not sys.stdin.isatty():
            console.print("[dim]Non-interactive environment: Continuing without active Docker sandbox.[/dim]")
            sandbox_status = "unavailable"
        else:
            console.print("\n[bold]Choose an option:[/bold]")
            console.print("  [bold cyan]1[/bold cyan]) Install / Start Docker (view setup instructions)")
            console.print("  [bold cyan]2[/bold cyan]) Continue without Docker (approve each command)")
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
        ("1", "openrouter", "OpenRouter: Meta Muse and many others with one key"),
        ("2", "meta", "Meta Model API: Muse Spark"),
        ("3", "ollama", "Ollama: local and private (localhost:11434)"),
        ("4", "gemini", "Google Gemini"),
        ("5", "anthropic", "Anthropic Claude"),
        ("6", "openai", "OpenAI"),
        ("7", "openai-compatible", "Other OpenAI-compatible endpoint (vLLM, Groq, LM Studio)"),
        ("8", "later", "Configure later (defaults to local Ollama)"),
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
        choices=[num for num, _, _ in providers],
        default="1"
    )
    selected = next(pid for num, pid, _ in providers if num == choice)

    config = copy.deepcopy(DEFAULT_CONFIG)
    if selected != "later":
        _configure_provider(selected, config)
        _configure_fallbacks(config)
        _test_connection(config)
    else:
        console.print("[dim]Using local Ollama settings. Reconfigure anytime with 'buzzard setup'.[/dim]")

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

    console.print("\n[bold green]✓ Buzzard Code is ready.[/bold green]\n")
    console.print("Next, open a project and start:")
    console.print("  [bold cyan]cd your-project[/bold cyan]")
    console.print("  [bold cyan]buzzard tui[/bold cyan]\n")
    console.print("[dim]Check your setup anytime with 'buzzard doctor'.[/dim]\n")
    return True


# provider id -> (credential name, default model, API key page)
CLOUD_PROVIDERS = {
    "meta": ("meta", "muse-spark-1.1", "https://dev.meta.ai"),
    "gemini": ("gemini", "gemini-3.5-flash-lite", "https://aistudio.google.com/apikey"),
    "anthropic": ("anthropic", "", "https://console.anthropic.com"),
    "openai": ("openai", "", "https://platform.openai.com/api-keys"),
}
OPENROUTER_URL = "https://openrouter.ai/api/v1"
OPENROUTER_DEFAULT_MODEL = "meta/muse-glimmer-30b"


def _ask_key(credential_name: str, label: str, signup_url: str = "", optional: bool = False) -> None:
    """Asks for an API key without echoing it, unless one is already available."""
    if get_credential(credential_name):
        console.print(f"[green]✓ Found a saved {label} key.[/green]")
        return
    if signup_url:
        console.print(f"[dim]Get a key at {signup_url}[/dim]")
    suffix = " (optional, press Enter to skip)" if optional else ""
    key = Prompt.ask(f"{label} API key{suffix}", password=True, default="" if optional else None)
    if key and key.strip():
        set_credential(credential_name, key.strip())
        console.print("[green]✓ Key saved to your user config, outside any repository.[/green]")


def _looks_like_api_key(value: str) -> bool:
    """Model names are short and readable; a pasted key would be saved and shown on screen."""
    text = value.strip()
    return text.lower().startswith(("sk-", "sk_", "ghp_", "aiza", "aq.", "hf_", "xai-")) or (
        len(text) >= 40 and " " not in text and "/" not in text and any(c.isdigit() for c in text)
    )


def _ask_model(default: Optional[str]) -> str:
    """Asks for a model name, refusing anything that looks like an API key."""
    while True:
        answer = Prompt.ask("Model name (press Enter for the default)", default=default)
        if not _looks_like_api_key(answer or ""):
            return answer
        console.print("[yellow]! That looks like an API key, not a model name. It was not saved.[/yellow]")


def _configure_provider(selected: str, config: Dict[str, Any]) -> None:
    model = config["model"]
    if selected == "openrouter":
        model["provider"] = "openai-compatible"
        model["endpoint"] = OPENROUTER_URL
        _ask_key("openai-compatible", "OpenRouter", "https://openrouter.ai/keys")
        model["name"] = _ask_model(OPENROUTER_DEFAULT_MODEL)
    elif selected == "ollama":
        model["provider"] = "ollama"
        host = Prompt.ask("Ollama server URL", default="http://localhost:11434")
        model["endpoint"] = host
        provider = get_model_provider(provider_name="ollama", config=config, host=host)
        models = provider.get_available_models() if provider.is_available() else []
        if models:
            console.print(f"[green]✓ Ollama reachable ({len(models)} models).[/green]")
            model["name"] = Prompt.ask("Model", choices=models, default=models[0])
        else:
            console.print("[yellow]! No Ollama models found. Start it with 'ollama serve', then 'ollama pull <model>'.[/yellow]")
            model["name"] = _ask_model("qwen3:8b")
    elif selected == "openai-compatible":
        model["provider"] = "openai-compatible"
        model["endpoint"] = Prompt.ask("Base URL", default="http://localhost:8000/v1")
        model["name"] = _ask_model("default")
        _ask_key("openai-compatible", "Endpoint", optional=True)
    else:
        credential, default_model, signup_url = CLOUD_PROVIDERS[selected]
        model["provider"] = selected
        model.pop("endpoint", None)
        _ask_key(credential, selected.capitalize(), signup_url)
        model["name"] = _ask_model(default_model or None)


def _configure_fallbacks(config: Dict[str, Any]) -> None:
    """Fallbacks must be chosen by the user, because they can send code to another host."""
    console.print("\n[bold cyan]Backup models[/bold cyan] [dim](optional)[/dim]")
    console.print("If your model fails, Buzzard moves to the next one. Your code then goes to that provider.")
    console.print("[dim]Example: gemini/gemini-3.5-flash-lite, ollama/llama3[/dim]")
    answer = Prompt.ask("Backup models, comma-separated (Enter to skip)", default="")
    fallbacks = [spec.strip() for spec in answer.split(",") if spec.strip()]
    if fallbacks:
        config["model"]["fallbacks"] = fallbacks
        console.print(f"[green]✓ {len(fallbacks)} backup model(s) saved. Their API keys come from the environment or 'buzzard setup'.[/green]")


def _test_connection(config: Dict[str, Any]) -> None:
    """Offers one small real request, since an API key can look valid and still fail."""
    if not Confirm.ask("\nSend one short test message to check it works? (uses a few tokens)", default=True):
        return
    try:
        provider = get_model_provider(config=config)
        reply = provider.chat(
            [{"role": "user", "content": "Reply with the single word: ready"}],
            options={"max_tokens": 200} if config["model"]["provider"] not in ("ollama", "gemini") else None,
        )
        text = ((reply.get("message") or {}).get("content") or "").strip()
        console.print(f"[green]✓ {getattr(provider, 'model_name', 'Model')} responded: {text[:60] or '(empty reply)'}[/green]")
    except Exception as e:  # The wizard reports any failure and still finishes
        console.print(f"[yellow]! The test failed: {e}[/yellow]")
        console.print("[dim]Setup will still finish. Fix this, then run 'buzzard setup' or 'buzzard doctor'.[/dim]")
