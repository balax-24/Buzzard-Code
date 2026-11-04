import click
import sys
from cli.commands import (
    run_doctor,
    run_status,
    run_models,
    run_tools,
    run_config,
    run_non_interactive_task,
    load_config,
    save_config,
    list_tasks,
    get_task_status,
    resume_task,
    generate_report,
)
from cli.interactive import start_interactive_session
from cli.setup_wizard import is_first_run, run_first_run_wizard
from core.project import init_project
from cli.renderer import console

@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0", prog_name="Buzzard Code")
@click.option("--skip-toolchain", is_flag=True, default=False, help="Bypass mandatory toolchain bootstrap check (development only).")
@click.option("--profile", is_flag=True, default=False, help="Enable detailed performance profiling breakdown.")
@click.option("--no-tui", is_flag=True, default=False, help="Disable TUI and use legacy line-based interactive REPL.")
@click.pass_context
def main(ctx, skip_toolchain, profile, no_tui):
    """
    Buzzard Code v1.0 — a terminal coding agent that must prove its work.
    If no command is provided, starts an interactive shell session.
    """
    if ctx.invoked_subcommand is None:
        if is_first_run():
            run_first_run_wizard()
        if sys.stdin.isatty() and not no_tui:
            try:
                from tui.app import BuzzardTUIApp
                app = BuzzardTUIApp()
                app.run()
            except Exception as e:
                console.print(f"[bold yellow]Notice: TUI initialization failed ({e}), falling back to line REPL.[/bold yellow]")
                start_interactive_session(skip_toolchain=skip_toolchain, profile=profile)
        else:
            start_interactive_session(skip_toolchain=skip_toolchain, profile=profile)

@main.command(name="run")
@click.argument("task_prompt")
@click.option("--model", "-m", default=None, help="Model override (e.g. ollama/qwen3:8b, gpt-4o, claude-3-5-sonnet).")
@click.option("--provider", "-p", default=None, help="Provider override (ollama, openai, gemini, anthropic, openai-compatible).")
@click.option("--target", "-t", default=None, help="Target host/URL.")
@click.option("--scope", "-s", multiple=True, help="Additional target hosts to authorize in scope.")
@click.option("--max-iterations", default=15, help="Maximum execution loop iterations.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress streaming output.")
def run_cmd(task_prompt, model, provider, target, scope, max_iterations, quiet):
    """
    Execute a non-interactive security assessment task through the full control plane.
    Enforces policy, scope, tool validation, sandbox isolation, and audit journaling.
    """
    run_non_interactive_task(
        prompt=task_prompt,
        model=model,
        provider=provider,
        target=target,
        scope=list(scope) if scope else None,
        max_iterations=max_iterations,
        quiet=quiet
    )

@main.command(name="init")
@click.option("--force", "-f", is_flag=True, default=False, help="Force overwrite existing configuration.")
def init_cmd(force):
    """
    Initialize a new Buzzard Code project workspace (buzzard.json and .buzzard/).
    """
    ok, msg, created = init_project(force=force)
    if ok:
        console.print(f"[bold green]✓ {msg}[/bold green]")
        for p in created:
            console.print(f"  • Created: [cyan]{p.name}[/cyan]")
    else:
        console.print(f"[bold yellow]! {msg}[/bold yellow]")

@main.command()
@click.option("--model", "-m", default=None, help="Model to run diagnostics against.")
def doctor(model):
    """
    Run diagnostic checks on the environment, tools, and model.
    """
    run_doctor(model_override=model)

@main.command()
@click.argument("task_id", required=False)
def status(task_id):
    """
    Show current agent configuration & sandbox status, or view a specific task.
    """
    if task_id:
        get_task_status(task_id)
    else:
        run_status()

@main.command()
@click.option("--provider", "-p", default=None, help="Provider to query models for.")
def models(provider):
    """
    List available models and inspect their capabilities.
    """
    run_models(provider_name=provider)

@main.command()
@click.argument("tool_name", required=False)
@click.option("--category", "-c", default=None, help="Filter tools by category.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Export tool inventory as JSON.")
def tools(tool_name, category, json_output):
    """
    List authoritative tool inventory or inspect parameters/schemas for a tool.
    """
    if tool_name:
        from tools.inspector import render_tools as r_tools
        r_tools(tool_name=tool_name)
    else:
        run_tools(category_filter=category, json_output=json_output)

@main.command()
@click.argument("action", default="show", type=click.Choice(["show", "path", "validate"]))
def config(action):
    """
    View or validate configuration settings (secrets strictly redacted).
    """
    run_config(action=action)

@main.command()
def setup():
    """
    Launch the interactive first-run setup wizard.
    """
    run_first_run_wizard(force=True)

@main.command()
@click.option("--force-rebuild", is_flag=True, default=False, help="Force rebuild of sandbox Docker image.")
def toolchain(force_rebuild):
    """
    Validate, build, and verify the security toolchain inside the Docker sandbox.
    """
    from toolchain.manager import ToolchainManager
    manager = ToolchainManager()
    manager.run_cli(force_rebuild=force_rebuild)

@main.command(name="server")
def server():
    """
    Start the Buzzard Code NDJSON IPC server for the TypeScript React+Ink TUI.
    """
    from cli.server import start_server
    start_server()

@main.command(name="tui")
@click.option("--model", "-m", default=None, help="Initial model name.")
@click.option("--mode", default=None, help="Initial operating mode.")
@click.option("--resume", "-r", is_flag=True, default=False, help="Resume most recent interrupted session.")
@click.option("--session", "-s", default=None, help="Specific session ID to resume.")
@click.option("--fake", is_flag=True, default=False, help="Run with deterministic FakeModelProvider.")
@click.option("--legacy", is_flag=True, default=False, help="Launch legacy prototype TUI.")
def tui_cmd(model, mode, resume, session, fake, legacy):
    """
    Start the Terminal User Interface (TUI).
    """
    if legacy:
        from tui.cli import main as tui_main
        ctx = click.get_current_context()
        ctx.invoke(tui_main, model=model, mode=mode, resume=resume, session=session, fake=fake)
    else:
        from tui.app import BuzzardTUIApp
        app = BuzzardTUIApp(model=model, mode=mode, resume=resume, session_id=session, fake=fake)
        app.run()

@main.command()
@click.argument("task_id")
def resume(task_id):
    """
    Resume an existing audit task.
    """
    resume_task(task_id)

@main.command()
@click.argument("task_id")
def report(task_id):
    """
    Generate or view findings report for a completed task.
    """
    try:
        path = generate_report(task_id)
        console.print(f"[bold green]Report generated successfully:[/bold green] {path}")
    except Exception as e:
        console.print(f"[bold red]Error generating report: {e}[/bold red]")

@main.command()
def tasks():
    """
    List all recorded audit tasks.
    """
    list_tasks()

@main.command()
def version():
    """
    Display the software version.
    """
    click.echo("Buzzard Code v1.0.0")

@main.command()
@click.option("--model", "-m", multiple=True, help="Specific model(s) to benchmark.")
def benchmark(model):
    """
    Run standardized security benchmarks across local models.
    """
    from cli.commands import run_benchmark
    run_benchmark(models=list(model) if model else None)

@main.command(name="bench-multiservice")
@click.option("--manifest", "-f", default="benchmarks/multi_service_manifest.yaml", help="Path to benchmark manifest.")
@click.option("--model", "-m", "model", multiple=True, help="Specific model(s) to benchmark.")
def bench_multiservice(manifest, model):
    """
    Run standardized multi-service laboratory benchmark.
    """
    from cli.commands import run_multiservice_benchmark
    run_multiservice_benchmark(manifest_path=manifest, models=list(model) if model else None)

@main.command()
def preflight():
    """
    Validate Docker sandbox isolation and resource limits before testing.
    """
    from sandbox.preflight import SandboxPreflightValidator, render_preflight_checks
    validator = SandboxPreflightValidator()
    render_preflight_checks(validator)

@main.command()
def runtime():
    """
    Inspect and smoke test the active security sandbox runtime and binaries.
    """
    from cli.commands import run_runtime
    run_runtime()

@main.command()
def toolcheck():
    """
    Audit module imports, tool contracts, and run live dispatcher smoke-tests.
    """
    from toolchain.toolcheck import run_toolcheck
    ok = run_toolcheck()
    if not ok:
        sys.exit(1)

@main.group()
def hack():
    """
    Direct hacking toolkit: run any fallback-chain capability without the LLM.
    """
    pass

@hack.command(name="list")
def hack_list():
    """
    List all available hacking capabilities.
    """
    from tools.arsenal import CAPABILITIES, CATEGORIES
    click.echo(f"{len(CAPABILITIES)} capabilities available across {len(CATEGORIES)} categories:\n")
    for category in sorted(CATEGORIES):
        click.echo(f"{category}")
        for name in sorted(CATEGORIES[category]):
            click.echo(f"  {name:<24} {CAPABILITIES[name]['desc']}")

@main.group()
def skills():
    """
    Manage autonomous agent skills/playbooks.
    """
    pass

@skills.command(name="list")
def list_skills():
    """
    List all installed/available agent skills.
    """
    from agent.skills import SkillManager
    manager = SkillManager()
    if not manager.skills:
        console.print("[yellow]No skills installed.[/yellow]")
        return
    console.print(f"[bold green]Installed Skills ({len(manager.skills)}):[/bold green]")
    for skill in manager.skills:
        origin = "Global" if skill["is_global"] else "Local"
        console.print(f"  • [bold cyan]{skill['name']}[/bold cyan] ({origin}) - {skill['description']}")


@main.command(name="uninstall")
@click.option("--purge-data", is_flag=True, default=False, help="Also remove all user configuration, credentials, and session logs.")
@click.option("--yes", "-y", is_flag=True, default=False, help="Confirm uninstallation without prompting.")
def uninstall_cmd(purge_data, yes):
    """
    Uninstall Buzzard Code standalone CLI and runtime components.
    Distinguishes program files from user data and configuration.
    """
    from core.config import get_global_config_dir
    import shutil
    import os
    import sys
    from pathlib import Path

    if not yes:
        if not click.confirm("Are you sure you want to uninstall Buzzard Code?", default=False):
            click.echo("Uninstallation aborted.")
            return

    # Determine installed paths
    if sys.platform == "win32":
        local_app = os.environ.get("LOCALAPPDATA")
        program_dir = Path(local_app) / "Programs" / "buzzard" if local_app else None
    else:
        program_dir = Path.home() / ".local" / "share" / "buzzard"
        bin_dir = Path.home() / ".local" / "bin"
        for shim in ["buzzard", "buzzard-code"]:
            shim_path = bin_dir / shim
            if shim_path.is_file():
                try:
                    shim_path.unlink()
                    click.echo(f"Removed launcher: {shim_path}")
                except Exception as e:
                    click.echo(f"Could not remove {shim_path}: {e}")

    if program_dir and program_dir.is_dir():
        try:
            shutil.rmtree(program_dir)
            click.echo(f"Removed program directory: {program_dir}")
        except Exception as e:
            click.echo(f"Could not remove {program_dir}: {e}")

    config_dir = get_global_config_dir()
    if purge_data:
        if not yes:
            if not click.confirm(f"Purge user configuration and credentials at {config_dir}?", default=False):
                click.echo(f"User configuration preserved at: {config_dir}")
                click.echo("Buzzard Code program files uninstalled successfully.")
                return
        if config_dir.is_dir():
            shutil.rmtree(config_dir)
            click.echo(f"Purged user configuration: {config_dir}")
    else:
        click.echo(f"[NOTE] User configuration, credentials, and session data were preserved at: {config_dir}")
        click.echo("To completely erase user data, delete that directory or re-run with --purge-data.")

    click.echo("Buzzard Code uninstallation completed.")

if __name__ == "__main__":
    main()
