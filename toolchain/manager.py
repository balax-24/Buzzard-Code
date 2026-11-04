import sys
from typing import Dict, List, Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED
from cli.renderer import console
from tools.registry import ToolRegistry
from tools.basic import register_basic_tools
from tools.security import register_security_tools
from tools.browser import register_browser_tools
from tools.http import register_http_tools
from tools.http_suite import register_http_suite_tools
from tools.filesystem import register_filesystem_tools
from tools.source_audit import register_source_audit_tools
from tools.manifest_suite import register_manifest_tools
from tools.attack import register_attack_tools
from tools.arsenal import register_arsenal_tools
from tools.knowledge import register_knowledge_tools
from tools.evidence import register_evidence_tools
from toolchain.manifest import ToolchainManifest, ToolCategory, ToolDependency
from toolchain.checker import ToolchainChecker, CheckStatus, ToolCheckResult
from toolchain.installer import ToolchainInstaller
from sandbox.container import get_sandbox, is_docker_active, DockerSandbox


class ToolchainManager:
    """
    Orchestrates discovery, sandbox validation, automated image bootstrap, and health reporting.
    """
    def __init__(self, registry: Optional[ToolRegistry] = None, sandbox_image: Optional[str] = None):
        self.registry = registry or self._create_default_registry()
        self.manifest = ToolchainManifest.from_registry(self.registry)
        self.sandbox = DockerSandbox(image=sandbox_image or self.manifest.get_image_tag()) if is_docker_active() else get_sandbox()
        self.checker = ToolchainChecker(sandbox=self.sandbox)
        self.installer = ToolchainInstaller(manifest=self.manifest)

    @staticmethod
    def _create_default_registry() -> ToolRegistry:
        from tools.registry import create_authoritative_registry
        return create_authoritative_registry()

    def bootstrap(self, interactive: bool = True, skip_toolchain: bool = False, force_rebuild: bool = False) -> bool:
        """
        Runs the mandatory startup check before granting access to the interactive shell or agent loop.
        """
        if skip_toolchain:
            console.print("[bold yellow]WARNING: TOOLCHAIN CHECK BYPASSED (development mode)[/bold yellow]\n")
            return True

        if interactive:
            console.print(Panel(
                "[cyan]Checking security-agent runtime dependencies inside Docker sandbox...[/cyan]",
                title="[bold]Toolchain Initialization[/bold]",
                border_style="bright_blue",
                box=ROUNDED,
                expand=False
            ))
            console.print()

        # Step 1: Verify Docker availability
        docker_ok, docker_msg = self.checker.check_docker()
        if not docker_ok:
            self._render_blocked_panel(
                tool_name="Docker Sandbox",
                dependency="docker",
                status_msg="DOCKER DAEMON UNAVAILABLE",
                details="Docker daemon is not running or current user lacks permissions to connect to /var/run/docker.sock."
            )
            return False

        # Step 2: Ensure sandbox image is built
        image_tag = self.manifest.get_image_tag()
        if isinstance(self.sandbox, DockerSandbox):
            if force_rebuild or not self.installer.is_image_available(image_tag):
                if interactive:
                    console.print(f"[dim]Building updated toolchain image ({image_tag})...[/dim]")
                build_ok, build_msg = self.installer.build_sandbox_image(image_tag=image_tag, force_rebuild=force_rebuild)
                if build_ok:
                    self.sandbox = DockerSandbox(image=image_tag)
                    self.checker = ToolchainChecker(sandbox=self.sandbox)
                else:
                    self.sandbox = DockerSandbox(image="alpine:latest")
                    self.checker = ToolchainChecker(sandbox=self.sandbox)
            else:
                self.sandbox = DockerSandbox(image=image_tag)
                self.checker = ToolchainChecker(sandbox=self.sandbox)

        # Step 3: Check all dependencies
        dependencies = self.manifest.get_all()
        total_deps = len(dependencies)
        check_results: Dict[str, ToolCheckResult] = {}
        missing_required: List[ToolDependency] = []

        for idx, dep in enumerate(dependencies, start=1):
            res = self.checker.check_dependency(dep)
            check_results[dep.name] = res

            if interactive:
                status_icon = "[bold green]✓[/bold green]" if res.status == CheckStatus.INSTALLED else ("[dim yellow]○[/dim yellow]" if not dep.required else "[bold red]✗[/bold red]")
                tool_display = f"[{idx}/{total_deps}] {dep.name:<25}"
                console.print(f"{tool_display} {status_icon}")

            if res.status != CheckStatus.INSTALLED and dep.required:
                missing_required.append(dep)

        if interactive:
            console.print()

        # Step 4: Handle missing required dependencies
        if missing_required:
            if interactive:
                console.print(f"[bold yellow]Attempting automated toolchain build for {len(missing_required)} missing dependencies...[/bold yellow]")
            install_ok, install_msg = self.installer.install_missing(missing_required)
            if install_ok:
                if isinstance(self.sandbox, DockerSandbox):
                    self.sandbox = DockerSandbox(image=image_tag)
                    self.checker = ToolchainChecker(sandbox=self.sandbox)
                # Re-check
                missing_required = []
                for dep in dependencies:
                    res = self.checker.check_dependency(dep)
                    check_results[dep.name] = res
                    if res.status != CheckStatus.INSTALLED and dep.required:
                        missing_required.append(dep)

            if missing_required:
                first_missing = missing_required[0]
                self._render_blocked_panel(
                    tool_name=first_missing.name,
                    dependency=first_missing.package,
                    status_msg="INSTALL FAILED",
                    details=f"Required executable '{first_missing.executable}' could not be verified inside Docker sandbox."
                )
                return False

        # Step 5: Render Startup Health Report
        if interactive:
            self._render_health_report(check_results, image_tag=image_tag)

        return True

    def _render_blocked_panel(self, tool_name: str, dependency: str, status_msg: str, details: str):
        content = f"""[bold red]Required tool unavailable: {tool_name}[/bold red]

Dependency: [bold]{dependency}[/bold]
Status:     [bold red]{status_msg}[/bold red]

{details}

[bold yellow]Autonomous execution cannot start.[/bold yellow]
"""
        console.print(Panel(
            content.strip(),
            title="[bold red]STARTUP BLOCKED[/bold red]",
            border_style="red",
            box=ROUNDED,
            expand=False
        ))
        console.print()

    def _render_health_report(self, results: Dict[str, ToolCheckResult], image_tag: str):
        manifest_hash = self.manifest.get_hash()
        
        # Calculate category statistics
        cat_stats = {}
        for cat in [ToolCategory.CORE, ToolCategory.NETWORK, ToolCategory.WEB, ToolCategory.BROWSER, ToolCategory.ANALYSIS]:
            deps_in_cat = self.manifest.get_by_category(cat)
            if not deps_in_cat:
                continue
            installed_count = sum(1 for d in deps_in_cat if results.get(d.name, None) and results[d.name].status == CheckStatus.INSTALLED)
            total_count = len(deps_in_cat)
            cat_stats[cat.value] = (installed_count, total_count, installed_count >= sum(1 for d in deps_in_cat if d.required))

        total_installed = sum(1 for r in results.values() if r.status == CheckStatus.INSTALLED)
        total_count = len(results)

        body_lines = [
            f"Sandbox Image: [bold cyan]{image_tag}[/bold cyan]",
            f"Toolchain:     [bold]{manifest_hash}[/bold]\n"
        ]

        for cat_name, (inst, tot, ok) in cat_stats.items():
            mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
            body_lines.append(f"{cat_name:<16} {inst}/{tot}   {mark}")

        body_lines.append(f"\nTotal:           {total_installed}/{total_count}")
        body_lines.append(f"\nDocker:          [bold green]READY[/bold green]")
        body_lines.append(f"Toolchain:       [bold green]READY[/bold green]")

        panel_content = "\n".join(body_lines)

        console.print(Panel(
            panel_content,
            title="[bold bright_cyan]BUZZARD TOOLCHAIN[/bold bright_cyan]",
            border_style="bright_blue",
            box=ROUNDED,
            expand=False
        ))
        console.print("[bold green]All required tools verified.[/bold green]\n")

    def run_cli(self, force_rebuild: bool = False):
        """
        Entry point for `uv run security-agent toolchain`.
        """
        console.print("[bold bright_cyan]BUZZARD CODE — TOOLCHAIN DIAGNOSTIC & BOOTSTRAP[/bold bright_cyan]\n")
        success = self.bootstrap(interactive=True, force_rebuild=force_rebuild)
        if not success:
            sys.exit(1)
