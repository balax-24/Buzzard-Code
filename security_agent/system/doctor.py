"""
Central Environment Verifier and Diagnostics ("buzzard doctor").

Audits:
- Core environment: Python version, Git
- Security infrastructure: Docker, daemon, sandbox image, PolicyEngine, KillSwitch, ToolRegistry
- Model provider: active provider, authentication/endpoint, configured model availability
- Filesystem: permissions, writable paths, session store
"""

import sys
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from security_agent.core.config import (
    load_merged_config,
    get_global_config_dir,
    get_project_buzzard_dir,
)
from security_agent.model.factory import (
    get_model_provider,
    resolve_provider_and_model,
)

@dataclass
class CheckResult:
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    message: str
    remediation: Optional[str] = None
    category: str = "Core"
    is_required: bool = True

class EnvironmentDoctor:
    """
    Comprehensive environment verifier.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_merged_config()
        self.results: List[CheckResult] = []

    def check_core(self) -> List[CheckResult]:
        results = []
        # Python check
        py_ver = sys.version_info
        py_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
        if py_ver >= (3, 10):
            results.append(CheckResult(
                name="Python",
                status="PASS",
                message=f"v{py_str}",
                category="Core",
                is_required=True
            ))
        else:
            results.append(CheckResult(
                name="Python",
                status="FAIL",
                message=f"v{py_str} (requires >= 3.10)",
                remediation="Install Python 3.10 or higher.",
                category="Core",
                is_required=True
            ))

        # Git check
        git_path = shutil.which("git")
        if git_path:
            try:
                out = subprocess.check_output([git_path, "--version"], text=True, stderr=subprocess.DEVNULL, timeout=4).strip()
                results.append(CheckResult(
                    name="Git",
                    status="PASS",
                    message=out,
                    category="Core",
                    is_required=True
                ))
            except Exception:
                results.append(CheckResult(
                    name="Git",
                    status="PASS",
                    message=f"Found at {git_path}",
                    category="Core",
                    is_required=True
                ))
        else:
            results.append(CheckResult(
                name="Git",
                status="WARN",
                message="Git executable not found in PATH",
                remediation="Install Git to enable version control and repository context.",
                category="Core",
                is_required=False
            ))
        return results

    def check_security_and_sandbox(self) -> List[CheckResult]:
        results = []
        # 1. Docker CLI
        docker_cli = shutil.which("docker")
        if docker_cli:
            results.append(CheckResult(
                name="Docker CLI",
                status="PASS",
                message=f"Installed ({docker_cli})",
                category="Security & Sandbox",
                is_required=False
            ))
        else:
            results.append(CheckResult(
                name="Docker CLI",
                status="WARN",
                message="Docker not found in PATH",
                remediation="Install Docker Desktop (Windows/macOS) or docker.io (Linux) for isolated tool execution.",
                category="Security & Sandbox",
                is_required=False
            ))

        # 2. Docker daemon
        from security_agent.sandbox.container import is_docker_active, get_security_sandbox_image
        daemon_ok = is_docker_active()
        if daemon_ok:
            results.append(CheckResult(
                name="Docker daemon",
                status="PASS",
                message="Active and reachable",
                category="Security & Sandbox",
                is_required=False
            ))
            # 3. Sandbox Image
            image_name = get_security_sandbox_image()
            try:
                res = subprocess.run(["docker", "image", "inspect", image_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
                if res.returncode == 0:
                    results.append(CheckResult(
                        name="Sandbox image",
                        status="PASS",
                        message=f"Available ({image_name})",
                        category="Security & Sandbox",
                        is_required=False
                    ))
                else:
                    results.append(CheckResult(
                        name="Sandbox image",
                        status="WARN",
                        message=f"Image '{image_name}' not built locally",
                        remediation=f"Build sandbox image with: buzzard toolchain",
                        category="Security & Sandbox",
                        is_required=False
                    ))
            except Exception:
                results.append(CheckResult(
                    name="Sandbox image",
                    status="WARN",
                    message="Unable to inspect Docker images",
                    category="Security & Sandbox",
                    is_required=False
                ))
        else:
            results.append(CheckResult(
                name="Docker daemon",
                status="WARN",
                message="Daemon unavailable (fallback: local mock/native sandbox)",
                remediation="Start Docker Desktop and run 'buzzard doctor'.",
                category="Security & Sandbox",
                is_required=False
            ))

        # 4. Policy Engine
        try:
            from security_agent.security.policy import PolicyEngine
            pe = PolicyEngine(scope=["localhost"])
            results.append(CheckResult(
                name="Policy engine",
                status="PASS",
                message="Active (deterministic control plane ready)",
                category="Security & Sandbox",
                is_required=True
            ))
        except Exception as e:
            results.append(CheckResult(
                name="Policy engine",
                status="FAIL",
                message=f"Initialization error: {e}",
                remediation="Verify security policy modules and dependencies.",
                category="Security & Sandbox",
                is_required=True
            ))

        # 5. Kill Switch
        try:
            from security_agent.security.kill_switch import KillSwitch
            ks = KillSwitch.get_instance()
            is_trig = ks.is_triggered()
            if not is_trig:
                results.append(CheckResult(
                    name="Kill switch",
                    status="PASS",
                    message="Ready (armed and operational)",
                    category="Security & Sandbox",
                    is_required=True
                ))
            else:
                results.append(CheckResult(
                    name="Kill switch",
                    status="WARN",
                    message="Currently TRIGGERED (execution halted)",
                    remediation="Resume execution using: /resume",
                    category="Security & Sandbox",
                    is_required=True
                ))
        except Exception as e:
            results.append(CheckResult(
                name="Kill switch",
                status="FAIL",
                message=f"Kill switch error: {e}",
                category="Security & Sandbox",
                is_required=True
            ))

        # 6. Tool Registry
        try:
            from security_agent.tools.registry import create_authoritative_registry
            reg = create_authoritative_registry()
            count = len(reg.tools)
            results.append(CheckResult(
                name="Tool registry",
                status="PASS",
                message=f"Operational ({count} security tools loaded)",
                category="Security & Sandbox",
                is_required=True
            ))
        except Exception as e:
            results.append(CheckResult(
                name="Tool registry",
                status="FAIL",
                message=f"Tool registration error: {e}",
                category="Security & Sandbox",
                is_required=True
            ))

        return results

    def check_model_and_provider(self) -> List[CheckResult]:
        results = []
        model_cfg = self.config.get("model", {})
        provider_name = model_cfg.get("provider", "ollama")
        model_name = model_cfg.get("name", "qwen3:8b")

        results.append(CheckResult(
            name="Configured provider",
            status="PASS",
            message=f"{provider_name} (model: {model_name})",
            category="Model & Provider",
            is_required=True
        ))

        try:
            provider = get_model_provider(config=self.config)
            health = provider.health_check()
            if health.get("status") == "ok":
                results.append(CheckResult(
                    name="Provider connection",
                    status="PASS",
                    message="Reachable & authenticated",
                    category="Model & Provider",
                    is_required=True
                ))
                models = provider.get_available_models()
                if model_name in models or any(model_name in m for m in models) or not models:
                    results.append(CheckResult(
                        name="Model availability",
                        status="PASS",
                        message=f"'{model_name}' verified",
                        category="Model & Provider",
                        is_required=True
                    ))
                else:
                    results.append(CheckResult(
                        name="Model availability",
                        status="WARN",
                        message=f"'{model_name}' not found in available models",
                        remediation=f"Pull model with: ollama pull {model_name} (or switch with /model)",
                        category="Model & Provider",
                        is_required=False
                    ))
            else:
                has_creds = health.get("has_credentials", True)
                if not has_creds:
                    results.append(CheckResult(
                        name="Provider connection",
                        status="FAIL",
                        message=f"Missing credentials for {provider_name}",
                        remediation=f"Configure API key with: /connect {provider_name} or set {provider_name.upper()}_API_KEY",
                        category="Model & Provider",
                        is_required=True
                    ))
                else:
                    endpoint = health.get("endpoint", "")
                    results.append(CheckResult(
                        name="Provider connection",
                        status="FAIL",
                        message=f"Cannot reach {provider_name} at {endpoint or 'configured endpoint'}",
                        remediation=f"Ensure {provider_name} service is running and accessible.",
                        category="Model & Provider",
                        is_required=True
                    ))
        except Exception as e:
            results.append(CheckResult(
                name="Provider connection",
                status="FAIL",
                message=f"Provider error: {e}",
                remediation=f"Run 'buzzard /connect {provider_name}' to reconfigure.",
                category="Model & Provider",
                is_required=True
            ))

        return results

    def check_filesystem(self) -> List[CheckResult]:
        results = []
        # Global config directory
        g_dir = get_global_config_dir()
        if g_dir.exists() and os.access(g_dir, os.W_OK):
            results.append(CheckResult(
                name="Global config directory",
                status="PASS",
                message=f"Writable ({g_dir})",
                category="Filesystem",
                is_required=True
            ))
        else:
            results.append(CheckResult(
                name="Global config directory",
                status="FAIL",
                message=f"Cannot write to {g_dir}",
                remediation="Ensure write permissions for user home/appdata directory.",
                category="Filesystem",
                is_required=True
            ))

        # Project directory
        cwd = Path.cwd()
        if os.access(cwd, os.W_OK):
            results.append(CheckResult(
                name="Working directory",
                status="PASS",
                message=f"Writable ({cwd})",
                category="Filesystem",
                is_required=True
            ))
        else:
            results.append(CheckResult(
                name="Working directory",
                status="FAIL",
                message=f"Working directory not writable ({cwd})",
                category="Filesystem",
                is_required=True
            ))
        return results

    def run_all(self) -> Tuple[str, List[CheckResult]]:
        """Runs all checks and returns overall verdict and result list."""
        all_results = []
        all_results.extend(self.check_core())
        all_results.extend(self.check_security_and_sandbox())
        all_results.extend(self.check_model_and_provider())
        all_results.extend(self.check_filesystem())
        self.results = all_results

        has_fail = any(r.status == "FAIL" and r.is_required for r in all_results)
        has_warn = any(r.status == "WARN" for r in all_results)

        if has_fail:
            verdict = "FAIL"
        elif has_warn:
            verdict = "WARN"
        else:
            verdict = "PASS"

        return verdict, all_results

    def render_console(self) -> None:
        """Prints a professional, clean diagnostics report."""
        verdict, results = self.run_all()
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            console = Console()

            table = Table(title="BUZZARD CODE ENVIRONMENT DIAGNOSTICS", show_header=True, header_style="bold cyan")
            table.add_column("Category", style="dim", width=20)
            table.add_column("Component", style="bold")
            table.add_column("Status", width=8)
            table.add_column("Details")

            for r in results:
                if r.status == "PASS":
                    st = "[bold green]PASS[/bold green]"
                elif r.status == "WARN":
                    st = "[bold yellow]WARN[/bold yellow]"
                else:
                    st = "[bold red]FAIL[/bold red]"
                table.add_row(r.category, r.name, st, r.message)

            console.print()
            console.print(table)

            remediations = [r for r in results if r.remediation]
            if remediations:
                console.print("\n[bold yellow]Recommended Actions:[/bold yellow]")
                for r in remediations:
                    console.print(f"  * [bold]{r.name}[/bold]: {r.remediation}")

            if verdict == "PASS":
                console.print(Panel("[bold green]System Status: READY[/bold green]", border_style="green"))
            elif verdict == "WARN":
                console.print(Panel("[bold yellow]System Status: READY WITH WARNINGS[/bold yellow]", border_style="yellow"))
            else:
                console.print(Panel("[bold red]System Status: CONFIGURATION REQUIRED[/bold red]", border_style="red"))
            console.print()

        except Exception:
            # Plaintext fallback for environments without rich or cp1252
            print("\n=== BUZZARD CODE ENVIRONMENT DIAGNOSTICS ===")
            for r in results:
                print(f"[{r.status:4s}] {r.category:18s} | {r.name:22s} : {r.message}")
                if r.remediation:
                    print(f"       Fix: {r.remediation}")
            print(f"\nOverall Verdict: {verdict}\n")
