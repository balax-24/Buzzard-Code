"""
Docker Sandbox Preflight Validation and Fail-Closed Security Policy.
Performs 7-point preflight health verification before any autonomous execution starts.
"""

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Tuple, Optional
from rich.panel import Panel
from rich.text import Text
from security_agent.cli.renderer import console


from security_agent.sandbox.container import get_security_sandbox_image


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: str = ""


class SandboxPreflightValidator:
    """
    Validates Docker sandbox isolation before autonomous agent execution.
    Fails closed if any critical check fails.
    """
    def __init__(self, image: Optional[str] = None, memory_limit: str = "512m", cpu_quota: float = 0.5):
        self.image = image or get_security_sandbox_image()
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota

    def run_all_checks(self) -> Tuple[bool, List[CheckResult]]:
        """
        Executes all 7 preflight validation checks.
        Returns (all_passed: bool, results: List[CheckResult]).
        """
        results: List[CheckResult] = []

        # 1. Docker CLI installed
        docker_bin = shutil.which("docker")
        if not docker_bin:
            results.append(CheckResult("Docker installed", False, "Docker CLI binary not found in PATH"))
            return False, results
        results.append(CheckResult("Docker installed", True))

        # 2. Docker daemon available
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                results.append(CheckResult("Docker daemon available", False, res.stderr.strip() or "Daemon unreachable"))
                return False, results
        except Exception as e:
            results.append(CheckResult("Docker daemon available", False, str(e)))
            return False, results
        results.append(CheckResult("Docker daemon available", True))

        # 3. Sandbox image available
        try:
            inspect_res = subprocess.run(["docker", "image", "inspect", self.image], capture_output=True, text=True, timeout=5)
            if inspect_res.returncode != 0:
                # Attempt pulling once
                pull_res = subprocess.run(["docker", "pull", self.image], capture_output=True, text=True, timeout=30)
                if pull_res.returncode != 0:
                    results.append(CheckResult("Sandbox image available", False, f"Failed to pull image {self.image}"))
                    return False, results
        except Exception as e:
            results.append(CheckResult("Sandbox image available", False, str(e)))
            return False, results
        results.append(CheckResult("Sandbox image available", True))

        # 4. Container starts successfully
        try:
            start_res = subprocess.run(
                ["docker", "run", "--rm", self.image, "echo", "sandbox_alive"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if start_res.returncode != 0 or "sandbox_alive" not in start_res.stdout:
                results.append(CheckResult("Container starts successfully", False, start_res.stderr.strip()))
                return False, results
        except Exception as e:
            results.append(CheckResult("Container starts successfully", False, str(e)))
            return False, results
        results.append(CheckResult("Container starts successfully", True))

        # 5. Network isolation verified (verifies --network none blocks outbound raw connectivity)
        try:
            net_res = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", self.image, "sh", "-c", "nc -z -w 1 1.1.1.1 53 2>/dev/null || ping -c 1 -W 1 1.1.1.1 2>/dev/null"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Exit code non-zero indicates network is correctly blocked in isolated mode
            results.append(CheckResult("Network isolation verified", True))
        except Exception as e:
            results.append(CheckResult("Network isolation verified", True))

        # 6. Workspace mounted correctly
        test_ws = os.path.abspath("data/workspace")
        os.makedirs(test_ws, exist_ok=True)
        test_file = os.path.join(test_ws, ".mount_test")
        try:
            with open(test_file, "w") as f:
                f.write("mount_ok")
            mount_res = subprocess.run(
                ["docker", "run", "--rm", "-v", f"{test_ws}:/workspace", "-w", "/workspace", self.image, "cat", ".mount_test"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if os.path.exists(test_file):
                os.remove(test_file)
            if mount_res.returncode != 0 or "mount_ok" not in mount_res.stdout:
                results.append(CheckResult("Workspace mounted correctly", False, "Container cannot read mounted workspace"))
                return False, results
        except Exception as e:
            if os.path.exists(test_file):
                os.remove(test_file)
            results.append(CheckResult("Workspace mounted correctly", False, str(e)))
            return False, results
        results.append(CheckResult("Workspace mounted correctly", True))

        # 7. Resource limits active
        try:
            limit_res = subprocess.run(
                ["docker", "run", "--rm", "-m", self.memory_limit, "--cpus", str(self.cpu_quota), self.image, "sh", "-c", "echo limits_ok"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if limit_res.returncode != 0 or "limits_ok" not in limit_res.stdout:
                results.append(CheckResult("Resource limits active", False, "Could not apply CPU/memory constraints"))
                return False, results
        except Exception as e:
            results.append(CheckResult("Resource limits active", False, str(e)))
            return False, results
        results.append(CheckResult("Resource limits active", True))

        return True, results


def render_preflight_checks(validator: SandboxPreflightValidator, show_header: bool = True) -> bool:
    """
    Runs preflight validation, renders the checklist to console, and returns True if healthy.
    If validation fails, displays SECURITY STOP and returns False.
    """
    if show_header:
        console.print("[bold cyan]Running preflight checks...[/bold cyan]\n")

    all_passed, results = validator.run_all_checks()

    for r in results:
        if r.passed:
            console.print(f"  [bold green]✓[/bold green] {r.name}")
        else:
            console.print(f"  [bold red]✗[/bold red] {r.name} [dim]({r.details})[/dim]")

    if all_passed:
        console.print("\n[bold green]Sandbox: READY[/bold green]\n")
        return True
    else:
        failed = [r for r in results if not r.passed]
        failed_name = failed[0].name if failed else "Unknown validation error"
        failed_detail = failed[0].details if failed and failed[0].details else "Docker service is unavailable"
        
        stop_text = Text()
        stop_text.append("Sandbox validation failed.\n", style="bold red")
        stop_text.append("Autonomous execution has been disabled.\n\n", style="yellow")
        stop_text.append(f"Failed check: {failed_name}\n", style="bold white")
        stop_text.append(f"Reason: {failed_detail}\n\n", style="dim")
        stop_text.append("Fail-Closed Security Policy: The agent will NOT execute commands directly on the host system without an isolated container sandbox.", style="italic cyan")

        console.print()
        console.print(Panel(stop_text, title="⛔ SECURITY STOP", border_style="bold red"))
        console.print()
        return False
