"""
Runs the completion gate's tests inside Docker, for repositories you do not fully trust.

Configured in .buzzard/project.json:

    "test_isolation": "host" | "docker" | "auto"   (default "host")
    "test_image":     Docker image for the tests    (default chosen from the test runner)
    "test_setup":     command run first in the same container, e.g. "pip install -e .[dev]"
    "test_network":   "none" | "bridge"             (default "none"; "bridge" if test_setup is set)

How a run is isolated:
- The project is copied to a temporary folder and only the copy is mounted, so tests cannot
  change, delete or plant files in the real workspace. Host-specific folders (.venv,
  node_modules, build caches) are left out of the copy.
- The container runs with all capabilities dropped, no-new-privileges, memory, CPU and
  process limits, and no network unless the project asks for one.
- "docker" never falls back to the host: if Docker is unavailable the gate fails and says so.
  "auto" uses Docker when it is reachable and the host otherwise, and reports which it used.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ISOLATION_MODES = ("host", "docker", "auto")
DEFAULT_IMAGES = {
    "pytest": "python:3.12-slim",
    "npm": "node:20-slim",
    "pnpm": "node:20-slim",
    "yarn": "node:20-slim",
    "bun": "oven/bun:1",
    "cargo": "rust:1",
    "go": "golang:1.22",
    "maven": "maven:3-eclipse-temurin-21",
    "gradle": "gradle:8-jdk21",
    "rspec": "ruby:3.3",
    "make": "buildpack-deps:bookworm",
}
CONTAINER_COMMANDS = {
    # Host commands can point at a Windows virtualenv, which does not exist in a Linux container
    "pytest": "python -m pytest -q",
    "gradle": "gradle test",
}
COPY_EXCLUDES = frozenset({
    ".venv", "venv", "env", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", "target", "dist", "build", ".next", ".dart_tool", ".gradle",
})
MEMORY_LIMIT = "2g"
CPU_LIMIT = "2"
PIDS_LIMIT = "512"


class IsolationConfigError(ValueError):
    """Invalid isolation settings; the message is shown to the user."""


@dataclass(frozen=True)
class IsolationConfig:
    mode: str
    image: Optional[str]
    setup: Optional[str]
    network: str

    def describe(self) -> str:
        setup = f", setup `{self.setup}`" if self.setup else ""
        return f"Docker image {self.image}, network {self.network}{setup}"


def resolve_isolation(settings: Dict[str, Any], runner: Optional[str]) -> IsolationConfig:
    mode = str(settings.get("test_isolation") or "host").strip().lower()
    if mode not in ISOLATION_MODES:
        raise IsolationConfigError(f"test_isolation must be one of {', '.join(ISOLATION_MODES)}, not '{mode}'.")
    image = settings.get("test_image") or DEFAULT_IMAGES.get(runner or "")
    if image is not None and (not isinstance(image, str) or not image.strip() or image.startswith("-") or any(c.isspace() for c in image)):
        raise IsolationConfigError("test_image must be a single Docker image name such as 'python:3.12-slim'.")
    setup = settings.get("test_setup")
    if setup is not None and (not isinstance(setup, str) or not setup.strip()):
        raise IsolationConfigError("test_setup must be a non-empty command string.")
    network = str(settings.get("test_network") or ("bridge" if setup else "none")).strip().lower()
    if network not in ("none", "bridge"):
        raise IsolationConfigError("test_network must be 'none' or 'bridge'.")
    if mode != "host" and not image:
        raise IsolationConfigError("no Docker image is known for this project; set test_image in .buzzard/project.json.")
    return IsolationConfig(mode=mode, image=image.strip() if image else None, setup=setup.strip() if setup else None, network=network)


def container_command(runner: Optional[str], host_command: str, configured: bool) -> str:
    """The command to run inside the container; a user-configured command is kept as written."""
    if configured:
        return host_command
    return CONTAINER_COMMANDS.get(runner or "", host_command)


def docker_available() -> bool:
    from sandbox.container import is_docker_active
    return is_docker_active()


def _copy_workspace(workspace: Path, destination: Path) -> None:
    def ignore(directory: str, names: list) -> set:
        return {name for name in names if name in COPY_EXCLUDES}

    # symlinks=True copies links as links, so a link cannot pull outside files into the copy
    shutil.copytree(workspace, destination, symlinks=True, ignore=ignore, dirs_exist_ok=True)


def run_tests_in_docker(workspace: Path, command: str, isolation: IsolationConfig, timeout: float) -> Dict[str, Any]:
    """Runs setup and tests in one locked-down container against a copy of the workspace."""
    script = f"{isolation.setup} && {command}" if isolation.setup else command
    container = f"buzzard-tests-{uuid.uuid4().hex[:10]}"
    start = time.time()
    with tempfile.TemporaryDirectory(prefix="buzzard-tests-") as temporary:
        copy = Path(temporary) / "workspace"
        try:
            _copy_workspace(workspace, copy)
        except (OSError, shutil.Error) as error:
            return {"exit_code": 1, "stdout": "", "stderr": f"Could not copy the project for an isolated test run: {error}", "sandboxed": True}
        docker_command = [
            "docker", "run", "--rm", "--name", container,
            "--network", isolation.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", MEMORY_LIMIT, "--cpus", CPU_LIMIT, "--pids-limit", PIDS_LIMIT,
            "-v", f"{copy}:/workspace", "-w", "/workspace",
            "-e", "CI=1",
            isolation.image, "sh", "-c", script,
        ]
        try:
            result = subprocess.run(docker_command, capture_output=True, text=True, errors="replace", timeout=timeout)
            exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            exit_code, stdout, stderr = 124, "", f"Tests timed out after {timeout:.0f} seconds in Docker."
        except OSError as error:
            exit_code, stdout, stderr = 1, "", f"Could not start Docker: {error}"
    if exit_code == 125:
        stderr = (stderr + "\nDocker could not start the container; check that the image exists and Docker is running.").strip()
    return {
        "exit_code": exit_code, "stdout": stdout, "stderr": stderr, "sandboxed": True,
        "sandbox_image": isolation.image, "duration": time.time() - start, "command": script,
    }
