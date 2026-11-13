"""
Coding Agent Verification Subsystem for Buzzard Code.

Enforces an authoritative completion gate for software engineering tasks:
1. Detects project manifest and test runner (pytest, npm, cargo, go, etc.).
2. Validates code syntax on modified files (AST parsing for Python, JSON/YAML).
3. Executes project tests inside the ControlledHostSandbox.
4. Enforces uncommitted diff verification before allowing task completion.
5. Rejects premature completion if tests fail or no changes were made for modification tasks.
"""

from __future__ import annotations

import os
import ast
import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Any, List, Optional, Tuple

from tools.filesystem import get_active_workspace
from sandbox.container import ControlledHostSandbox
from verification.changed_coverage import (
    MIN_COVERAGE_VERSION,
    ChangedLineCoverage,
    coverage_data_path,
    coverage_setting,
    installed_coverage_version,
    measure_changed_line_coverage,
    not_measured,
    wrap_pytest_command,
)
from verification.docker_tests import (
    IsolationConfigError,
    container_command,
    docker_available,
    resolve_isolation,
    run_tests_in_docker,
)


logger = logging.getLogger(__name__)


@dataclass
class CodingVerificationResult:
    """Outcome of the coding task verification gate."""
    passed: bool
    requires_action: bool
    message: str
    runner_detected: Optional[str] = None
    test_command: Optional[str] = None
    test_exit_code: Optional[int] = None
    test_output: Optional[str] = None
    diff_summary: Optional[str] = None
    syntax_errors: List[str] = field(default_factory=list)
    lint_command: Optional[str] = None
    lint_status: str = "not configured"
    test_environment: str = "host"
    changed_line_coverage: Optional[Dict[str, Any]] = None


_EDIT_REQUEST = re.compile(
    r"\b(fix|add|refactor|implement|update|modify|change|create|write|repair|patch|edit|rename|remove|delete)\b",
    re.IGNORECASE,
)
# Only a ban on all changes makes a task read-only. "Do not modify the tests" still requires edits.
_EDITS_FORBIDDEN = re.compile(
    r"\b(do not|don't|dont|without|never)\s+"
    r"(fix|fixing|change|changing|modify|modifying|edit|editing|write|writing|touch|touching)\s+"
    r"(any\s+|the\s+)?(files?|code|codebase|repo|repository|anything)\b"
    r"|\bno\s+(code\s+|file\s+)?(changes|edits)\b",
    re.IGNORECASE,
)


def task_requires_edits(task_goal: str) -> bool:
    """True when the task asks for code changes, rather than only explanation or diagnosis."""
    if _EDITS_FORBIDDEN.search(task_goal):
        return False
    return bool(_EDIT_REQUEST.search(task_goal))


DEFAULT_TEST_TIMEOUT_SECONDS = 300.0
PROJECT_SETTINGS_FILE = Path(".buzzard") / "project.json"


def load_project_settings(workspace: Path) -> Dict[str, Any]:
    """Reads .buzzard/project.json. Any command it names still needs operator approval."""
    path = workspace / PROJECT_SETTINGS_FILE
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        logger.warning("Ignoring unreadable %s: %s", path, e)
        return {}
    return settings if isinstance(settings, dict) else {}


def resolve_test_timeout(settings: Dict[str, Any]) -> float:
    """Project setting, then BUZZARD_TEST_TIMEOUT, then the default. Invalid values are ignored."""
    for candidate in (settings.get("test_timeout"), os.environ.get("BUZZARD_TEST_TIMEOUT")):
        try:
            value = float(candidate)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return DEFAULT_TEST_TIMEOUT_SECONDS


def project_python(workspace: Path) -> str:
    """Prefers the project's own virtual environment, so tests see its dependencies."""
    for folder in (".venv", "venv"):
        relative = Path(folder) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if (workspace / relative).is_file():
            return str(relative)
    return "python"


def detect_project_test_runner(workspace: Optional[str] = None) -> Dict[str, Any]:
    """
    Detects the project's test framework from manifest files in the repository root.
    Returns:
        {"detected": bool, "runner": str, "command": str, "description": str}
    """
    ws = Path(workspace or get_active_workspace()).resolve()

    # 1. Rust Cargo
    if (ws / "Cargo.toml").is_file():
        return {
            "detected": True,
            "runner": "cargo",
            "command": "cargo test",
            "description": "Rust Cargo test suite"
        }

    # 2. Go Modules
    if (ws / "go.mod").is_file():
        return {
            "detected": True,
            "runner": "go",
            "command": "go test ./...",
            "description": "Go test suite"
        }

    # 3. Node.js / JavaScript / TypeScript
    pkg_json = ws / "package.json"
    if pkg_json.is_file():
        runner = "npm"
        if (ws / "pnpm-lock.yaml").is_file():
            runner = "pnpm"
        elif (ws / "yarn.lock").is_file():
            runner = "yarn"
        elif (ws / "bun.lockb").is_file() or (ws / "bun.lock").is_file():
            runner = "bun"
        return {
            "detected": True,
            "runner": runner,
            "command": f"{runner} test",
            "description": f"Node.js ({runner}) test runner"
        }

    # 4. Python (pyproject.toml, pytest.ini, setup.cfg, setup.py, requirements.txt)
    py_indicators = ["pyproject.toml", "pytest.ini", "setup.cfg", "setup.py", "requirements.txt"]
    if any((ws / f).is_file() for f in py_indicators):
        # Prefer python -m pytest if available or pytest
        return {
            "detected": True,
            "runner": "pytest",
            "command": f"{project_python(ws)} -m pytest -q",
            "description": "Python pytest test suite"
        }

    # 5. Java Maven or Gradle
    if (ws / "pom.xml").is_file():
        return {
            "detected": True,
            "runner": "maven",
            "command": "mvn test",
            "description": "Java Maven test suite"
        }
    if (ws / "build.gradle").is_file() or (ws / "build.gradle.kts").is_file():
        cmd = "./gradlew test" if os.name != "nt" else "gradlew.bat test"
        return {
            "detected": True,
            "runner": "gradle",
            "command": cmd,
            "description": "Gradle test suite"
        }

    # 6. Ruby
    if (ws / "Gemfile").is_file():
        return {
            "detected": True,
            "runner": "rspec",
            "command": "bundle exec rspec",
            "description": "Ruby RSpec test suite"
        }

    # 7. Makefile fallback
    if (ws / "Makefile").is_file():
        return {
            "detected": True,
            "runner": "make",
            "command": "make test",
            "description": "Makefile test target"
        }

    return {
        "detected": False,
        "runner": None,
        "command": None,
        "description": "No recognized test manifest found"
    }


def _run_git(workspace: Path, args: List[str]) -> Tuple[int, str]:
    """Runs git in the verified workspace, which may differ from the active workspace."""
    git_bin = shutil.which("git")
    if not git_bin:
        return 1, ""
    try:
        res = subprocess.run(
            [git_bin, *args],
            cwd=workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30.0,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return res.returncode, res.stdout


def list_changed_files(workspace: Path) -> List[str]:
    """Returns meaningful staged, unstaged and untracked paths.

    Untracked interpreter and test-runner caches are omitted because they are generated by
    verification itself and must not make an otherwise unchanged task look edited.
    Tracked files with these names remain visible.
    """
    ret, out = _run_git(workspace, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if ret != 0:
        return []
    changed: List[str] = []
    entries = iter(out.split("\0"))
    for entry in entries:
        if not entry:
            continue
        status, path = entry[:2], entry[3:]
        normalized_parts = Path(path.replace("\\", "/")).parts
        generated_cache = any(part in {
            "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        } for part in normalized_parts) or Path(path).name == ".coverage"
        if not (status == "??" and generated_cache):
            changed.append(path)
        # Renames and copies are followed by a separate original-path entry
        if status[0] in ("R", "C") or status[1] in ("R", "C"):
            next(entries, None)
    return changed


def _workspace_diff(workspace: Path) -> str:
    """Returns the staged and unstaged diff against HEAD for the verified workspace."""
    ret, out = _run_git(workspace, ["diff", "HEAD"])
    return out if ret == 0 else ""


def check_code_syntax(workspace: Optional[str] = None) -> List[str]:
    """
    Scans changed files for syntax/parsing errors (AST check for Python, JSON check).
    """
    ws = Path(workspace or get_active_workspace()).resolve()
    errors: List[str] = []

    files_to_check = [ws / rel_path for rel_path in list_changed_files(ws)]
    files_to_check = [f_path for f_path in files_to_check if f_path.is_file()]

    for p in files_to_check:
        if p.suffix == ".py":
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                ast.parse(content, filename=str(p))
            except SyntaxError as se:
                errors.append(f"SyntaxError in {p.name} (line {se.lineno}): {se.msg}")
            except Exception as e:
                errors.append(f"Parse error in {p.name}: {e}")
        elif p.suffix == ".json":
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                json.loads(content)
            except Exception as e:
                errors.append(f"JSONDecodeError in {p.name}: {e}")

    return errors


LINT_SAFE_PATH = re.compile(r"^[\w./-]+$")
ESLINT_CONFIGS = ("eslint.config.js", "eslint.config.mjs", ".eslintrc", ".eslintrc.js", ".eslintrc.json")


def detect_lint_command(workspace: Path, changed: List[str]) -> Optional[str]:
    """Returns a linter command for changed files when the project configures one."""
    # Paths go into a shell command, so unusual names are left out rather than trusted
    safe = [path for path in changed if LINT_SAFE_PATH.match(path) and (workspace / path).is_file()]
    python_files = [path for path in safe if path.endswith(".py")]
    pyproject = workspace / "pyproject.toml"
    has_ruff = (workspace / "ruff.toml").is_file() or (
        pyproject.is_file() and "[tool.ruff" in pyproject.read_text(encoding="utf-8", errors="replace")
    )
    if python_files and has_ruff:
        return f"{project_python(workspace)} -m ruff check {' '.join(python_files)}"
    script_files = [path for path in safe if path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs"))]
    if script_files and any((workspace / name).is_file() for name in ESLINT_CONFIGS):
        return f"npx --no-install eslint {' '.join(script_files)}"
    return None


class CodingVerifier:
    """
    Authoritative completion verification gate for Buzzard Code engineering tasks.
    """

    def __init__(
        self,
        workspace: Optional[str] = None,
        command_approver: Optional[Callable[[str], bool]] = None,
    ):
        self.workspace = workspace or get_active_workspace()
        self.command_approver = command_approver
        self.sandbox = ControlledHostSandbox(workspace=self.workspace)

    def _plan_coverage(
        self, workspace: Path, command: str, settings: Dict[str, Any]
    ) -> Tuple[str, ChangedLineCoverage, Optional[Path]]:
        """Wraps a pytest command in coverage when the project can measure it; never changes other commands."""
        setting, problem = coverage_setting(settings)
        if problem:
            return command, not_measured(problem), None
        if setting == "off":
            return command, not_measured("turned off in .buzzard/project.json"), None
        version = installed_coverage_version(workspace, project_python(workspace))
        if version is None:
            return command, not_measured("coverage.py is not installed in the project's virtual environment"), None
        if version < MIN_COVERAGE_VERSION:
            return command, not_measured("coverage.py 6.3 or newer is needed"), None
        # Outside the repository, so the data file never shows up as a changed file, and at a fixed
        # path per workspace, so the command text stays the same and "allow for session" keeps working
        data_file = coverage_data_path(workspace)
        wrapped = wrap_pytest_command(command, data_file)
        if wrapped is None:
            return command, not_measured("only `<python> -m pytest` test commands are measured so far"), None
        try:
            data_file.parent.mkdir(parents=True, exist_ok=True)
            data_file.unlink(missing_ok=True)  # never report a previous run's data
        except OSError as error:
            return command, not_measured(f"could not prepare the coverage data file: {error}"), None
        return wrapped, not_measured("tests did not finish"), data_file

    def _run_lint(self, workspace: Path) -> Tuple[Optional[str], str]:
        """Reports lint results without blocking, so existing lint debt cannot stop a good fix."""
        command = detect_lint_command(workspace, list_changed_files(workspace))
        if command is None:
            return None, "not configured"
        if self.command_approver is not None and not self.command_approver(command):
            return command, "not approved"
        result = self.sandbox.execute(command, timeout=120.0)
        exit_code = result.get("exit_code", 1) if isinstance(result, dict) else getattr(result, "exit_code", 1)
        output = str(result.get("stdout", "") if isinstance(result, dict) else "") + str(result.get("stderr", "") if isinstance(result, dict) else "")
        if exit_code == 0:
            return command, "passed"
        if "No module named" in output or "not found" in output.lower() or exit_code in (126, 127):
            return command, "could not run"
        return command, "issues found"

    def verify_task(
        self,
        task_goal: str,
        auto_run_tests: bool = True
    ) -> CodingVerificationResult:
        """
        Evaluates whether the coding task satisfies all completion requirements.
        """
        requires_edits = task_requires_edits(task_goal)
        if not requires_edits:
            return CodingVerificationResult(
                passed=True,
                requires_action=False,
                message="Verification gate passed: This task did not request code changes.",
            )

        # Gate 1: Git Diff & Modification Check
        workspace_path = Path(self.workspace).resolve()
        diff_text = _workspace_diff(workspace_path)
        has_changes = bool(list_changed_files(workspace_path))

        if requires_edits and not has_changes:
            return CodingVerificationResult(
                passed=False,
                requires_action=True,
                message=(
                    "COMPLETION GATE REJECTED: No modifications were made in the repository.\n"
                    "The task requested code changes, but git diff is empty.\n"
                    "Please inspect the relevant files with file_read/file_view, apply changes with file_edit, "
                    "and verify with tests before concluding."
                ),
            )

        # Gate 2: Code Syntax Validation Check
        syntax_errors = check_code_syntax(self.workspace)
        if syntax_errors:
            err_summary = "\n".join(f"- {e}" for e in syntax_errors)
            return CodingVerificationResult(
                passed=False,
                requires_action=True,
                message=(
                    f"COMPLETION GATE REJECTED: Code syntax errors detected in modified files:\n{err_summary}\n"
                    "Please fix the syntax errors using file_edit before completing."
                ),
                syntax_errors=syntax_errors,
            )

        # Gate 3: Test Runner Detection & Test Execution
        settings = load_project_settings(workspace_path)
        test_info = detect_project_test_runner(self.workspace)
        configured_command = settings.get("test_command")
        configured = isinstance(configured_command, str) and bool(configured_command.strip())
        if configured:
            test_info = {"detected": True, "runner": "configured", "command": configured_command.strip()}
        if test_info["detected"] and auto_run_tests:
            runner = test_info["runner"]
            cmd = test_info["command"]
            detected_runner = detect_project_test_runner(self.workspace).get("runner")

            try:
                isolation = resolve_isolation(settings, detected_runner)
            except IsolationConfigError as error:
                return CodingVerificationResult(
                    passed=False,
                    requires_action=True,
                    message=f"COMPLETION GATE REJECTED: Invalid test isolation settings in .buzzard/project.json: {error}",
                    runner_detected=runner,
                    test_command=cmd,
                )
            use_docker = isolation.mode == "docker" or (isolation.mode == "auto" and docker_available())
            if isolation.mode == "docker" and not docker_available():
                return CodingVerificationResult(
                    passed=False,
                    requires_action=True,
                    message=(
                        "COMPLETION GATE REJECTED: This project requires tests to run in Docker "
                        "(test_isolation is 'docker'), but Docker is not reachable. Start Docker, or set "
                        "test_isolation to 'auto' or 'host' in .buzzard/project.json if you trust this repository."
                    ),
                    runner_detected=runner,
                    test_command=cmd,
                    test_environment="docker (unavailable)",
                )
            coverage_plan: Optional[ChangedLineCoverage] = None
            coverage_data_file: Optional[Path] = None
            if use_docker:
                container_test = container_command(detected_runner, cmd, configured)
                cmd = f"{isolation.setup} && {container_test}" if isolation.setup else container_test
                environment = isolation.describe()
                coverage_plan = not_measured("tests ran in Docker; coverage is measured on the host only")
            else:
                environment = "host (Docker not reachable)" if isolation.mode == "auto" else "host"
                cmd, coverage_plan, coverage_data_file = self._plan_coverage(
                    workspace_path, cmd, settings
                )

            if self.command_approver is not None and not self.command_approver(cmd):
                return CodingVerificationResult(
                    passed=False,
                    requires_action=True,
                    message=(
                        f"COMPLETION GATE REJECTED: The test command `{cmd}` was not approved, "
                        "so this task cannot be verified as complete."
                    ),
                    runner_detected=runner,
                    test_command=cmd,
                    diff_summary=diff_text[:800] if diff_text else None,
                )

            if use_docker:
                res = run_tests_in_docker(
                    workspace_path, container_test, isolation, timeout=resolve_test_timeout(settings)
                )
            else:
                res = self.sandbox.execute(cmd, timeout=resolve_test_timeout(settings))
            if coverage_data_file is not None:
                coverage_plan = measure_changed_line_coverage(workspace_path, coverage_data_file)
            coverage_result = coverage_plan.to_dict() if coverage_plan is not None else None
            if isinstance(res, dict):
                exit_code = res.get("exit_code", 1)
                stdout = res.get("stdout", "")
                stderr = res.get("stderr", "")
            else:
                exit_code = getattr(res, "exit_code", 1)
                stdout = getattr(res, "stdout", "")
                stderr = getattr(res, "stderr", "")
            output = (stdout + "\n" + stderr).strip()

            if exit_code != 0:
                truncated_output = output[-1200:] if len(output) > 1200 else output
                return CodingVerificationResult(
                    passed=False,
                    requires_action=True,
                    message=(
                        f"COMPLETION GATE REJECTED: Test suite failed (exit code {exit_code}).\n"
                        f"Command: `{cmd}`\n"
                        f"Ran in: {environment}\n"
                        f"Test Failure Output:\n```\n{truncated_output}\n```\n"
                        "Please inspect the test failure, modify the code to fix the issue, and re-test."
                    ),
                    runner_detected=runner,
                    test_command=cmd,
                    test_exit_code=exit_code,
                    test_output=output,
                    diff_summary=diff_text[:800] if diff_text else None,
                    test_environment=environment,
                    changed_line_coverage=coverage_result,
                )

            # Test suite passed!
            lint_command, lint_status = self._run_lint(workspace_path)
            return CodingVerificationResult(
                lint_command=lint_command,
                lint_status=lint_status,
                passed=True,
                requires_action=False,
                message=f"All verification gates passed: Test suite `{cmd}` passed with exit code 0 ({environment}).",
                test_environment=environment,
                runner_detected=runner,
                test_command=cmd,
                test_exit_code=0,
                test_output=output[-500:],
                diff_summary=diff_text[:800] if diff_text else None,
                changed_line_coverage=coverage_result,
            )

        # Gate 4: If no test runner configured, pass if syntax and diff are valid
        return CodingVerificationResult(
            passed=True,
            requires_action=False,
            message="Verification gate passed: Syntax valid and modifications confirmed (no project test runner configured).",
            diff_summary=diff_text[:800] if diff_text else None,
        )
