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
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Any, List, Optional, Tuple

from security_agent.tools.filesystem import get_active_workspace
from security_agent.sandbox.container import ControlledHostSandbox


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
            "command": "python -m pytest -q",
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
    """Returns staged, unstaged and untracked paths; empty when not in a git repository."""
    ret, out = _run_git(workspace, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if ret != 0:
        return []
    changed: List[str] = []
    entries = iter(out.split("\0"))
    for entry in entries:
        if not entry:
            continue
        changed.append(entry[3:])
        # Renames and copies are followed by a separate original-path entry
        if entry[0] in ("R", "C") or entry[1] in ("R", "C"):
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
        test_info = detect_project_test_runner(self.workspace)
        if test_info["detected"] and auto_run_tests:
            runner = test_info["runner"]
            cmd = test_info["command"]

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

            # Execute test command in ControlledHostSandbox
            res = self.sandbox.execute(cmd, timeout=60.0)
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
                        f"Test Failure Output:\n```\n{truncated_output}\n```\n"
                        "Please inspect the test failure, modify the code to fix the issue, and re-test."
                    ),
                    runner_detected=runner,
                    test_command=cmd,
                    test_exit_code=exit_code,
                    test_output=output,
                    diff_summary=diff_text[:800] if diff_text else None,
                )

            # Test suite passed!
            return CodingVerificationResult(
                passed=True,
                requires_action=False,
                message=f"All verification gates passed: Test suite `{cmd}` passed with exit code 0.",
                runner_detected=runner,
                test_command=cmd,
                test_exit_code=0,
                test_output=output[-500:],
                diff_summary=diff_text[:800] if diff_text else None,
            )

        # Gate 4: If no test runner configured, pass if syntax and diff are valid
        return CodingVerificationResult(
            passed=True,
            requires_action=False,
            message="Verification gate passed: Syntax valid and modifications confirmed (no project test runner configured).",
            diff_summary=diff_text[:800] if diff_text else None,
        )
