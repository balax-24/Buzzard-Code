"""
Git Tools Subsystem for Buzzard Code.

Provides read-only, repository-aware git inspection:
- git_status: view working tree status, staged files, untracked files
- git_diff: view working tree or staged unified diffs
- git_log: view recent commit history

Guarantees:
- Strictly read-only: never automatically commits or discards changes.
- Uses the configured active repository workspace.
- Clear error handling when directory is not a git repository.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional
from security_agent.tools.filesystem import get_active_workspace, get_safe_path


def _run_git_cmd(args: list[str], timeout: float = 15.0) -> tuple[int, str, str]:
    """Runs a git command inside the active project workspace."""
    git_bin = shutil.which("git")
    if not git_bin:
        return 1, "", "Error: git executable not found on system PATH."

    ws = get_active_workspace()
    try:
        res = subprocess.run(
            [git_bin] + args,
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace"
        )
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Error: git command timed out after {timeout} seconds."
    except Exception as e:
        return 1, "", f"Error executing git command: {e}"


def git_status(path: str = ".") -> str:
    """
    Returns the working tree status of the active repository.
    Arguments:
        path: Optional directory or file subpath to check (default '.').
    """
    ret, out, err = _run_git_cmd(["status", "--short", "--branch", path])
    if ret != 0:
        if "not a git repository" in err.lower():
            return f"Error: Workspace '{get_active_workspace()}' is not a git repository."
        return f"Error running git status: {err.strip() or out.strip()}"

    lines = out.strip().splitlines()
    if len(lines) <= 1 and (not lines or lines[0].startswith("##")):
        branch = lines[0] if lines else "## (unknown)"
        return f"Repository Clean ({branch})\nNo working tree changes or untracked files."

    return f"Git Status ({get_active_workspace()}):\n{out.strip()}"


def git_diff(path: Optional[str] = None, cached: bool = False) -> str:
    """
    Returns the working tree diff (or staged diff if cached=True) for the repository.
    Arguments:
        path: Optional specific file or directory to inspect.
        cached: If True, inspect staged changes instead of unstaged.
    """
    args = ["diff"]
    if cached:
        args.append("--cached")

    if path:
        # Validate path stays in workspace
        try:
            safe = get_safe_path(path)
            rel = os.path.relpath(safe, get_active_workspace())
            args.append(rel)
        except Exception as e:
            return f"Error resolving diff path: {e}"

    ret, out, err = _run_git_cmd(args)
    if ret != 0:
        if "not a git repository" in err.lower():
            return f"Error: Workspace '{get_active_workspace()}' is not a git repository."
        return f"Error running git diff: {err.strip() or out.strip()}"

    if not out.strip():
        scope_msg = f" for '{path}'" if path else ""
        mode_msg = "staged" if cached else "working tree"
        return f"No {mode_msg} changes detected{scope_msg}."

    return out.strip()


def git_log(max_count: int = 10, path: Optional[str] = None) -> str:
    """
    Returns the recent commit history for the active repository.
    Arguments:
        max_count: Maximum number of commits to display (default 10).
        path: Optional specific file or directory to view history for.
    """
    limit = max(1, min(100, max_count or 10))
    args = ["log", f"-n{limit}", "--oneline", "--decorate"]

    if path:
        try:
            safe = get_safe_path(path)
            rel = os.path.relpath(safe, get_active_workspace())
            args.extend(["--", rel])
        except Exception as e:
            return f"Error resolving log path: {e}"

    ret, out, err = _run_git_cmd(args)
    if ret != 0:
        if "not a git repository" in err.lower():
            return f"Error: Workspace '{get_active_workspace()}' is not a git repository."
        if "does not have any commits yet" in err.lower():
            return "Repository has no commits yet."
        return f"Error running git log: {err.strip() or out.strip()}"

    return out.strip() or "No commits found."


def register_git_tools(registry):
    """
    Registers git tools with the authoritative ToolRegistry.
    """
    from security_agent.tools.registry import ToolCategory

    registry.register(
        name="git_status",
        description="Returns the current working tree status and branch info for the workspace. Arguments: path (str, default '.').",
        func=git_status,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="git_diff",
        description="Returns the git diff of working tree or staged modifications. Arguments: path (str, optional), cached (bool, default False).",
        func=git_diff,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="git_log",
        description="Returns recent commit history for the repository. Arguments: max_count (int, default 10), path (str, optional).",
        func=git_log,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )

    # Aliases
    registry.register(
        name="git.status",
        description="Returns the current working tree status for the workspace. Arguments: path (str, default '.').",
        func=git_status,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        timeout=15
    )
    registry.register(
        name="git.diff",
        description="Returns the git diff of working tree or staged modifications. Arguments: path (str, optional), cached (bool, default False).",
        func=git_diff,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        timeout=15
    )
    registry.register(
        name="git.log",
        description="Returns recent commit history for the repository. Arguments: max_count (int, default 10), path (str, optional).",
        func=git_log,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        timeout=15
    )

