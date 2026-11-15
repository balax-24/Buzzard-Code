"""
User hooks around tool calls (roadmap item F2).

Configured only in the user-level file ``~/.buzzard/hooks.json`` (or ``BUZZARD_HOOKS_CONFIG``);
a repository cannot add hooks, because a hook runs a program automatically:

    {"hooks": [
      {"event": "after_tool", "tools": ["file_edit", "apply_patch"], "command": ["ruff", "format", "."]},
      {"event": "before_tool", "tools": ["file_*"], "command": ["python", "C:/hooks/protect.py"]},
      {"event": "task_end", "command": ["notify-send", "Buzzard finished"]}
    ]}

- ``before_tool`` runs after the call is approved and before it executes. A non-zero exit blocks
  the call; the hook's output becomes the reason the agent sees.
- ``after_tool`` runs after a successful call; its output is appended to the tool result.
- ``task_end`` runs when a task finishes.
Each hook receives the event as JSON on stdin (event, tool, arguments, workspace, session),
runs as an argument list without a shell, in the workspace, with a timeout (default 30 s,
at most 120 s). A hook that cannot start or times out is reported; for ``before_tool`` that
blocks the call, so a broken guard fails closed.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

EVENTS = ("before_tool", "after_tool", "task_end")
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 120.0
MAX_OUTPUT_CHARS = 4000


class HookConfigError(ValueError):
    """The hooks file is invalid; the message is safe to show."""


@dataclass(frozen=True)
class Hook:
    event: str
    command: Tuple[str, ...]
    tools: Tuple[str, ...] = ("*",)
    timeout: float = DEFAULT_TIMEOUT

    def matches(self, tool_name: str) -> bool:
        return any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in self.tools)


def hooks_config_path() -> Path:
    override = os.environ.get("BUZZARD_HOOKS_CONFIG")
    if override:
        return Path(override)
    return Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "hooks.json"


def load_hooks() -> List[Hook]:
    """Reads and validates the user's hooks. Raises HookConfigError for an invalid file."""
    path = hooks_config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as error:
        raise HookConfigError(f"could not read {path}: {error}") from None
    entries = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise HookConfigError(f'{path} needs a "hooks" list')
    hooks = []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise HookConfigError(f"hook {index} in {path} must be an object")
        event = entry.get("event")
        command = entry.get("command")
        tools = entry.get("tools", ["*"])
        timeout = entry.get("timeout", DEFAULT_TIMEOUT)
        if event not in EVENTS:
            raise HookConfigError(f"hook {index}: event must be one of {', '.join(EVENTS)}")
        if not (isinstance(command, list) and command and all(isinstance(part, str) and part for part in command)):
            raise HookConfigError(f'hook {index}: "command" must be a non-empty list of strings')
        if not (isinstance(tools, list) and tools and all(isinstance(pattern, str) for pattern in tools)):
            raise HookConfigError(f'hook {index}: "tools" must be a list of tool names or patterns')
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
            raise HookConfigError(f"hook {index}: timeout must be between 0 and {MAX_TIMEOUT:.0f} seconds")
        hooks.append(Hook(event, tuple(command), tuple(tools), float(timeout)))
    return hooks


@dataclass
class HookRun:
    hook: Hook
    exit_code: int
    output: str


def _run(hook: Hook, payload: Dict[str, Any], workspace: str) -> HookRun:
    executable = shutil.which(hook.command[0]) or hook.command[0]
    command = [executable, *hook.command[1:]]
    if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
        command = ["cmd", "/c", *command]  # the command comes from the user's own config
    try:
        result = subprocess.run(
            command, input=json.dumps(payload, default=str), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=hook.timeout, cwd=workspace or None, check=False,
        )
        output = (result.stdout + ("\n" + result.stderr if result.stderr.strip() else "")).strip()
        return HookRun(hook, result.returncode, output[:MAX_OUTPUT_CHARS])
    except subprocess.TimeoutExpired:
        return HookRun(hook, 124, f"hook timed out after {hook.timeout:.0f}s")
    except OSError as error:
        return HookRun(hook, 127, f"hook could not start: {error}")


def _hooks_for(event: str, tool_name: str = "") -> Tuple[List[Hook], Optional[str]]:
    try:
        hooks = load_hooks()
    except HookConfigError as error:
        return [], str(error)
    return [hook for hook in hooks if hook.event == event and (event == "task_end" or hook.matches(tool_name))], None


def run_before_tool(tool_name: str, arguments: Dict[str, Any], workspace: str, session_id: str) -> Optional[str]:
    """Returns a reason to block the call, or None to let it run. Invalid config blocks (fails closed)."""
    hooks, problem = _hooks_for("before_tool", tool_name)
    if problem:
        return f"Blocked: the hooks file is invalid ({problem}). Fix it or remove it."
    payload = {"event": "before_tool", "tool": tool_name, "arguments": arguments, "workspace": workspace, "session": session_id}
    for hook in hooks:
        run = _run(hook, payload, workspace)
        if run.exit_code != 0:
            reason = run.output or f"exit code {run.exit_code}"
            return f"Blocked by a before_tool hook ({' '.join(hook.command)}): {reason}"
    return None


def run_after_tool(tool_name: str, arguments: Dict[str, Any], result: str, workspace: str, session_id: str) -> str:
    """Returns text to append to the tool result (empty when no hook ran or none printed anything)."""
    hooks, problem = _hooks_for("after_tool", tool_name)
    if problem:
        return f"\n\nHooks not run: {problem}"
    payload = {"event": "after_tool", "tool": tool_name, "arguments": arguments, "result": result[:MAX_OUTPUT_CHARS],
               "workspace": workspace, "session": session_id}
    notes = []
    for hook in hooks:
        run = _run(hook, payload, workspace)
        status = "" if run.exit_code == 0 else f" (exit code {run.exit_code})"
        if run.output or status:
            notes.append(f"[after_tool hook {' '.join(hook.command)}{status}]\n{run.output}".rstrip())
    return ("\n\n" + "\n\n".join(notes)) if notes else ""


def run_task_end(workspace: str, session_id: str, status: str) -> None:
    hooks, problem = _hooks_for("task_end")
    if problem:
        logger.warning("Hooks not run: %s", problem)
        return
    for hook in hooks:
        run = _run(hook, {"event": "task_end", "workspace": workspace, "session": session_id, "status": status}, workspace)
        if run.exit_code != 0:
            logger.warning("task_end hook %s failed: %s", hook.command, run.output)
