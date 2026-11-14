"""
Parallel subtasks in git worktrees (roadmap E1).

Several independent subtasks run at the same time. Each runs as its own `buzzard exec` process
in its own detached worktree holding the user's current state, so they share nothing: not the
active workspace, not the conversation, not the approval state. When all have finished, their
diffs are merged one by one (`git apply --3way`) into a fresh worktree; a subtask whose diff
conflicts with the ones before it is left out and reported. The completion gate then runs on the
merged result, and only if it passes are the merged changes applied to the user's project.

Workers cannot ask for approval while they run, so approvals are flags, exactly as for
`buzzard exec`: nothing is edited or run unless the caller allows it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agent.best_of import BestOfError, Worktree, _current_state, _git, attempts_directory

MAX_SUBTASKS = 6
WORKER_TIMEOUT_SECONDS = 3600


class ParallelError(RuntimeError):
    """Parallel subtasks could not start (no git repository, bad arguments)."""


@dataclass
class SubtaskResult:
    number: int
    task: str
    status: str = "not run"
    seconds: float = 0.0
    diff: str = ""
    changed_lines: int = 0
    final_answer: str = ""
    error: Optional[str] = None
    merged: bool = False


@dataclass
class ParallelResult:
    status: str  # "completed", "failed" or "rejected"
    seconds: float
    subtasks: List[SubtaskResult] = field(default_factory=list)
    gate_passed: bool = False
    gate_message: str = ""
    applied: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {key: value for key, value in self.__dict__.items() if key != "subtasks"}
        data["subtasks"] = [{key: value for key, value in item.__dict__.items() if key != "diff"} for item in self.subtasks]
        return data


WorkerCommand = Callable[[str, Path], List[str]]


def default_worker_command(allow_edits: bool, allow_commands: bool, model: Optional[str] = None) -> WorkerCommand:
    """`buzzard exec` in the worktree, with the caller's approval flags."""
    def command(task: str, workspace: Path) -> List[str]:
        if getattr(sys, "frozen", False):
            argv = [sys.executable, "exec", task, "--workspace", str(workspace), "--json"]
        else:
            argv = [sys.executable, "-m", "cli.main", "exec", task, "--workspace", str(workspace), "--json"]
        if allow_edits:
            argv.append("--allow-edits")
        if allow_commands:
            argv.append("--allow-commands")
        if model:
            argv += ["--model", model]
        return argv
    return command


def _run_worker(number: int, task: str, worktree: Worktree, command: WorkerCommand, timeout: float) -> SubtaskResult:
    result = SubtaskResult(number=number, task=task)
    started = time.monotonic()
    try:
        finished = subprocess.run(command(task, worktree.path), cwd=str(worktree.path), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout, check=False,
                                  stdin=subprocess.DEVNULL)
        start = finished.stdout.find("{")  # `buzzard exec --json` prints one JSON object
        try:
            report = json.loads(finished.stdout[start:]) if start >= 0 else {}
        except json.JSONDecodeError:
            report = {}
        result.status = str(report.get("status") or ("completed" if finished.returncode == 0 else "failed"))
        result.final_answer = str(report.get("finalAnswer") or "")
        result.error = report.get("error") or (finished.stderr.strip()[-500:] if finished.returncode not in (0, 1) else None)
        result.diff, result.changed_lines = worktree.changes()
    except subprocess.TimeoutExpired:
        result.status, result.error = "failed", f"timed out after {timeout:.0f} s"
    except (OSError, BestOfError) as error:
        result.status, result.error = "failed", str(error)
    result.seconds = round(time.monotonic() - started, 2)
    return result


def run_parallel(
    workspace: Path,
    tasks: List[str],
    worker_command: WorkerCommand,
    verify: Callable[[Path], Any],
    timeout: float = WORKER_TIMEOUT_SECONDS,
    minimum: int = 2,
) -> ParallelResult:
    """
    Runs `tasks` concurrently in worktrees, merges their diffs, gates the merge with
    `verify(merged_worktree)` (returning an object with `passed` and `message`), and applies the
    merge to `workspace` only if the gate passed.
    """
    tasks = [task.strip() for task in tasks if task and task.strip()]
    if not minimum <= len(tasks) <= MAX_SUBTASKS:
        raise ParallelError(f"give between {minimum} and {MAX_SUBTASKS} subtasks")
    root = Path(workspace).resolve()
    if _git(root, "rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
        raise ParallelError("parallel subtasks need the project to be a git repository")
    started = time.monotonic()
    tracked, untracked = _current_state(root)
    directory = attempts_directory(root) / "parallel"
    worktrees = [Worktree(root, directory / f"subtask-{number}") for number in range(1, len(tasks) + 1)]
    merge = Worktree(root, directory / "merged")
    result = ParallelResult(status="failed", seconds=0.0)
    try:
        for worktree in worktrees:
            worktree.create(tracked, untracked)
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = [pool.submit(_run_worker, number, task, worktree, worker_command, timeout)
                       for number, (task, worktree) in enumerate(zip(tasks, worktrees), 1)]
            result.subtasks = [future.result() for future in futures]

        merge.create(tracked, untracked)
        for subtask in result.subtasks:
            if subtask.status != "completed" or not subtask.diff.strip():
                continue
            applied = _git(merge.path, "apply", "--3way", "--binary", "--whitespace=nowarn", "-",
                           input_bytes=subtask.diff.encode("utf-8"), check=False)
            if applied.returncode == 0:
                subtask.merged = True
            else:
                _git(merge.path, "reset", "-q", "--hard", "HEAD", check=False)  # undo a partial 3-way apply
                for earlier in result.subtasks:  # re-apply what was already merged
                    if earlier.merged:
                        _git(merge.path, "apply", "--3way", "--binary", "--whitespace=nowarn", "-",
                             input_bytes=earlier.diff.encode("utf-8"), check=False)
                subtask.error = "its changes conflict with an earlier subtask's; left out of the merge"
        merged_diff, _ = merge.changes()
        if not merged_diff.strip():
            result.error = "no subtask produced changes that could be merged"
            return result
        _git(merge.path, "reset", "-q")  # leave the merged changes unstaged for the gate
        verification = verify(merge.path)
        result.gate_passed = bool(getattr(verification, "passed", False))
        result.gate_message = str(getattr(verification, "message", ""))
        if not result.gate_passed:
            result.error = "the merged changes did not pass the completion gate; nothing was applied"
            return result
        applied = _git(root, "apply", "--binary", "--whitespace=nowarn", "-", input_bytes=merged_diff.encode("utf-8"), check=False)
        if applied.returncode != 0:
            result.error = "the merged changes could not be applied to your project: " + \
                applied.stderr.decode("utf-8", "replace").strip()[:300]
            return result
        result.applied = True
        result.status = "completed" if all(item.merged for item in result.subtasks) else "partial"
        return result
    except BestOfError as error:
        result.error = str(error)
        return result
    finally:
        result.seconds = round(time.monotonic() - started, 2)
        for worktree in [*worktrees, merge]:
            worktree.remove()


def render(result: ParallelResult) -> str:
    rows = [f"Parallel subtasks: {result.status} in {result.seconds:.1f} s"]
    for item in result.subtasks:
        mark = "merged" if item.merged else "not merged"
        rows.append(f"- {item.number}. {item.task[:70]} — {item.status}, {item.seconds:.1f} s, "
                    f"{item.changed_lines} changed lines, {mark}" + (f" ({item.error})" if item.error else ""))
    rows.append("Gate on the merged changes: " + ("passed" if result.gate_passed else "not passed"))
    rows.append("Applied to your project." if result.applied else f"Nothing was applied: {result.error}")
    return "\n".join(rows)
