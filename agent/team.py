"""
Planner, workers and reviewer (roadmap E3).

1. The planner (one model call) splits a goal into at most six independent subtasks.
2. The workers run them in parallel git worktrees (parallel.py); their changes are merged.
3. The completion gate runs on the merged result.
4. The reviewer (one model call) reads the merged diff and either approves it or lists blocking
   issues. Only a gated and approved result is applied to the project.

The review fails closed: if the reviewer's answer cannot be read, nothing is applied.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agent.parallel import MAX_SUBTASKS, ParallelResult, WorkerCommand, run_parallel

MAX_DIFF_FOR_REVIEW = 30_000

PLANNER_PROMPT = (
    "You split a software task into independent subtasks that separate engineers can do at the same "
    "time in separate copies of the repository, without seeing each other's work. Each subtask must "
    "change different files or different parts of files, be complete on its own, and say which files "
    f"it touches. Use as few subtasks as the work needs (1 to {MAX_SUBTASKS}); if the work cannot be "
    'split safely, return one subtask. Reply with JSON only: {"subtasks": ["...", "..."]}'
)
REVIEWER_PROMPT = (
    "You review a combined diff produced by several engineers for one task. The tests already pass. "
    "Look for bugs, missing pieces of the task, changes that contradict each other, and security "
    'problems. Reply with JSON only: {"approve": true or false, "issues": ["..."]}. Approve unless '
    "there is a real problem; list only blocking issues."
)


@dataclass
class TeamResult:
    goal: str
    subtasks: List[str] = field(default_factory=list)
    parallel: Optional[ParallelResult] = None
    review_approved: bool = False
    review_issues: List[str] = field(default_factory=list)
    applied: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal, "subtasks": self.subtasks, "review_approved": self.review_approved,
            "review_issues": self.review_issues, "applied": self.applied, "error": self.error,
            "parallel": self.parallel.to_dict() if self.parallel else None,
        }


def _reply_json(reply: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    text = str(((reply or {}).get("message") or {}).get("content") or "")
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def plan_subtasks(provider: Any, goal: str) -> List[str]:
    """The planner's subtasks; falls back to the whole goal as one subtask if the answer is unusable."""
    data = _reply_json(provider.chat([{"role": "system", "content": PLANNER_PROMPT},
                                      {"role": "user", "content": goal}]))
    items = (data or {}).get("subtasks")
    subtasks = [str(item).strip() for item in items if str(item).strip()] if isinstance(items, list) else []
    return subtasks[:MAX_SUBTASKS] or [goal]


def review_diff(provider: Any, goal: str, diff: str) -> tuple[bool, List[str]]:
    """(approved, issues). An unreadable answer is not an approval."""
    shown = diff if len(diff) <= MAX_DIFF_FOR_REVIEW else diff[:MAX_DIFF_FOR_REVIEW] + "\n[diff truncated]"
    data = _reply_json(provider.chat([{"role": "system", "content": REVIEWER_PROMPT},
                                      {"role": "user", "content": f"Task: {goal}\n\nDiff:\n{shown}"}]))
    if data is None or not isinstance(data.get("approve"), bool):
        return False, ["the reviewer's answer could not be read, so the changes were not approved"]
    issues = [str(item) for item in data.get("issues") or [] if str(item).strip()]
    return data["approve"], issues


def run_team(
    workspace: Path,
    goal: str,
    provider: Any,
    worker_command: WorkerCommand,
    gate: Callable[[Path], Any],
    review: bool = True,
) -> TeamResult:
    """Plans, runs the workers, gates and reviews the merge, and applies it only if both pass."""
    from agent.best_of import _git

    result = TeamResult(goal=goal)
    result.subtasks = plan_subtasks(provider, goal)

    def gate_then_review(merged: Path) -> Any:
        verification = gate(merged)
        if not getattr(verification, "passed", False) or not review:
            result.review_approved = not review and bool(getattr(verification, "passed", False))
            return verification
        _git(merged, "add", "-A", "--", ".", ":(exclude).buzzard")  # include files the workers created
        diff = _git(merged, "diff", "--cached", "HEAD").stdout.decode("utf-8", "replace")
        _git(merged, "reset", "-q")
        result.review_approved, result.review_issues = review_diff(provider, goal, diff)
        if result.review_approved:
            return verification
        return _Rejected(f"the reviewer did not approve the merged changes: {'; '.join(result.review_issues)}")

    result.parallel = run_parallel(workspace, result.subtasks, worker_command, gate_then_review, minimum=1)
    result.applied = result.parallel.applied
    result.error = result.parallel.error
    return result


@dataclass
class _Rejected:
    message: str
    passed: bool = False


def render(result: TeamResult) -> str:
    from agent.parallel import render as render_parallel

    rows = [f"Plan: {len(result.subtasks)} subtask(s)"] + [f"  {number}. {task}" for number, task in enumerate(result.subtasks, 1)]
    if result.parallel is not None:
        rows.append(render_parallel(result.parallel))
    if result.review_issues:
        rows.append("Review issues:\n" + "\n".join(f"- {issue}" for issue in result.review_issues))
    elif result.review_approved and result.applied:
        rows.append("Review: approved.")
    return "\n".join(rows)
