"""
Best-of-N attempts with the completion gate as judge (roadmap item E2).

For a hard task, run the same task several times, each in its own git worktree that starts from
the user's current working state, let the completion gate verify each attempt, and keep only the
best verified one. The others are discarded.

Design decisions:
- Attempts run one after another, not in parallel: each attempt asks for approvals like a normal
  run, and the tools share one active-workspace setting. The quality gain comes from the gate
  choosing between attempts, which does not need parallelism.
- Each worktree lives under BUZZARD_HOME, outside the repository. It starts at HEAD, receives the
  user's uncommitted changes (tracked diff plus untracked files), and that state is committed
  inside the worktree as the attempt's base, so an attempt's own changes are exactly
  `git diff <base>`.
- Scoring is deterministic: tests passed, then reproduce-first proof, then changed-line coverage,
  then lint, then the smaller diff. Only attempts whose gate passed can win.
- The winner's diff is applied to the user's project with `git apply`; if that fails, nothing is
  applied and the outcome says so. The user's project is not touched while attempts run.
- Every worktree is removed afterwards, whatever happens.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
VARIATION_HINT = (
    "\n\n(This is attempt {number} of {total}. Earlier attempts may have taken the obvious route; "
    "if there is a reasonable alternative approach, prefer it.)"
)


class BestOfError(RuntimeError):
    """Attempts could not be set up; the message is safe to show the user."""


@dataclass
class AttemptResult:
    number: int
    status: str
    passed: bool = False
    score: Tuple = ()
    diff: str = ""
    changed_lines: int = 0
    summary: str = ""
    final_answer: str = ""
    evidence_report: Optional[str] = None
    error: Optional[str] = None


def _git(directory: Path, *args: str, input_bytes: Optional[bytes] = None, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", str(directory), *args], input=input_bytes, capture_output=True,
        timeout=180, check=False, stdin=None if input_bytes is not None else subprocess.DEVNULL,
    )
    if check and result.returncode != 0:
        raise BestOfError(f"git {' '.join(args[:2])} failed: {result.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return result


def attempts_directory(root: Path) -> Path:
    key = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard")
    return base / "attempts" / key


def score_attempt(verification: Any, changed_lines: int) -> Tuple:
    """Higher is better. Only used to compare attempts whose gate passed."""
    reproduction = getattr(verification, "reproduction", None) or {}
    coverage = getattr(verification, "changed_line_coverage", None) or {}
    percent = coverage.get("percent") if coverage.get("measured") else None
    lint_ok = getattr(verification, "lint_status", "") in ("passed", "not configured")
    return (
        1 if getattr(verification, "passed", False) else 0,
        1 if reproduction.get("status") == "reproduced" else 0,
        float(percent) if percent is not None else -1.0,
        1 if lint_ok else 0,
        -changed_lines,
    )


def _describe(verification: Any, changed_lines: int) -> str:
    if verification is None:
        return "no verification result"
    parts = ["tests passed" if getattr(verification, "passed", False) else "gate rejected"]
    reproduction = (getattr(verification, "reproduction", None) or {}).get("status")
    if reproduction == "reproduced":
        parts.append("bug reproduced")
    coverage = getattr(verification, "changed_line_coverage", None) or {}
    if coverage.get("measured") and coverage.get("percent") is not None:
        parts.append(f"{coverage['percent']}% changed-line coverage")
    parts.append(f"{changed_lines} changed lines")
    return ", ".join(parts)


class Worktree:
    """A detached worktree holding the user's current state as its base commit."""

    def __init__(self, root: Path, path: Path):
        self.root = root
        self.path = path
        self.base = ""

    def create(self, tracked_patch: bytes, untracked: List[str]) -> None:
        self.remove()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _git(self.root, "worktree", "add", "--detach", "--force", str(self.path), "HEAD")
        if tracked_patch.strip():
            _git(self.path, "apply", "--binary", "--whitespace=nowarn", "-", input_bytes=tracked_patch)
        for relative in untracked:
            target = self.path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.root / relative, target)
        _git(self.path, "add", "-A")
        _git(self.path, "-c", "user.name=Buzzard", "-c", "user.email=buzzard@localhost", "commit",
             "--allow-empty", "--no-verify", "-q", "-m", "buzzard attempt base")
        self.base = _git(self.path, "rev-parse", "HEAD").stdout.decode().strip()

    def changes(self) -> Tuple[str, int]:
        """The attempt's own changes since its base, excluding Buzzard's runtime files."""
        _git(self.path, "add", "-A", "--", ".", ":(exclude).buzzard")
        diff = _git(self.path, "diff", "--cached", "--binary", self.base).stdout.decode("utf-8", "replace")
        stat = _git(self.path, "diff", "--cached", "--numstat", self.base).stdout.decode("utf-8", "replace")
        lines = 0
        for row in stat.splitlines():
            added, removed, *_ = row.split("\t") + ["", ""]
            lines += (int(added) if added.isdigit() else 0) + (int(removed) if removed.isdigit() else 0)
        return diff, lines

    def remove(self) -> None:
        _git(self.root, "worktree", "remove", "--force", str(self.path), check=False)
        if self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        _git(self.root, "worktree", "prune", check=False)


def _current_state(root: Path) -> Tuple[bytes, List[str]]:
    tracked = _git(root, "diff", "--binary", "HEAD").stdout
    untracked = [
        path for path in _git(root, "ls-files", "--others", "--exclude-standard").stdout.decode("utf-8", "replace").splitlines()
        if path and not path.replace("\\", "/").startswith(".buzzard/")
    ]
    return tracked, untracked


def run_best_of(session: Any, goal: str, target: str, scope: List[str], session_id: str, attempts: int):
    """Runs `attempts` verified attempts and applies the best. Call with the session's run lock held."""
    from agent.project_context import save_conversation
    from agent.run_session import RunOutcome
    from tools.filesystem import get_active_workspace, set_active_workspace

    attempts = max(2, min(int(attempts), MAX_ATTEMPTS))
    root = Path(get_active_workspace()).resolve()
    original_config = session.config
    conversation = list(session.conversation)
    results: List[AttemptResult] = []
    try:
        if _git(root, "rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
            raise BestOfError("several attempts need the project to be a git repository")
        tracked, untracked = _current_state(root)
        directory = attempts_directory(root)
        for number in range(1, attempts + 1):
            if session.stop_event.is_set():
                break
            worktree = Worktree(root, directory / f"attempt-{number}")
            try:
                worktree.create(tracked, untracked)
                set_active_workspace(str(worktree.path))
                session.config = {**original_config, "workspace": str(worktree.path)}
                session.conversation = list(conversation)
                attempt_goal = goal + (VARIATION_HINT.format(number=number, total=attempts) if number > 1 else "")
                outcome = session._run(attempt_goal, target, scope, f"{session_id}-attempt{number}")
                verification = getattr(session, "last_verification", None)
                diff, changed = worktree.changes()
                passed = bool(getattr(verification, "passed", False)) and outcome.status == "completed" and bool(diff.strip())
                results.append(AttemptResult(
                    number=number, status=outcome.status, passed=passed,
                    score=score_attempt(verification, changed), diff=diff, changed_lines=changed,
                    summary=_describe(verification, changed), final_answer=outcome.final_answer,
                    evidence_report=outcome.evidence_report, error=outcome.error,
                ))
            except BestOfError as error:
                results.append(AttemptResult(number=number, status="failed", summary=str(error), error=str(error)))
            finally:
                set_active_workspace(str(root))
                session.config = original_config
                worktree.remove()
    except BestOfError as error:
        session.conversation = conversation
        return RunOutcome(session_id, "failed", error=str(error))
    finally:
        set_active_workspace(str(root))
        session.config = original_config

    session.conversation = conversation
    report = ["**Attempts**", ""] + [
        f"- Attempt {result.number}: {result.summary}" + (f" ({result.status})" if result.status != "completed" else "")
        for result in results
    ]
    candidates = [result for result in results if result.passed]
    if not candidates:
        session.remember_turn(goal, "None of the attempts passed the completion gate.")
        return RunOutcome(session_id, "failed", final_answer="None of the attempts passed the completion gate; no changes were applied.",
                          evidence_report="\n".join(report), error="No attempt passed the completion gate.")
    winner = max(candidates, key=lambda result: result.score)
    applied = _git(root, "apply", "--binary", "--whitespace=nowarn", "-", input_bytes=winner.diff.encode("utf-8"), check=False)
    if applied.returncode != 0:
        detail = applied.stderr.decode("utf-8", "replace").strip()[:300]
        return RunOutcome(session_id, "failed", evidence_report="\n".join(report),
                          error=f"The best attempt ({winner.number}) could not be applied to your project: {detail}")
    report.append(f"- Kept attempt {winner.number}; its changes are now in your project. The other attempts were discarded.")
    evidence = "\n".join(report) + ("\n\n" + winner.evidence_report if winner.evidence_report else "")
    session.remember_turn(goal, winner.final_answer)
    return RunOutcome(session_id, "completed", final_answer=winner.final_answer, evidence_report=evidence)
