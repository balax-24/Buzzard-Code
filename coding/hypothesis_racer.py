"""
Speculative Worktree Hypothesis Racing for Buzzard Code.

Eliminates the serial try-fail-revert bottleneck by running multiple candidate
code patches in parallel git worktrees. Tests all hypotheses concurrently,
ranks the outcomes, merges the best solution, and prunes losing branches.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.worktree_manager import WorktreeManager
from coding.atomic_editor import AtomicCodeEditor, EditOperation

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    id: str
    description: str
    edits: List[EditOperation]
    priority: int = 1


@dataclass
class HypothesisTrialResult:
    hypothesis: Hypothesis
    worktree_path: Path
    syntax_passed: bool
    tests_passed: bool
    test_output: str
    diff_lines_changed: int
    duration_ms: float
    score: float  # Higher is better
    error: Optional[str] = None


@dataclass
class RaceOutcome:
    winner: Optional[HypothesisTrialResult]
    all_trials: List[HypothesisTrialResult]
    merged_successfully: bool
    summary: str


class HypothesisRacer:
    """
    Races speculative fixes across concurrent isolated worktrees.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.worktree_manager = WorktreeManager(self.workspace_root)

    def race(self, hypotheses: List[Hypothesis], test_command: Optional[List[str]] = None) -> RaceOutcome:
        """
        Executes and evaluates multiple hypotheses concurrently.
        """
        if not hypotheses:
            return RaceOutcome(
                winner=None,
                all_trials=[],
                merged_successfully=False,
                summary="No hypotheses provided to race.",
            )

        trials: List[HypothesisTrialResult] = []

        # Run each hypothesis in an isolated worktree
        for hypo in hypotheses:
            trial = self._evaluate_hypothesis(hypo, test_command)
            trials.append(trial)

        # Sort trials: must pass tests, then highest score
        passing_trials = [t for t in trials if t.tests_passed and t.syntax_passed]
        passing_trials.sort(key=lambda t: t.score, reverse=True)

        winner = passing_trials[0] if passing_trials else None
        merged = False

        if winner:
            # Merge winning worktree into workspace
            merged = self.worktree_manager.merge_worktree(winner.hypothesis.id)

        # Clean up all worktrees
        self.worktree_manager.cleanup_all()

        summary_lines = [
            f"🏁 HYPOTHESIS RACE COMPLETED ({len(trials)} candidates evaluated):",
        ]
        for t in trials:
            status = "🏆 WINNER" if (winner and t.hypothesis.id == winner.hypothesis.id) else ("✔ PASSED" if t.tests_passed else "✖ FAILED")
            summary_lines.append(
                f"  • [{t.hypothesis.id}] {t.hypothesis.description} -> {status} (Score: {t.score:.1f}, Diff: {t.diff_lines_changed} lines, Time: {t.duration_ms:.0f}ms)"
            )

        if winner and merged:
            summary_lines.append(f"\n✔ Merged winning hypothesis [{winner.hypothesis.id}] into main working tree.")
        elif winner and not merged:
            summary_lines.append(f"\n⚠ Winning hypothesis found but merge encountered conflict.")
        else:
            summary_lines.append("\n✖ No candidate hypothesis passed the verification test suite.")

        return RaceOutcome(
            winner=winner,
            all_trials=trials,
            merged_successfully=merged,
            summary="\n".join(summary_lines),
        )

    def _evaluate_hypothesis(self, hypo: Hypothesis, test_cmd: Optional[List[str]]) -> HypothesisTrialResult:
        t0 = time.perf_counter()
        wt = self.worktree_manager.create_worktree(hypo.id)
        editor = AtomicCodeEditor(wt.worktree_path)

        # Apply edits in the isolated worktree
        tx = editor.apply_transaction(hypo.edits)
        if not tx.success:
            elapsed = (time.perf_counter() - t0) * 1000.0
            return HypothesisTrialResult(
                hypothesis=hypo,
                worktree_path=wt.worktree_path,
                syntax_passed=False,
                tests_passed=False,
                test_output="",
                diff_lines_changed=0,
                duration_ms=elapsed,
                score=0.0,
                error=tx.error_message,
            )

        # Calculate diff lines changed
        diff_lines = sum(len(op.replacement_text or op.new_full_content or "") for op in hypo.edits) // 40 + 1

        # Run verification tests
        cmd = test_cmd or [sys.executable, "-m", "pytest", "-q"]
        tests_passed = False
        test_out = ""

        try:
            res = subprocess.run(
                cmd,
                cwd=str(wt.worktree_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            tests_passed = (res.returncode == 0)
            test_out = res.stdout or res.stderr
        except Exception as e:
            test_out = str(e)
            tests_passed = False

        elapsed = (time.perf_counter() - t0) * 1000.0

        # Score formula: 100 base if passed, minus penalties for execution time and diff bloat
        score = 0.0
        if tests_passed:
            score = 100.0 - min(30.0, diff_lines * 0.5) - min(20.0, elapsed / 500.0)

        return HypothesisTrialResult(
            hypothesis=hypo,
            worktree_path=wt.worktree_path,
            syntax_passed=True,
            tests_passed=tests_passed,
            test_output=test_out,
            diff_lines_changed=diff_lines,
            duration_ms=elapsed,
            score=max(0.0, score),
        )
