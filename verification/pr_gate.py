"""
The completion gate for committed changes, such as a pull request in CI (roadmap F4).

The gate (coding_verifier.py) checks uncommitted changes against HEAD. For a pull request the
changes are already committed, so this moves HEAD back to the merge base with `git reset
--soft` (the files stay as they are; the PR's changes become staged), runs the gate, and
always moves HEAD back afterwards. Because HEAD is the merge base during the run, the
reproduce-first and mutation checks compare against the code before the pull request.

No model is involved: the gate checks the diff, syntax, the project's tests, changed-line
coverage, and the optional reproduce-first and mutation checks.
"""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

DEFAULT_GOAL = "Implement the changes in this pull request"


class GateError(RuntimeError):
    """The gate could not run (not a git repository, uncommitted changes, unknown base)."""


@dataclass
class GateResult:
    passed: bool
    message: str
    base: str
    head: str
    report: str = ""
    verification: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=120, check=False, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {result.stderr.strip()[:300] or 'unknown error'}")
    return result.stdout.strip()


def gate_goal(title: Optional[str]) -> str:
    """The pull request title when it reads as a code change (so a "fix" title gets the reproduce-first check)."""
    from verification.coding_verifier import task_requires_edits

    title = (title or "").strip()
    return title if title and task_requires_edits(title) else DEFAULT_GOAL


def run_pr_gate(
    workspace: Path,
    base: str,
    title: Optional[str] = None,
    verifier_factory: Optional[Callable[[str], Any]] = None,
) -> GateResult:
    """Runs the gate on the commits between `base` and HEAD. HEAD is always restored."""
    from verification.coding_verifier import CodingVerifier
    from verification.evidence_report import build_evidence_report

    root = Path(_git(Path(workspace), "rev-parse", "--show-toplevel"))
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise GateError("the working tree has uncommitted changes; commit or stash them first")
    head = _git(root, "rev-parse", "HEAD")
    try:
        merge_base = _git(root, "merge-base", base, head)
    except GateError as error:
        raise GateError(f"cannot find the merge base with {base!r} (in CI, check out with fetch-depth: 0): {error}") from None
    if merge_base == head:
        return GateResult(True, f"No changes between {base} and HEAD; nothing to verify.", merge_base, head)

    factory = verifier_factory or (lambda path: CodingVerifier(workspace=path))
    _git(root, "reset", "--soft", merge_base)
    try:
        verification = factory(str(root)).verify_task(gate_goal(title))
        report = build_evidence_report(verification, str(root), 0, 0) or ""
    finally:
        _git(root, "reset", "--soft", head)
    return GateResult(
        passed=bool(verification.passed),
        message=str(verification.message),
        base=merge_base,
        head=head,
        report=report,
        verification=asdict(verification) if hasattr(verification, "__dataclass_fields__") else {},
    )


def comment_body(result: GateResult) -> str:
    """Markdown for a pull request comment."""
    verdict = "✅ Buzzard Verify passed" if result.passed else "❌ Buzzard Verify failed"
    body = [f"## {verdict}", "", f"Checked `{result.base[:10]}..{result.head[:10]}`.", ""]
    if result.report:
        body += [result.report, ""]
    if not result.passed:
        body += ["<details><summary>Gate message</summary>", "", "```", result.message[:6000], "```", "", "</details>"]
    return "\n".join(body) + "\n"
