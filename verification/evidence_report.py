"""
The evidence shown at the end of a coding task.

Everything comes from real records (git, exit codes and the approval log). Anything not
checked is shown as not checked, never as a pass.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List, Optional

from verification.coding_verifier import _run_git, list_changed_files

TEST_FILE = re.compile(r"(^|/)(tests?/|test_[^/]*$|[^/]*_test\.|[^/]*\.(test|spec)\.)")
SOURCE_FILE = re.compile(r"\.(py|js|jsx|ts|tsx|mjs|go|rs|java|kt|cs|c|cc|cpp|h|hpp|rb|php|swift|dart)$")


def _change_lines(workspace: Path, changed: List[str]) -> List[str]:
    counts = {}
    code, output = _run_git(workspace, ["diff", "HEAD", "--numstat"])
    if code == 0:
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                counts[parts[2]] = f"+{parts[0]} -{parts[1]}"
    return [f"`{path}` {counts.get(path, 'new')}" for path in changed]


def build_evidence_report(verification: Any, workspace: str, approved: int, denied: int) -> Optional[str]:
    """Returns the report as markdown, or None when a task neither changed nor tested anything."""
    root = Path(workspace)
    changed = list_changed_files(root)
    command = getattr(verification, "test_command", None)
    if not changed and not command:
        return None

    lines = ["**Evidence Report**", ""]
    exit_code = getattr(verification, "test_exit_code", None)
    if command and exit_code == 0:
        lines.append(f"- ✓ Tests: `{command}` exit 0, run by the gate")
    elif command and exit_code is not None:
        lines.append(f"- ✕ Tests: `{command}` exit {exit_code}, run by the gate")
    elif command:
        lines.append(f"- ○ Tests: `{command}` was not run")
    else:
        lines.append("- ○ Tests: not checked (no test runner found)")

    lines.append("- ✓ Changed: " + ", ".join(_change_lines(root, changed)) if changed else "- ○ Changed: no files")
    lines.append(f"- ✓ Approvals: {approved} approved, {denied} denied")

    source_changed = [path for path in changed if SOURCE_FILE.search(path) and not TEST_FILE.search(path)]
    if source_changed and not any(TEST_FILE.search(path) for path in changed):
        lines.append("- ⚠ No test changed: the gate only proves what existing tests check")

    lint_status = getattr(verification, "lint_status", "not configured")
    lint_mark = {"passed": "✓", "issues found": "⚠"}.get(lint_status, "○")
    lines.append(f"- {lint_mark} Lint: {lint_status}")
    return "\n".join(lines)
