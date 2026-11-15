"""
Causal Code History and Rationale Linker for Buzzard Code.

Provides historical intent and 'Why' memory to the agent:
1. Traces symbols and lines back to originating commits via git blame.
2. Extracts developer rationale, bugfix references, and issue tags.
3. Warns the agent if it is modifying intentional bugfixes or historical workarounds.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CommitRationale:
    commit_hash: str
    author: str
    date: str
    subject: str
    body: str
    is_bugfix_or_workaround: bool
    risk_warning: Optional[str] = None


@dataclass
class LineCausalContext:
    line_number: int
    content: str
    commit: CommitRationale


@dataclass
class CausalReport:
    file_path: str
    target_lines: List[int]
    line_contexts: List[LineCausalContext] = field(default_factory=list)
    has_historical_workarounds: bool = False
    warnings: List[str] = field(default_factory=list)

    def format_summary(self) -> str:
        lines = [f"📜 CAUSAL HISTORY & RATIONALE: {self.file_path}"]
        if self.warnings:
            lines.append("⚠ HISTORICAL INTENT WARNINGS:")
            for w in self.warnings:
                lines.append(f"  • {w}")
        else:
            lines.append("  • No historical bugfix or workaround constraints detected.")

        for ctx in self.line_contexts[:5]:
            cmt = ctx.commit
            tag = " [BUGFIX/WORKAROUND]" if cmt.is_bugfix_or_workaround else ""
            lines.append(f"  - L{ctx.line_number}: {cmt.commit_hash[:7]} by {cmt.author} ({cmt.date}){tag}")
            lines.append(f"    Commit: \"{cmt.subject}\"")

        return "\n".join(lines)


class CausalHistoryLinker:
    """
    Connects code symbols and lines to their historical commit rationale.
    """

    BUGFIX_PATTERNS = [
        re.compile(r"fix(?:es|ed)?\b", re.IGNORECASE),
        re.compile(r"bug\b", re.IGNORECASE),
        re.compile(r"workaround\b", re.IGNORECASE),
        re.compile(r"regression\b", re.IGNORECASE),
        re.compile(r"hotfix\b", re.IGNORECASE),
        re.compile(r"patch\b", re.IGNORECASE),
        re.compile(r"resolve[ds]?\b", re.IGNORECASE),
    ]

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def _is_git(self) -> bool:
        return (self.workspace_root / ".git").exists()

    def analyze_file_lines(self, rel_path: str, line_numbers: List[int]) -> CausalReport:
        """
        Runs git blame and inspects commit rationale for specific lines.
        """
        abs_p = self.workspace_root / rel_path
        if not abs_p.exists() or not self._is_git():
            return CausalReport(file_path=rel_path, target_lines=line_numbers)

        contexts: List[LineCausalContext] = []
        warnings: List[str] = []
        has_workarounds = False

        commit_cache: Dict[str, CommitRationale] = {}

        for l_num in line_numbers:
            # Run git blame -L <l_num>,<l_num> --porcelain <file>
            try:
                res = subprocess.run(
                    ["git", "blame", "-L", f"{l_num},{l_num}", "--porcelain", rel_path],
                    cwd=str(self.workspace_root),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode != 0:
                    continue

                lines = res.stdout.splitlines()
                if not lines:
                    continue

                commit_hash = lines[0].split()[0]
                if commit_hash not in commit_cache:
                    commit_cache[commit_hash] = self._get_commit_details(commit_hash)

                cmt = commit_cache[commit_hash]
                content = lines[-1].strip() if lines[-1].startswith("\t") else ""

                if cmt.is_bugfix_or_workaround:
                    has_workarounds = True
                    warn = f"Line {l_num} was created to fix an issue: '{cmt.subject}'. Modifying it may re-introduce regressions."
                    if warn not in warnings:
                        warnings.append(warn)

                contexts.append(LineCausalContext(line_number=l_num, content=content, commit=cmt))
            except Exception as e:
                logger.warning("Failed git blame for %s:%d: %s", rel_path, l_num, e)

        return CausalReport(
            file_path=rel_path,
            target_lines=line_numbers,
            line_contexts=contexts,
            has_historical_workarounds=has_workarounds,
            warnings=warnings,
        )

    def _get_commit_details(self, commit_hash: str) -> CommitRationale:
        try:
            res = subprocess.run(
                ["git", "show", "--format=%an%n%ad%n%s%n%b", "--no-patch", commit_hash],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                parts = res.stdout.splitlines()
                author = parts[0] if len(parts) > 0 else "unknown"
                date = parts[1] if len(parts) > 1 else ""
                subject = parts[2] if len(parts) > 2 else ""
                body = "\n".join(parts[3:]) if len(parts) > 3 else ""

                full_msg = subject + " " + body
                is_fix = any(p.search(full_msg) for p in self.BUGFIX_PATTERNS)

                return CommitRationale(
                    commit_hash=commit_hash,
                    author=author,
                    date=date,
                    subject=subject,
                    body=body,
                    is_bugfix_or_workaround=is_fix,
                )
        except Exception:
            pass

        return CommitRationale(
            commit_hash=commit_hash,
            author="unknown",
            date="",
            subject="",
            body="",
            is_bugfix_or_workaround=False,
        )
