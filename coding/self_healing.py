"""
Autonomous Self-Healing Loop for Buzzard Code.

Orchestrates the closed-loop repair cycle:
`Test Failure -> Diagnostic Extraction -> AST Symbol Correlation -> Repair Suggestion -> Re-Verification`.

Parses pytest, jest, and compiler outputs to pinpoint exact failing lines,
assertions, and dependencies, enabling the agent to fix bugs autonomously.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence.memory_graph import EngineeringMemoryGraph


@dataclass
class FailureDiagnostic:
    test_file: str
    test_function: Optional[str] = None
    failing_line: Optional[int] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: List[str] = field(default_factory=list)
    related_symbols: List[str] = field(default_factory=list)


@dataclass
class RepairPlan:
    failure_count: int
    diagnostics: List[FailureDiagnostic]
    suggested_actions: List[str]
    priority_files_to_edit: List[str]

    def format_diagnostic_report(self) -> str:
        lines = [
            f"⚡ AUTONOMOUS REPAIR DIAGNOSTICS ({self.failure_count} failing tests):",
        ]
        for idx, d in enumerate(self.diagnostics, 1):
            lines.append(f"  {idx}. [{d.error_type or 'FAILURE'}] in {d.test_file}")
            if d.test_function:
                lines.append(f"     Function: {d.test_function}()")
            if d.failing_line:
                lines.append(f"     Line: {d.failing_line}")
            if d.error_message:
                lines.append(f"     Message: {d.error_message}")
            if d.related_symbols:
                lines.append(f"     Related symbols to inspect: {', '.join(d.related_symbols)}")

        if self.priority_files_to_edit:
            lines.append(f"  • Recommended files to repair:")
            for f in self.priority_files_to_edit:
                lines.append(f"    - {f}")

        return "\n".join(lines)


class AutonomousSelfHealingLoop:
    """
    Analyzes test failures and generates targeted repair plans.
    """

    def __init__(self, workspace_root: Path, graph: Optional[EngineeringMemoryGraph] = None):
        self.workspace_root = workspace_root.resolve()
        self.graph = graph or EngineeringMemoryGraph(self.workspace_root)
        if not self.graph.files:
            self.graph.index_workspace()

    def parse_pytest_failures(self, test_output: str) -> List[FailureDiagnostic]:
        """
        Extracts structured diagnostics from pytest terminal output.
        """
        diagnostics: List[FailureDiagnostic] = []

        # Find failures section: ____________________ test_name ____________________
        test_block_pattern = re.compile(r"_{3,}\s+([a-zA-Z0-9_]+)\s+_{3,}")
        matches = list(test_block_pattern.finditer(test_output))

        for i, match in enumerate(matches):
            func_name = match.group(1)
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(test_output)
            block = test_output[start_pos:end_pos]

            test_file = ""
            line_no = None
            err_type = "AssertionError"
            err_msg = ""
            trace_lines = []

            for line in block.split("\n"):
                # E   assert ... or E   ValueError: ...
                if line.startswith("E   "):
                    err_line = line[4:].strip()
                    if ":" in err_line and not err_line.startswith("assert"):
                        parts = err_line.split(":", 1)
                        err_type = parts[0].strip()
                        err_msg = parts[1].strip()
                    else:
                        err_msg = err_line
                elif re.search(r"tests/[a-zA-Z0-9_\/.-]+:\d+:", line):
                    # File path and line: tests/test_foo.py:42: in test_func
                    m_file = re.search(r"([a-zA-Z0-9_\/.-]+):(\d+):", line)
                    if m_file:
                        test_file = m_file.group(1)
                        line_no = int(m_file.group(2))
                trace_lines.append(line)

            # Relate to implementation symbols via graph
            related: List[str] = []
            if test_file and test_file in self.graph.files:
                f_node = self.graph.files[test_file]
                related.extend(list(f_node.imports)[:5])

            diagnostics.append(
                FailureDiagnostic(
                    test_file=test_file or "tests",
                    test_function=func_name,
                    failing_line=line_no,
                    error_type=err_type,
                    error_message=err_msg or "Test failed assertion",
                    stack_trace=trace_lines[-8:],
                    related_symbols=related,
                )
            )

        # Fallback: if no individual blocks found, scan for summary: FAILED tests/test_foo.py::test_bar
        if not diagnostics:
            summary_pattern = re.compile(r"FAILED\s+([a-zA-Z0-9_\/.-]+)::([a-zA-Z0-9_]+)(?:\s+-\s+(.+))?")
            for m in summary_pattern.finditer(test_output):
                diagnostics.append(
                    FailureDiagnostic(
                        test_file=m.group(1),
                        test_function=m.group(2),
                        error_message=m.group(3) or "Test execution failed",
                    )
                )

        # Fallback: standard Python traceback (File "...", line X, in Y)
        if not diagnostics:
            tb_pattern = re.compile(r"File [\"']([^\"']+)[\"'], line (\d+)(?:, in (\w+))?")
            for m in tb_pattern.finditer(test_output):
                diagnostics.append(
                    FailureDiagnostic(
                        test_file=m.group(1),
                        failing_line=int(m.group(2)),
                        test_function=m.group(3),
                        error_message="Failure detected from execution trace",
                    )
                )

        return diagnostics

    def create_repair_plan(self, test_output: str) -> RepairPlan:
        """
        Creates an actionable repair plan from test failure output.
        """
        diagnostics = self.parse_pytest_failures(test_output)

        priority_files: set[str] = set()
        for d in diagnostics:
            # Map test file to the implementation file it tests
            if d.test_file:
                # E.g. tests/test_auth.py -> auth.py
                clean_test = Path(d.test_file).stem.replace("test_", "").replace("_test", "")
                for rel_path in self.graph.files.keys():
                    if not rel_path.startswith("test") and clean_test in rel_path.lower():
                        priority_files.add(rel_path)

        actions = [
            "Inspect the failing line and assertion expectation in the test.",
            "Verify whether the bug is in the implementation logic or in the test assertion itself.",
            "Formulate an atomic patch using AtomicCodeEditor to fix the root cause.",
            "Re-run only the affected test to verify resolution.",
        ]

        return RepairPlan(
            failure_count=len(diagnostics),
            diagnostics=diagnostics,
            suggested_actions=actions,
            priority_files_to_edit=sorted(list(priority_files)),
        )
