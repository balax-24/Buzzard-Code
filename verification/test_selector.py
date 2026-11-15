"""
Test Impact Selector for Buzzard Code.

Identifies, prioritizes, and constructs targeted test execution commands
based on modified source files and the Engineering Memory Graph.

Allows sub-second inner feedback loops by running only affected tests,
while reserving full suite execution for final evidence verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from intelligence.memory_graph import EngineeringMemoryGraph


@dataclass
class SelectedTests:
    runner: str  # 'pytest', 'vitest', 'jest', 'cargo', 'go', 'npm', 'unknown'
    targeted_test_files: List[str] = field(default_factory=list)
    targeted_command: Optional[str] = None
    full_command: Optional[str] = None
    all_tests_found: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runner": self.runner,
            "targeted_test_files": self.targeted_test_files,
            "targeted_command": self.targeted_command,
            "full_command": self.full_command,
            "all_tests_found": self.all_tests_found,
            "confidence": self.confidence,
        }


class TestImpactSelector:
    """
    Selects affected tests using structural dependency analysis.
    """
    __test__ = False

    def __init__(self, workspace_root: Path, graph: Optional[EngineeringMemoryGraph] = None):
        self.workspace_root = workspace_root.resolve()
        self.graph = graph or EngineeringMemoryGraph(self.workspace_root)
        if not self.graph.files:
            self.graph.index_workspace()

    def detect_runner(self) -> str:
        """Detects the primary test runner of the workspace."""
        root = self.workspace_root

        # Python
        if (root / "pytest.ini").exists() or (root / "pyproject.toml").exists() or (root / "setup.cfg").exists():
            return "pytest"
        if any(root.glob("test_*.py")) or any(root.glob("tests/*.py")):
            return "pytest"

        # Node / JS / TS
        if (root / "package.json").exists():
            pkg_text = (root / "package.json").read_text(encoding="utf-8", errors="replace")
            if "vitest" in pkg_text:
                return "vitest"
            if "jest" in pkg_text:
                return "jest"
            return "npm"

        # Rust
        if (root / "Cargo.toml").exists():
            return "cargo"

        # Go
        if (root / "go.mod").exists():
            return "go"

        return "unknown"

    def select_tests_for_files(self, changed_files: List[str]) -> SelectedTests:
        """
        Maps a list of changed file paths to the prioritized set of test files and commands.
        """
        runner = self.detect_runner()
        normalized_targets = [f.replace("\\", "/").strip("./") for f in changed_files]

        targeted_tests: Set[str] = set()

        for target in normalized_targets:
            # 1. Direct query in Engineering Memory Graph
            impact = self.graph.get_impact_radius(target)
            if impact["found"]:
                for t in impact["associated_tests"]:
                    targeted_tests.add(t)

                # Check downstream files that import this module
                for dep in impact["imported_by"]:
                    dep_impact = self.graph.get_impact_radius(dep)
                    for t in dep_impact.get("associated_tests", []):
                        targeted_tests.add(t)

            # 2. Heuristic convention matching: foo.py -> test_foo.py / foo.test.ts
            target_p = Path(target)
            stem = target_p.stem
            for f_path in self.graph.files.keys():
                if f_path.startswith("test") or "/test" in f_path:
                    if stem in f_path:
                        targeted_tests.add(f_path)

        sorted_tests = sorted(list(targeted_tests))
        all_tests = sorted([f for f in self.graph.files.keys() if "test" in f.lower()])

        targeted_cmd = self._build_test_command(runner, sorted_tests)
        full_cmd = self._build_full_test_command(runner)

        return SelectedTests(
            runner=runner,
            targeted_test_files=sorted_tests,
            targeted_command=targeted_cmd,
            full_command=full_cmd,
            all_tests_found=all_tests,
            confidence=0.9 if sorted_tests else 0.5,
        )

    def _build_test_command(self, runner: str, test_files: List[str]) -> Optional[str]:
        if not test_files:
            return self._build_full_test_command(runner)

        files_str = " ".join(test_files)
        if runner == "pytest":
            return f"pytest {files_str} -v"
        elif runner in ("vitest", "jest"):
            return f"npx {runner} run {files_str}"
        elif runner == "npm":
            return f"npm test -- {files_str}"
        elif runner == "cargo":
            return "cargo test"
        elif runner == "go":
            return f"go test {files_str}"
        return f"pytest {files_str}"

    def _build_full_test_command(self, runner: str) -> str:
        if runner == "pytest":
            return "pytest"
        elif runner in ("vitest", "jest"):
            return f"npx {runner} run"
        elif runner == "npm":
            return "npm test"
        elif runner == "cargo":
            return "cargo test"
        elif runner == "go":
            return "go test ./..."
        return "pytest"
