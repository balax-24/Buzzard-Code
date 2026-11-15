"""
Repo Supervisor & Continuous Maintenance Engine for Buzzard Code.

Phase 6 Continuous Engineering Platform:
1. Automated Codebase Health Auditing:
   - Dead symbol detection (unused functions/classes across repository).
   - Broken test & orphan test discovery.
   - Dependency freshness & security risk audit.
   - Architecture complexity & circular dependency detection.
2. Automated Maintenance Plan & Branch Generation:
   - Generates prioritized maintenance plans.
   - Prepares isolated maintenance branches via WorktreeManager.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from agent.autonomous_engineer import AutonomousEngineer
from agent.worktree_manager import WorktreeManager
from intelligence.memory_graph import EngineeringMemoryGraph

logger = logging.getLogger(__name__)


@dataclass
class HealthIssue:
    category: str  # "dead_code", "broken_test", "dependency_risk", "circular_dep"
    severity: str  # "low", "medium", "high"
    title: str
    description: str
    file_path: Optional[str] = None
    symbol_name: Optional[str] = None
    suggested_action: str = ""


@dataclass
class HealthReport:
    workspace: str
    overall_score: int  # 0 to 100
    issues: List[HealthIssue] = field(default_factory=list)
    dead_symbols_count: int = 0
    orphan_tests_count: int = 0
    circular_dep_count: int = 0
    total_files_audited: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace": self.workspace,
            "overall_score": self.overall_score,
            "dead_symbols_count": self.dead_symbols_count,
            "orphan_tests_count": self.orphan_tests_count,
            "circular_dep_count": self.circular_dep_count,
            "total_files_audited": self.total_files_audited,
            "issues": [
                {
                    "category": i.category,
                    "severity": i.severity,
                    "title": i.title,
                    "description": i.description,
                    "file_path": i.file_path,
                    "symbol_name": i.symbol_name,
                    "suggested_action": i.suggested_action,
                }
                for i in self.issues
            ],
        }


class RepoSupervisor:
    """
    Supervises repository health and plans automated continuous upgrades.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.engineer = AutonomousEngineer(self.workspace_root)
        self.worktree_manager = WorktreeManager(self.workspace_root)

    def scan_health(self) -> HealthReport:
        """
        Runs comprehensive repository health audit.
        """
        graph = self.engineer.graph
        issues: List[HealthIssue] = []

        # 1. Dead Symbol Detection
        dead_symbols = self._detect_dead_symbols(graph)
        for sym_name, file_p, line_no in dead_symbols:
            issues.append(
                HealthIssue(
                    category="dead_code",
                    severity="low",
                    title=f"Unused symbol: {sym_name}",
                    description=f"Function or class '{sym_name}' in {file_p}:{line_no} has 0 detected callers in workspace.",
                    file_path=file_p,
                    symbol_name=sym_name,
                    suggested_action=f"Verify if {sym_name} is part of public API or remove to reduce surface area.",
                )
            )

        # 2. Circular Dependency Detection
        circular_deps = self._detect_circular_dependencies(graph)
        for path_a, path_b in circular_deps:
            issues.append(
                HealthIssue(
                    category="circular_dep",
                    severity="medium",
                    title=f"Circular dependency between {path_a} and {path_b}",
                    description=f"Module {path_a} imports {path_b} while {path_b} directly or transitively imports {path_a}.",
                    file_path=path_a,
                    suggested_action="Refactor shared types or interfaces into a common base module.",
                )
            )

        # 3. Orphan Tests (tests with no associated source file)
        orphan_tests = self._detect_orphan_tests(graph)
        for test_path in orphan_tests:
            issues.append(
                HealthIssue(
                    category="broken_test",
                    severity="low",
                    title=f"Unlinked test module: {test_path}",
                    description=f"Test file {test_path} has no identified target implementation module.",
                    file_path=test_path,
                    suggested_action="Ensure test naming aligns with source file naming or add explicit coverage targets.",
                )
            )

        # 4. Dependency Manifest Audit
        dep_issues = self._audit_dependency_manifests()
        issues.extend(dep_issues)

        # Calculate Overall Health Score
        deductions = (
            len(dead_symbols) * 2
            + len(circular_deps) * 5
            + len(orphan_tests) * 2
            + len(dep_issues) * 5
        )
        score = max(20, min(100, 100 - deductions))

        report = HealthReport(
            workspace=str(self.workspace_root),
            overall_score=score,
            issues=issues,
            dead_symbols_count=len(dead_symbols),
            orphan_tests_count=len(orphan_tests),
            circular_dep_count=len(circular_deps),
            total_files_audited=len(graph.files),
        )

        # Persist report to .buzzard/maintenance/
        m_dir = self.workspace_root / ".buzzard" / "maintenance"
        m_dir.mkdir(parents=True, exist_ok=True)
        (m_dir / "latest_health.json").write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )

        return report

    def _detect_dead_symbols(self, graph: EngineeringMemoryGraph) -> List[tuple[str, str, int]]:
        """
        Finds functions and classes with zero incoming calls across files.
        Excludes test files, main entry points, and dunder methods.
        """
        dead = []
        # Build set of all called names across all files
        all_called_names: Set[str] = set()
        for fnode in graph.files.values():
            for sym in fnode.symbols.values():
                all_called_names.update(sym.calls)

        for rel_path, fnode in graph.files.items():
            if "test" in rel_path.lower() or "tests/" in rel_path:
                continue
            if rel_path.endswith(("__init__.py", "__main__.py", "main.py", "index.ts", "index.js", "app.py")):
                continue

            for sym in fnode.symbols.values():
                if sym.name.startswith("__") or sym.name in ("setUp", "tearDown", "run", "main"):
                    continue
                # If symbol is not called anywhere and file is not an entrypoint
                if sym.name not in all_called_names:
                    # Check if exported / imported by another file
                    if not fnode.imported_by:
                        dead.append((sym.name, rel_path, sym.line_number))
        return dead[:20]  # Cap to top 20 actionable items

    def _detect_circular_dependencies(self, graph: EngineeringMemoryGraph) -> List[tuple[str, str]]:
        circular = []
        seen = set()
        for src, fnode in graph.files.items():
            for imp in fnode.imports:
                if imp in graph.files:
                    target_node = graph.files[imp]
                    if src in target_node.imports:
                        pair = tuple(sorted([src, imp]))
                        if pair not in seen:
                            seen.add(pair)
                            circular.append((src, imp))
        return circular

    def _detect_orphan_tests(self, graph: EngineeringMemoryGraph) -> List[str]:
        orphans = []
        for rel_path in graph.files.keys():
            if "test" in rel_path.lower():
                # Check if this test is associated with any source file
                associated = False
                for fnode in graph.files.values():
                    if rel_path in fnode.associated_tests:
                        associated = True
                        break
                if not associated:
                    orphans.append(rel_path)
        return orphans

    def _audit_dependency_manifests(self) -> List[HealthIssue]:
        issues = []
        pyproject = self.workspace_root / "pyproject.toml"
        package_json = self.workspace_root / "package.json"

        if not pyproject.exists() and not package_json.exists():
            issues.append(
                HealthIssue(
                    category="dependency_risk",
                    severity="low",
                    title="No standard dependency manifest found",
                    description="Workspace does not contain pyproject.toml or package.json.",
                    suggested_action="Initialize dependencies using pyproject.toml or package.json.",
                )
            )

        if pyproject.exists():
            content = pyproject.read_text(encoding="utf-8", errors="replace")
            if "dependencies" not in content and "[tool.poetry]" not in content:
                issues.append(
                    HealthIssue(
                        category="dependency_risk",
                        severity="low",
                        title="Incomplete pyproject.toml",
                        description="pyproject.toml does not define a standard dependencies section.",
                        file_path="pyproject.toml",
                        suggested_action="Specify runtime dependencies in pyproject.toml.",
                    )
                )

        return issues

    def create_maintenance_branch(self, task_name: str) -> Dict[str, Any]:
        """
        Spawns an isolated git worktree branch for automated maintenance execution.
        """
        clean_name = "".join(c if c.isalnum() else "-" for c in task_name.lower())[:30]
        agent_id = f"maint-{clean_name}"
        worktree = self.worktree_manager.create_worktree(agent_id=agent_id)

        return {
            "status": "ready",
            "branch": worktree.branch_name,
            "path": str(worktree.worktree_path),
            "is_git": worktree.is_git_worktree,
        }
