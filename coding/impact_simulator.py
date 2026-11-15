"""
Change Impact Simulator for Buzzard Code.

Predicts:
1. Files directly and indirectly affected by a proposed modification
2. Priority test suites that must run to prevent regressions
3. Risk classification (Low, Medium, High, Critical)
4. Recommended checkpoint / rollback strategy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence.memory_graph import EngineeringMemoryGraph


@dataclass
class ImpactPrediction:
    target_files: List[str]
    affected_files: List[str]
    priority_tests: List[str]
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    risk_reasons: List[str]
    suggest_checkpoint: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_files": self.target_files,
            "affected_files": self.affected_files,
            "priority_tests": self.priority_tests,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "suggest_checkpoint": self.suggest_checkpoint,
        }

    def format_summary(self) -> str:
        lines = [
            f"⚡ CHANGE IMPACT SIMULATION — Risk: [{self.risk_level.upper()}]",
            f"  • Direct Target Files: {len(self.target_files)}",
        ]
        for f in self.target_files[:3]:
            lines.append(f"    - {f}")

        lines.append(f"  • Downstream Dependent Files: {len(self.affected_files)}")
        for f in self.affected_files[:5]:
            lines.append(f"    - {f}")
        if len(self.affected_files) > 5:
            lines.append(f"    ... and {len(self.affected_files) - 5} more")

        lines.append(f"  • Priority Verification Tests: {len(self.priority_tests)}")
        for t in self.priority_tests[:4]:
            lines.append(f"    ✔ {t}")

        if self.risk_reasons:
            lines.append("  • Risk Factors:")
            for r in self.risk_reasons:
                lines.append(f"    ! {r}")

        return "\n".join(lines)


class ChangeImpactSimulator:
    """
    Simulates the blast radius and regression risk of code modifications.
    """

    def __init__(self, workspace_root: Path, graph: Optional[EngineeringMemoryGraph] = None):
        self.workspace_root = workspace_root.resolve()
        self.graph = graph or EngineeringMemoryGraph(self.workspace_root)
        if not self.graph.files:
            self.graph.index_workspace()

    def simulate(self, target_files: List[str]) -> ImpactPrediction:
        """
        Simulates impact across all proposed files.
        """
        all_affected: set[str] = set()
        all_tests: set[str] = set()
        risk_reasons: List[str] = []

        critical_markers = ("auth", "security", "token", "crypto", "sandbox", "permission", "policy")

        for f in target_files:
            info = self.graph.get_impact_radius(f)
            if info["found"]:
                all_affected.update(info["imported_by"])
                all_tests.update(info["associated_tests"])

            # Check for critical keywords
            lower_name = f.lower()
            if any(marker in lower_name for marker in critical_markers):
                risk_reasons.append(f"File '{f}' touches sensitive security/auth boundary.")

        # Remove direct target files from affected list
        norm_targets = {t.replace("\\", "/") for t in target_files}
        affected_list = sorted([a for a in all_affected if a not in norm_targets])
        tests_list = sorted(list(all_tests))

        # Calculate Risk Level
        if len(norm_targets) > 5 or len(affected_list) > 10 or any("auth" in r or "security" in r for r in risk_reasons):
            risk_level = "critical" if any("security" in r for r in risk_reasons) else "high"
        elif len(affected_list) > 2 or len(norm_targets) > 1:
            risk_level = "medium"
        else:
            risk_level = "low"

        if not tests_list:
            risk_reasons.append("No associated unit tests detected for targeted files.")

        return ImpactPrediction(
            target_files=sorted(list(norm_targets)),
            affected_files=affected_list,
            priority_tests=tests_list,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            suggest_checkpoint=risk_level in ("medium", "high", "critical"),
        )
