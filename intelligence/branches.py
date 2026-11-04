"""
Phase 12 Multi-Path Investigation Branching Engine.

Allows concurrent or alternating investigation paths:
- Web Application surface
- API surface
- Network / Service surface
- Post-exploitation / Privilege Escalation surface

Tracks per-branch progress, hypotheses, capabilities, and budgets.
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional


class BranchStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXHAUSTED = "EXHAUSTED"
    COMPLETED = "COMPLETED"


class BranchPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class InvestigationBranch:
    branch_id: str
    name: str
    target: str
    status: BranchStatus = BranchStatus.ACTIVE
    priority: BranchPriority = BranchPriority.HIGH
    hypothesis_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    capability_ids: List[str] = field(default_factory=list)
    expected_gain_rating: str = "HIGH"
    tool_calls_allocated: int = 25
    tool_calls_used: int = 0
    total_gain: float = 0.0
    cost_incurred: float = 0.0
    turns_spent: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    @property
    def roi(self) -> float:
        if self.cost_incurred <= 0.0:
            return round(self.total_gain, 2)
        return round(self.total_gain / max(0.1, self.cost_incurred), 2)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "name": self.name,
            "target": self.target,
            "status": self.status.value,
            "priority": self.priority.value,
            "unresolved_hypotheses": len(self.hypothesis_ids),
            "expected_gain": self.expected_gain_rating,
            "budget": f"{self.tool_calls_used}/{self.tool_calls_allocated} tools",
            "total_gain": self.total_gain,
            "cost_incurred": self.cost_incurred,
        }

    def to_prompt_summary(self) -> str:
        return (
            f"• Branch [{self.name}] ({self.branch_id}) | Target: `{self.target}` | Priority: {self.priority.value}\n"
            f"    Status: {self.status.value} | Hypotheses: {len(self.hypothesis_ids)} | Expected Gain: {self.expected_gain_rating}\n"
            f"    Budget: {self.tool_calls_used}/{self.tool_calls_allocated} tool calls used | Gain: {self.total_gain:.2f}"
        )


class BranchManager:
    """
    Manages multi-path investigation branches and branch switching.
    """

    def __init__(self):
        self.branches: Dict[str, InvestigationBranch] = {}
        self.active_branch_id: Optional[str] = None

    def create_branch(
        self,
        name: str,
        target: str,
        priority: BranchPriority = BranchPriority.HIGH,
        tool_budget: int = 25,
        expected_gain: str = "HIGH",
        branch_id: Optional[str] = None,
    ) -> InvestigationBranch:
        b_id = branch_id or f"br-{name.lower().replace(' ', '_')}-{uuid.uuid4().hex[:6]}"
        branch = InvestigationBranch(
            branch_id=b_id,
            name=name,
            target=target,
            priority=priority,
            tool_calls_allocated=tool_budget,
            expected_gain_rating=expected_gain
        )
        self.branches[b_id] = branch
        if not self.active_branch_id:
            self.active_branch_id = b_id
        return branch

    def switch_branch(self, branch_id: str) -> Optional[InvestigationBranch]:
        if branch_id in self.branches:
            self.active_branch_id = branch_id
            return self.branches[branch_id]
        return None

    def get_active_branch(self) -> Optional[InvestigationBranch]:
        if self.active_branch_id and self.active_branch_id in self.branches:
            return self.branches[self.active_branch_id]
        return None

    def pause_branch(self, branch_id: str) -> Optional[InvestigationBranch]:
        if branch_id in self.branches:
            self.branches[branch_id].status = BranchStatus.PAUSED
            self.branches[branch_id].updated_at = time.time()
            return self.branches[branch_id]
        return None

    def resume_branch(self, branch_id: str) -> Optional[InvestigationBranch]:
        if branch_id in self.branches:
            self.branches[branch_id].status = BranchStatus.ACTIVE
            self.branches[branch_id].updated_at = time.time()
            self.active_branch_id = branch_id
            return self.branches[branch_id]
        return None

    def complete_branch(self, branch_id: str) -> Optional[InvestigationBranch]:
        if branch_id in self.branches:
            self.branches[branch_id].status = BranchStatus.COMPLETED
            self.branches[branch_id].updated_at = time.time()
            # If completing active branch, pick next active
            if self.active_branch_id == branch_id:
                active = [b.branch_id for b in self.branches.values() if b.status == BranchStatus.ACTIVE and b.branch_id != branch_id]
                self.active_branch_id = active[0] if active else None
            return self.branches[branch_id]
        return None

    def exhaust_branch(self, branch_id: str) -> Optional[InvestigationBranch]:
        if branch_id in self.branches:
            self.branches[branch_id].status = BranchStatus.EXHAUSTED
            self.branches[branch_id].updated_at = time.time()
            if self.active_branch_id == branch_id:
                active = [b.branch_id for b in self.branches.values() if b.status == BranchStatus.ACTIVE and b.branch_id != branch_id]
                self.active_branch_id = active[0] if active else None
            return self.branches[branch_id]
        return None

    def calculate_branch_priority_score(
        self,
        branch_or_id: Any,
        unexplored_surface_nodes: int = 0,
        active_hypotheses_count: int = 0,
        recent_gain: float = 1.0,
        failure_rate: float = 0.0
    ) -> float:
        """
        Calculates empirical priority score for branch arbitration:
        Score = (Expected Gain + Unexplored Surface + Active Hypotheses) * (1 - Failure Penalty)
        """
        if isinstance(branch_or_id, InvestigationBranch):
            branch = branch_or_id
        else:
            branch = self.branches.get(str(branch_or_id))
        if not branch or branch.status in (BranchStatus.COMPLETED, BranchStatus.EXHAUSTED):
            return 0.0

        # Base rating score
        gain_mult = 3.0 if branch.expected_gain_rating == "HIGH" else (2.0 if branch.expected_gain_rating == "MEDIUM" else 1.0)
        
        # Remaining budget factor
        budget_factor = max(0.1, (branch.tool_calls_allocated - branch.tool_calls_used) / max(1, branch.tool_calls_allocated))

        # Realized ROI factor
        roi = branch.total_gain / max(0.1, branch.cost_incurred) if branch.cost_incurred > 0 else 1.0

        # Surface & hypothesis factors
        surface_score = unexplored_surface_nodes * 1.5
        hypo_score = active_hypotheses_count * 2.0
        gain_score = (recent_gain * 2.0) + (branch.total_gain * 1.5)

        raw_score = (gain_mult + surface_score + hypo_score + gain_score + (roi * 2.0)) * budget_factor
        penalty = min(0.8, failure_rate * 0.5)
        
        return max(0.0, raw_score * (1.0 - penalty))

    def get_best_next_branch(
        self,
        branch_metrics: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Optional[InvestigationBranch]:
        """
        Returns the highest-scoring active branch based on current metrics and ROI.
        """
        active_branches = [b for b in self.branches.values() if b.status == BranchStatus.ACTIVE]
        if not active_branches:
            return None

        best_branch = None
        best_score = -1.0

        for b in active_branches:
            m = (branch_metrics or {}).get(b.branch_id, {})
            score = self.calculate_branch_priority_score(
                branch_or_id=b,
                unexplored_surface_nodes=m.get("unexplored_surface_nodes", 0),
                active_hypotheses_count=m.get("active_hypotheses_count", len(b.hypothesis_ids)),
                recent_gain=m.get("recent_gain", 1.0),
                failure_rate=m.get("failure_rate", 0.0)
            )
            if score > best_score:
                best_score = score
                best_branch = b

        return best_branch or active_branches[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "branches": {b_id: asdict(b) for b_id, b in self.branches.items()},
            "active_branch_id": self.active_branch_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BranchManager:
        bm = cls()
        bm.active_branch_id = data.get("active_branch_id")
        for b_id, b_dict in data.get("branches", {}).items():
            b = InvestigationBranch(
                branch_id=b_dict["branch_id"],
                name=b_dict["name"],
                target=b_dict["target"],
                status=BranchStatus(b_dict["status"]),
                priority=BranchPriority(b_dict["priority"]),
                hypothesis_ids=b_dict.get("hypothesis_ids", []),
                evidence_ids=b_dict.get("evidence_ids", []),
                capability_ids=b_dict.get("capability_ids", []),
                expected_gain_rating=b_dict.get("expected_gain_rating", "HIGH"),
                tool_calls_allocated=b_dict.get("tool_calls_allocated", 25),
                tool_calls_used=b_dict.get("tool_calls_used", 0),
                created_at=b_dict.get("created_at", time.time()),
                updated_at=b_dict.get("updated_at", time.time())
            )
            bm.branches[b_id] = b
        return bm

