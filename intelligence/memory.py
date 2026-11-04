"""
Phase 12 Layered Context Memory (L0-L8) & Memory Promotion Engine.

Memory Hierarchy:
- L0: Current Turn Decision Space
- L1: Recent Actions & Immediate Feedback
- L2: Active Investigation State (Target, Scope, Phase, Objective)
- L3: Attack Graph Frontier (Pending / Reachable Nodes)
- L4: Hypothesis Memory (Active vs Refuted)
- L5: Failure Memory (Learned Constraints & Blocked Paths)
- L6: Capability Memory (Verified Privileges & Session Credentials)
- L7: Verified Findings (Confirmed Vulnerabilities)
- L8: Historical Compressed Trajectory (Long-horizon Milestones)

Includes memory promotion/demotion and compact process rehydration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from agent.assessment_state import AssessmentState
from intelligence.attack_graph import AttackGraph, NodeStatus
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.branches import BranchManager
from persistence.models import BudgetSnapshot


@dataclass
class FailureMemoryRecord:
    target: str
    tool_or_strategy: str
    failure_classification: str
    attempt_count: int
    new_evidence_since_failure: bool = False
    notes: str = ""

    def to_summary(self) -> str:
        new_evi = "YES (Retest allowed)" if self.new_evidence_since_failure else "NONE (Avoid repetition)"
        return f"• [{self.failure_classification}] Target: `{self.target}` | Strategy: `{self.tool_or_strategy}` | Attempts: {self.attempt_count} | New Evidence: {new_evi}"


class LayeredMemoryManager:
    """
    Manages structured L0-L8 memory layers and generates compacted context representations.
    """

    def __init__(self):
        self.failure_records: Dict[str, FailureMemoryRecord] = {}
        self.milestones: List[str] = []

    def record_failure(
        self,
        target: str,
        tool_or_strategy: str,
        failure_class: str,
        notes: str = ""
    ) -> None:
        key = f"{target}:{tool_or_strategy}:{failure_class}"
        if key in self.failure_records:
            self.failure_records[key].attempt_count += 1
            self.failure_records[key].new_evidence_since_failure = False
        else:
            self.failure_records[key] = FailureMemoryRecord(
                target=target,
                tool_or_strategy=tool_or_strategy,
                failure_classification=failure_class,
                attempt_count=1,
                notes=notes
            )

    def mark_new_evidence_for_target(self, target: str) -> None:
        """Promotes refuted/failed actions by marking that new evidence has arrived."""
        for k, rec in self.failure_records.items():
            if target in k:
                rec.new_evidence_since_failure = True

    def build_rehydration_context(
        self,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        branch_manager: Optional[BranchManager] = None,
        budget: Optional[BudgetSnapshot] = None,
        resumed_checkpoint_id: Optional[str] = None
    ) -> str:
        """
        Builds a compact, high-density rehydration block for a resumed investigation.
        """
        parts: List[str] = []

        # Header
        if resumed_checkpoint_id:
            parts.append(f"=== INVESTIGATION RESUMED FROM CHECKPOINT [{resumed_checkpoint_id}] ===")
        else:
            parts.append("=== ACTIVE INVESTIGATION STATE (LAYERED MEMORY) ===")

        # L2: Target & Scope
        target = getattr(getattr(state, "context", None), "target", "127.0.0.1")
        scope = list(getattr(getattr(state, "context", None), "scope", [target]))
        obj = getattr(getattr(state, "context", None), "objective", "Assess security posture")
        phase = getattr(state, "current_phase", "INITIALIZING")
        phase_str = phase.value if hasattr(phase, "value") else str(phase)
        obj_status = getattr(state, "objective_status", "OBJECTIVE_UNREACHED")
        obj_status_str = obj_status.value if hasattr(obj_status, "value") else str(obj_status)

        parts.append(f"Target: {target} | Scope: {', '.join(scope)}")
        parts.append(f"Objective: {obj} | Status: {obj_status_str} | Phase: {phase_str}")

        # Budget
        if budget:
            parts.append(f"Remaining Budget: {budget.tool_calls_used}/{budget.max_tool_calls} tool calls ({budget.iterations_used}/{budget.max_iterations} turns)")

        # L6: Capability Memory
        caps = []
        for c_id, c in getattr(state, "capabilities", {}).items():
            caps.append(f"• [{c.capability_type.value}] Scope: {c.target_scope} (Source: {', '.join(c.source_evidence_ids)})")
        parts.append("\n[L6 - VERIFIED CAPABILITIES]:\n" + ("\n".join(caps) if caps else "• None (Unauthenticated)"))

        # Active Sessions
        sessions = []
        if hasattr(state, "get_session_store"):
            store = state.get_session_store()
            for s_id, s in getattr(store, "sessions", {}).items():
                auth_st = getattr(s, "authentication_state", None)
                is_expired = auth_st == "EXPIRED" or getattr(auth_st, "value", None) == "EXPIRED" or getattr(s, "is_expired", False) is True
                is_auth = s.is_authenticated() if callable(getattr(s, "is_authenticated", None)) else bool(getattr(s, "is_authenticated", False))
                if is_expired:
                    sessions.append(f"• [EXPIRED] {s.target_origin} (Reauthentication required)")
                elif is_auth:
                    sessions.append(f"• [{s.role}] {s.target_origin} (Cookies: {len(s.cookies)}, Token: {'YES' if s.bearer_tokens else 'NO'})")
        parts.append("\n[ACTIVE SESSIONS]:\n" + ("\n".join(sessions) if sessions else "• None"))

        # L7: Verified Findings
        findings = getattr(state, "findings", [])
        if findings:
            f_strs = [f"• {f.get('title', str(f))} [{f.get('severity', 'MED')}]" if isinstance(f, dict) else f"• {getattr(f, 'title', str(f))} [{getattr(f, 'severity', 'MED')}]" for f in findings]
            parts.append("\n[L7 - VERIFIED FINDINGS]:\n" + "\n".join(f_strs))
        else:
            parts.append("\n[L7 - VERIFIED FINDINGS]: 0 confirmed")

        # L5: Failure Memory
        if self.failure_records:
            fail_strs = [rec.to_summary() for rec in list(self.failure_records.values())[:4]]
            parts.append("\n[L5 - FAILURE MEMORY / LEARNED CONSTRAINTS]:\n" + "\n".join(fail_strs))

        # Investigation Branches
        if branch_manager and branch_manager.branches:
            b_strs = [b.to_prompt_summary() for b in branch_manager.branches.values()]
            parts.append("\n[ACTIVE INVESTIGATION BRANCHES]:\n" + "\n".join(b_strs))

        # L3: Attack Graph Frontier
        if graph and hasattr(graph, "nodes"):
            unexplored = [n.label for n in graph.nodes.values() if getattr(n, "status", None) == NodeStatus.PENDING and n.label != target]
            if unexplored:
                parts.append(f"\n[L3 - ATTACK GRAPH UNEXPLORED FRONTIER]:\nPending Nodes ({len(unexplored)}): {', '.join(unexplored[:6])}")

        # L1: Recent Actions
        decisions = getattr(state, "decision_records", [])
        if decisions:
            last_d = decisions[-1]
            parts.append(f"\n[L1 - LAST ACTION]: `{last_d.selected_tool}` on `{last_d.target}` (Source: {last_d.source.value})")

        return "\n".join(parts)
