"""
Phase 10 — Long-Horizon Memory, Context Compaction, Plan Replanning, and Adaptive Strategy.

Enables deterministic context compaction over 10, 20, 40, 80 iterations without
token bloat or losing critical authorization, capability, session, or verification state.
"""

from __future__ import annotations

import time
import re
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

from intelligence.decision import AutonomyMode, DecisionSource, CompletionMode


class StrategyType(str, Enum):
    """
    High-level operational strategy for the agent.
    """
    RECON = "RECON"                                     # Initial port, host, service discovery
    AUTHENTICATION = "AUTHENTICATION"                   # Credential discovery & login testing
    APPLICATION_ENUMERATION = "APPLICATION_ENUMERATION" # DOM, link, form, script mapping
    API_ENUMERATION = "API_ENUMERATION"                 # Discovered backend route & parameter mapping
    HYPOTHESIS_TESTING = "HYPOTHESIS_TESTING"           # Active vulnerability validation
    PRIVILEGE_EXPANSION = "PRIVILEGE_EXPANSION"         # Horizontal/vertical capability elevation
    SESSION_REUSE = "SESSION_REUSE"                     # Multi-role authenticated cross-surface exploration
    VERIFICATION = "VERIFICATION"                       # Independent exploit proof reproduction
    EXHAUSTION = "EXHAUSTION"                           # Full graph coverage / complete surface audit


@dataclass
class PlanStep:
    step_number: int
    action_description: str
    tool_hint: Optional[str] = None
    target_hint: Optional[str] = None
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, INVALIDATED, FAILED


@dataclass
class MultiStepPlan:
    plan_id: str
    steps: List[PlanStep] = field(default_factory=list)
    strategy: StrategyType = StrategyType.RECON
    created_at: float = field(default_factory=time.time)
    invalidated_reason: Optional[str] = None

    def get_next_step(self) -> Optional[PlanStep]:
        for step in self.steps:
            if step.status == "PENDING":
                return step
        return None


class PlanReassessmentEngine:
    """
    Parses multi-step plans from model output and checks validity against newly ingested evidence.
    """

    @staticmethod
    def parse_plan(content: str) -> Optional[MultiStepPlan]:
        if "PLAN" not in content.upper() and not re.search(r"^\s*\d+\.\s+", content, re.MULTILINE):
            return None

        steps: List[PlanStep] = []
        step_matches = re.findall(r"^\s*(\d+)\.\s+([^\n]+)", content, re.MULTILINE)
        for num_str, desc in step_matches:
            tool_hint = None
            for t in ("nmap_scan", "web_fetch", "http.request", "browser.snapshot", "browser.click", "browser.submit", "sqli_scan"):
                if t in desc:
                    tool_hint = t
                    break
            steps.append(PlanStep(
                step_number=int(num_str),
                action_description=desc.strip(),
                tool_hint=tool_hint
            ))

        if not steps:
            return None

        return MultiStepPlan(
            plan_id=f"PLAN-{int(time.time())}",
            steps=steps
        )

    @staticmethod
    def reassess_plan(plan: MultiStepPlan, latest_action_success: bool, failure_reason: str = "") -> MultiStepPlan:
        next_step = plan.get_next_step()
        if not next_step:
            return plan

        if latest_action_success:
            next_step.status = "COMPLETED"
        else:
            next_step.status = "FAILED"
            # Invalidate subsequent steps if a foundational step failed (e.g. auth failed)
            if "login" in next_step.action_description.lower() or "auth" in next_step.action_description.lower():
                for s in plan.steps:
                    if s.status == "PENDING":
                        s.status = "INVALIDATED"
                plan.invalidated_reason = f"Step {next_step.step_number} failed ({failure_reason}). Dependent steps invalidated."

        return plan


class LongHorizonContextCompactor:
    """
    Generates deterministic, highly compressed context for long-horizon execution.
    """

    @staticmethod
    def build_compact_context(
        state: Any,
        graph: Optional[Any] = None,
        hypotheses: Optional[List[Any]] = None,
        last_information_gain: float = 0.0,
        last_action_note: str = "",
        mode: AutonomyMode = AutonomyMode.RAW_MODEL,
        completion_mode: CompletionMode = CompletionMode.TARGETED,
        active_plan: Optional[MultiStepPlan] = None,
    ) -> str:
        ctx_parts: List[str] = []

        # 1. Header & Operating Mode
        ctx_parts.append("=== ASSESSMENT STATE & APPLICATION SURFACE ===")
        ctx_parts.append(f"Operating Mode: {mode.value} | Completion Policy: {completion_mode.value}")

        # Target & Scope
        target = getattr(getattr(state, "context", None), "target", "127.0.0.1")
        allowed = list(getattr(getattr(state, "context", None), "scope", [target]))
        ctx_parts.append(f"Target: {target} | Authorized Scope: {', '.join(allowed)}")

        # 2. Phase & Capabilities
        phase = getattr(state, "current_phase", "DISCOVERY")
        phase_str = phase.value if hasattr(phase, "value") else str(phase)
        caps = list(getattr(state, "capabilities", {}).keys())
        ctx_parts.append(f"Phase: {phase_str} | Verified Capabilities: {caps or ['NONE']}")

        # 3. Active Authenticated Sessions
        sessions_summary = []
        if hasattr(state, "get_session_store"):
            store = state.get_session_store()
            for s_id, s in getattr(store, "sessions", {}).items():
                if getattr(s, "is_authenticated", False):
                    has_tok = bool(getattr(s, "bearer_tokens", None) or getattr(s, "bearer_token", None))
                    sessions_summary.append(f"[{s.role}] {s.target_origin} (Cookies: {len(s.cookies)}, Token: {'YES' if has_tok else 'NO'})")
        ctx_parts.append(f"Active Sessions: {', '.join(sessions_summary) if sessions_summary else 'None (Unauthenticated)'}")

        # 4. Verified Findings
        findings = getattr(state, "findings", []) or getattr(state, "verified_findings", [])
        if findings:
            f_strs = []
            for f in findings[:4]:
                if isinstance(f, dict):
                    f_strs.append(f"• {f.get('title', str(f))} [{f.get('severity', 'MED')}]")
                else:
                    f_strs.append(f"• {getattr(f, 'title', str(f))} [{getattr(f, 'severity', 'MED')}]")
            ctx_parts.append("Verified Findings:\n" + "\n".join(f_strs))
        else:
            ctx_parts.append("Verified Findings: 0 confirmed")

        # 5. Information Gain Signal & Pivot Recommendation
        ctx_parts.append(f"Last Action Info Gain: {last_information_gain:.2f}")
        if last_information_gain == 0.0 and last_action_note:
            ctx_parts.append(f"⚡ [PIVOT ADVICE]: Last action yielded 0 new intelligence ({last_action_note}). Do NOT repeat identical requests. Explore new endpoints, forms, or hypotheses.")

        # 6. Ranked Candidate Hypotheses (Competition)
        if hypotheses:
            ctx_parts.append("\n--- RANKED HYPOTHESIS CANDIDATES (Choose or Formulate Action) ---")
            for i, h in enumerate(hypotheses[:5], 1):
                h_id = getattr(h, "hypothesis_id", f"HYP-{i}")
                v_type = getattr(h, "vulnerability_type", "unknown")
                tgt = getattr(h, "target", target)
                tool = getattr(h, "tool_name", "web_fetch")
                conf = getattr(h, "confidence", "MEDIUM")
                conf_str = conf.value if hasattr(conf, "value") else str(conf)
                rat = getattr(h, "rationale", "")
                ctx_parts.append(f"[{i}] ID: {h_id} | Type: {v_type} | Target: {tgt} | Tool: {tool} | Conf: {conf_str}\n    Rationale: {rat}")
            ctx_parts.append("----------------------------------------------------------------")

        # 7. Unexplored Application Graph Work
        if graph and hasattr(graph, "nodes"):
            from intelligence.attack_graph import NodeStatus
            unexplored = [n.label for n in graph.nodes.values() if getattr(n, "status", None) == NodeStatus.PENDING and n.label != target]
            if unexplored:
                ctx_parts.append(f"Unexplored Surface Nodes ({len(unexplored)}): {', '.join(unexplored[:8])}")

        # 8. Active Plan Status
        if active_plan and active_plan.steps:
            next_step = active_plan.get_next_step()
            ctx_parts.append(f"\nActive Plan ({active_plan.plan_id}):")
            for s in active_plan.steps:
                mark = "✓" if s.status == "COMPLETED" else ("✗" if s.status in ("FAILED", "INVALIDATED") else "►" if s == next_step else " ")
                ctx_parts.append(f"  [{mark}] {s.step_number}. {s.action_description} ({s.status})")
            if active_plan.invalidated_reason:
                ctx_parts.append(f"  ⚠ Re-plan Needed: {active_plan.invalidated_reason}")

        # 9. Verification & Safety Requirement
        obj_status = getattr(state, "objective_status", None)
        status_str = obj_status.value if hasattr(obj_status, "value") else str(obj_status)
        if status_str == "OBJECTIVE_ACHIEVED_UNVERIFIED":
            ctx_parts.append("\n⚡ [CRITICAL]: Primary objective is achieved but UNVERIFIED. Independent verification proof is required before concluding.")

        ctx_parts.append("================================================")
        return "\n".join(ctx_parts)
