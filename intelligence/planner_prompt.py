"""
Phase 11 Dedicated Model-Facing Planner Prompt Architecture.

Constructs structured, information-dense, high-clarity prompt contracts for
Qwythos, Qwen-Cyber, and K3-Sec without unbounded token bloating.
"""

from __future__ import annotations

from typing import List, Optional, Any
from agent.assessment_state import AssessmentState, ObjectiveStatus
from intelligence.attack_graph import AttackGraph, NodeStatus
from intelligence.hypothesis_engine import HypothesisProposal
from intelligence.action_selection import ActionCandidate, ActionSelectionEngine
from intelligence.tool_reliability import CANONICAL_TOOL_REGISTRY


class PlannerPromptBuilder:
    """
    Builds the model-facing system and user prompts with complete context hierarchy.
    """

    @classmethod
    def build_system_prompt(cls, model_name: str = "qwythos:latest") -> str:
        # Canonical tools compact specification
        tools_specs = "\n\n".join(
            schema.to_compact_prompt()
            for schema in CANONICAL_TOOL_REGISTRY.values()
        )

        return (
            "You are Qwythos, an elite autonomous security assessment agent operating in authorized penetration testing.\n"
            "Your objective is to reason methodically over discovered attack surfaces, select the highest-value action, "
            "and execute tools to verify vulnerabilities and reach authorized objectives.\n\n"
            "### CANONICAL AVAILABLE TOOLS:\n"
            f"{tools_specs}\n\n"
            "### DECISION RULES:\n"
            "1. Ground decisions in verified evidence and attack graph state.\n"
            "2. Prioritize HIGH_GAIN candidates and explore newly acquired capabilities.\n"
            "3. Do NOT repeat ZERO_GAIN or identical failed actions without new evidence.\n"
            "4. Keep pre-action reasoning concise (under 3 sentences), then immediately output the JSON tool call block.\n"
            "5. Output your decision as a valid JSON block at the end of your response:\n\n"
            "```json\n"
            "{\n"
            '  "thought": "<concise step reasoning and candidate selection>",\n'
            '  "tool": "<canonical_tool_name>",\n'
            '  "arguments": {"<param>": "<value>"}\n'
            "}\n"
            "```"
        )

    @classmethod
    def build_user_prompt(
        cls,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        proposals: Optional[List[HypothesisProposal]] = None,
        candidates: Optional[List[ActionCandidate]] = None,
        last_information_gain: float = 0.0,
        last_action_note: str = "",
        validation_error: Optional[str] = None,
    ) -> str:
        parts: List[str] = []

        # 1. Target & Scope
        target = getattr(getattr(state, "context", None), "target", "127.0.0.1")
        scope = list(getattr(getattr(state, "context", None), "scope", [target]))
        parts.append(f"=== MISSION TARGET & SCOPE ===\nTarget: {target}\nAuthorized Scope: {', '.join(scope)}")

        # 2. Phase & Capabilities
        phase = getattr(state, "current_phase", "DISCOVERY")
        phase_str = phase.value if hasattr(phase, "value") else str(phase)
        caps = []
        for c_id, cap in getattr(state, "capabilities", {}).items():
            caps.append(f"• [{cap.capability_type.value}] Scope: {cap.target_scope} (Source: {', '.join(cap.source_evidence_ids)})")
        parts.append(f"\n=== OPERATIONAL STATE ===\nPhase: {phase_str}\nVerified Capabilities:\n" + ("\n".join(caps) if caps else "• None (Unauthenticated)"))

        # 3. Active Authenticated Sessions
        sessions = []
        if hasattr(state, "get_session_store"):
            store = state.get_session_store()
            for s_id, s in getattr(store, "sessions", {}).items():
                if getattr(s, "is_authenticated", False):
                    sessions.append(f"• [{s.role}] {s.target_origin} (Cookies: {len(s.cookies)}, Token: {'YES' if s.bearer_tokens else 'NO'})")
        parts.append("\n=== ACTIVE SESSIONS ===\n" + ("\n".join(sessions) if sessions else "• None (Unauthenticated)"))

        # 4. Verified Findings
        findings = getattr(state, "findings", [])
        if findings:
            f_strs = [f"• {f.get('title', str(f))} [{f.get('severity', 'MED')}]" if isinstance(f, dict) else f"• {getattr(f, 'title', str(f))} [{getattr(f, 'severity', 'MED')}]" for f in findings[:4]]
            parts.append("\n=== VERIFIED FINDINGS ===\n" + "\n".join(f_strs))
        else:
            parts.append("\n=== VERIFIED FINDINGS ===\n• 0 confirmed vulnerabilities")

        # 5. Information Gain & Failure Learning
        parts.append(f"\n=== INFORMATION GAIN & PIVOT ADVICE ===\nLast Action Gain: {last_information_gain:.2f}")
        if last_information_gain == 0.0 and last_action_note:
            parts.append(f"⚡ [PIVOT ADVICE]: {last_action_note}. Avoid repeating identical requests. Choose a different surface candidate.")

        # 6. Tool Validation Error Feedback (Self-Repair)
        if validation_error:
            parts.append(f"\n⚠️ [PREVIOUS TOOL CALL FAILED VALIDATION]:\n{validation_error}\nPlease correct the arguments according to canonical schema and retry.")

        # 7. Attack Graph Unexplored Frontier
        if graph and hasattr(graph, "nodes"):
            unexplored = [n.label for n in graph.nodes.values() if getattr(n, "status", None) == NodeStatus.PENDING and n.label != target]
            if unexplored:
                parts.append(f"\n=== ATTACK GRAPH UNEXPLORED FRONTIER ===\nPending Nodes ({len(unexplored)}): {', '.join(unexplored[:6])}")

        # 8. Available Action Candidates (Comparison Space)
        if not candidates and proposals:
            candidates = ActionSelectionEngine.generate_candidates(state, graph, proposals)

        if candidates:
            parts.append("\n=== AVAILABLE ACTION CANDIDATES (Compare & Select) ===")
            for c in candidates:
                parts.append(c.to_prompt_summary())
                parts.append("")

        parts.append("\nSelect the optimal candidate or formulate your next action. Conclude with the JSON tool call block.")
        return "\n".join(parts)
