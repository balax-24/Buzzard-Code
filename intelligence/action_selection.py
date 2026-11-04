"""
Phase 15: Action Selection Engine & Multi-Attribute Utility Optimization.

Exposes comprehensive multi-attribute decision representations to the LLM and deterministic planner:
- candidate_id, target, tool, purpose, hypothesis
- evidence_ids, required_capabilities, available_capabilities
- expected_information_gain, estimated_cost, expected_efficiency, novelty_score
- failure memory blocking status & unblocking conditions
- frontier relevance (UNEXPLORED / REACHABLE / HYPOTHESIZED / EXHAUSTED)
- machine-readable why_this_action justification string
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from agent.assessment_state import AssessmentState, CapabilityType
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import HypothesisProposal
from intelligence.action_identity import ActionIdentity
from intelligence.action_history import ActionHistoryStore
from intelligence.failure_memory import FailureAwareMemory
from intelligence.gain_predictor import GainPredictor
from intelligence.action_cost import ActionCostEngine
from intelligence.frontier import FrontierEngine, FrontierStage


class GainRecommendation(str, Enum):
    HIGH_GAIN = "HIGH_GAIN"
    MEDIUM_GAIN = "MEDIUM_GAIN"
    LOW_GAIN = "LOW_GAIN"
    ZERO_GAIN = "ZERO_GAIN"


class RiskClass(str, Enum):
    SAFE = "SAFE"
    MODERATE = "MODERATE"
    AGGRESSIVE = "AGGRESSIVE"


@dataclass
class ActionCandidate:
    candidate_id: str
    target: str
    tool: str
    purpose: str
    hypothesis_id: str
    evidence_ids: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    available_capabilities: List[str] = field(default_factory=list)
    expected_information_gain: float = 1.0
    novelty_score: float = 1.0
    frontier_stage: str = "UNEXPLORED"
    estimated_cost: str = "LOW"
    estimated_cost_value: float = 1.0
    expected_efficiency: float = 1.0
    risk_class: RiskClass = RiskClass.SAFE
    dependencies: List[str] = field(default_factory=list)
    previous_attempts: int = 0
    previous_failures: int = 0
    verification_value: str = "NONE"
    arguments: Dict[str, Any] = field(default_factory=dict)
    gain_recommendation: GainRecommendation = GainRecommendation.HIGH_GAIN
    is_blocked_by_failure: bool = False
    block_reason: str = ""
    why_this_action: str = ""
    utility_score: float = 0.0

    def to_prompt_summary(self) -> str:
        """Formats the candidate for model comparison in the prompt."""
        gain_badge = f"[{self.gain_recommendation.value}] (Exp Gain: {self.expected_information_gain:.2f}, Novelty: {self.novelty_score:.2f})"
        caps_str = ", ".join(self.required_capabilities) or "NONE"
        prev_str = f"Attempts: {self.previous_attempts}, Failures: {self.previous_failures}"
        blocked_str = f" | BLOCKED: {self.block_reason}" if self.is_blocked_by_failure else ""
        
        return (
            f"Candidate [{self.candidate_id}] ➔ Tool: `{self.tool}` | Target: `{self.target}`\n"
            f"    Purpose: {self.purpose}\n"
            f"    Hypothesis: {self.hypothesis_id} | Gain Rating: {gain_badge}\n"
            f"    Prerequisites: {caps_str} | Cost: {self.estimated_cost} (Eff: {self.expected_efficiency:.2f}) | Risk: {self.risk_class.value}\n"
            f"    History: {prev_str} | Frontier: {self.frontier_stage}{blocked_str}\n"
            f"    Justification: {self.why_this_action}"
        )


class ActionSelectionEngine:
    """
    Constructs, scores, and ranks ActionCandidates from state, attack graph, hypotheses, and memory.
    """

    @classmethod
    def generate_candidates(
        cls,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        proposals: Optional[List[HypothesisProposal]] = None,
        history: Optional[ActionHistoryStore] = None,
        failure_memory: Optional[FailureAwareMemory] = None,
        max_candidates: int = 10,
    ) -> List[ActionCandidate]:
        candidates: List[ActionCandidate] = []
        avail_caps = set(state.capabilities.keys()) if hasattr(state, "capabilities") else set()

        if proposals is None:
            from intelligence.hypothesis_engine import HypothesisEngine
            engine = HypothesisEngine()
            proposals = engine.propose_next_actions(state, graph=graph)

        if proposals:
            # Build set of all available capabilities in state (ids, types, and values)
            avail_cap_objects = list(getattr(state, "capabilities", {}).values()) if hasattr(state, "capabilities") else []
            avail_cap_ids = {getattr(c, "capability_id", "") for c in avail_cap_objects if getattr(c, "capability_id", "")}
            avail_cap_types = {getattr(c, "capability_type", None) for c in avail_cap_objects}
            avail_cap_type_strs = {ct.value if hasattr(ct, "value") else str(ct) for ct in avail_cap_types if ct}
            all_avail = avail_caps | avail_cap_ids | avail_cap_type_strs

            seen_canonical_keys: Set[str] = set()
            for idx, prop in enumerate(proposals[:max_candidates], 1):
                key_obj = ActionIdentity.generate_canonical_key(prop.tool_name, prop.tool_args, prop.target)
                canonical_key = key_obj.canonical_key

                # Deduplicate identical actions within candidate generation
                if canonical_key in seen_canonical_keys:
                    continue
                seen_canonical_keys.add(canonical_key)

                # 1. Required capabilities & Precondition check
                req_caps: List[str] = []
                if getattr(prop, "capability_context", None):
                    req_caps.append(str(prop.capability_context))
                if getattr(prop, "required_capabilities", None):
                    for rc in prop.required_capabilities:
                        if rc and str(rc) not in req_caps:
                            req_caps.append(str(rc))

                is_blocked = False
                block_reason = ""

                # Check if any required capability is missing
                for rc in req_caps:
                    if rc not in all_avail:
                        is_blocked = True
                        block_reason = f"Precondition unfulfilled: missing capability '{rc}'"
                        break

                # Failure Memory check
                if not is_blocked and failure_memory:
                    is_blocked, block_reason = failure_memory.is_action_blocked(canonical_key, avail_caps)

                # 2. History check
                state_attempts = sum(
                    1 for d in getattr(state, "decision_records", [])
                    if (getattr(d, "selected_tool", "") == prop.tool_name or getattr(d, "tool_name", "") == prop.tool_name) and (getattr(d, "target", "") == prop.target or prop.target in str(getattr(d, "target", "")))
                )
                prev_attempts = max(history.get_repetition_count(canonical_key) if history else 0, state_attempts)
                decision_failures = sum(
                    1 for d in getattr(state, "decision_records", [])
                    if (getattr(d, "selected_tool", "") == prop.tool_name or getattr(d, "tool_name", "") == prop.tool_name) and (getattr(d, "target", "") == prop.target or prop.target in str(getattr(d, "target", ""))) and getattr(d, "is_failure", False)
                )
                state_failures = sum(
                    1 for fa in getattr(state, "failed_actions", [])
                    if (fa.get("tool") == prop.tool_name or fa.get("tool_name") == prop.tool_name) and (fa.get("target") == prop.target or prop.target in str(fa.get("target", "")))
                )
                prev_failures = max(decision_failures, state_failures)

                # 3. Novelty & Expected Gain calculation
                is_verif = "verify" in prop.verification_plan.lower() or "flag" in prop.target.lower()
                pred_result = GainPredictor.predict_expected_gain(
                    tool_name=prop.tool_name,
                    parameters=prop.tool_args,
                    target=prop.target,
                    graph=graph,
                    history=history,
                    hypothesis_confidence=prop.confidence.value if hasattr(prop.confidence, "value") else str(prop.confidence),
                    is_verification=is_verif,
                    current_capabilities=avail_caps,
                    prior_attempts=prev_attempts,
                )

                # 4. Cost estimation
                cost_bd = ActionCostEngine.estimate_cost(
                    tool_name=prop.tool_name,
                    parameters=prop.tool_args,
                    expected_gain=pred_result.expected_gain,
                )

                # 5. Gain recommendation badge
                if is_blocked or prev_attempts >= 2:
                    gain_rec = GainRecommendation.ZERO_GAIN
                elif prev_attempts == 1:
                    gain_rec = GainRecommendation.MEDIUM_GAIN
                elif pred_result.expected_gain >= 2.0 or getattr(prop.confidence, "value", "") in ("HIGH", "MEDIUM"):
                    gain_rec = GainRecommendation.HIGH_GAIN
                elif pred_result.expected_gain >= 1.0:
                    gain_rec = GainRecommendation.MEDIUM_GAIN
                elif pred_result.expected_gain >= 0.2:
                    gain_rec = GainRecommendation.LOW_GAIN
                else:
                    gain_rec = GainRecommendation.ZERO_GAIN

                # 6. Frontier stage
                frontier_stage = "UNEXPLORED"
                if graph:
                    for node in graph.nodes.values():
                        if node.label == prop.target or (key_obj.endpoint and key_obj.endpoint in node.label):
                            frontier_stage = FrontierEngine.classify_node_stage(node, graph, avail_caps).value
                            break

                if frontier_stage == "EXHAUSTED":
                    is_blocked = True
                    block_reason = f"Frontier stage for target '{prop.target}' is EXHAUSTED"

                # 7. Machine-readable justification (WHY THIS ACTION)
                why = (
                    f"Investigate {prop.hypothesis_id} on {prop.target} (exp_gain={pred_result.expected_gain:.2f}, "
                    f"novelty={pred_result.novelty_score:.2f}, eff={cost_bd.expected_efficiency:.2f}, stage={frontier_stage})"
                )

                # 8. Multi-attribute Utility Score
                # Utility = (0.35 * efficiency) + (0.30 * novelty) + (0.20 * frontier_relevance) + (0.15 * hyp_confidence)
                utility = (
                    (0.35 * cost_bd.expected_efficiency) +
                    (0.30 * pred_result.novelty_score) +
                    (0.20 * pred_result.frontier_relevance) +
                    (0.15 * pred_result.hypothesis_confidence_score)
                )
                if is_verif:
                    utility += 5.0  # Verification potential bonus
                if is_blocked:
                    utility -= 100.0  # Massive penalty for blocked actions / unmet preconditions
                elif prev_attempts >= 2:
                    utility -= 10.0 * prev_attempts  # Severe penalty for repeated probes
                elif prev_attempts == 1:
                    utility -= 2.0
                if prev_failures > 0:
                    utility -= 5.0 * prev_failures  # Previous failure penalty

                cand = ActionCandidate(
                    candidate_id=f"CAND-{idx}",
                    target=prop.target,
                    tool=prop.tool_name,
                    purpose=prop.rationale,
                    hypothesis_id=prop.hypothesis_id,
                    evidence_ids=prop.evidence_ids,
                    required_capabilities=req_caps,
                    available_capabilities=list(avail_caps),
                    expected_information_gain=pred_result.expected_gain,
                    novelty_score=pred_result.novelty_score,
                    frontier_stage=frontier_stage,
                    estimated_cost="LOW" if cost_bd.total_cost < 2.0 else ("MEDIUM" if cost_bd.total_cost < 4.0 else "HIGH"),
                    estimated_cost_value=cost_bd.total_cost,
                    expected_efficiency=cost_bd.expected_efficiency,
                    risk_class=RiskClass.MODERATE if "attack" in prop.tool_name or "sqlmap" in prop.tool_name else RiskClass.SAFE,
                    previous_attempts=prev_attempts,
                    previous_failures=prev_failures,
                    verification_value="FULL" if is_verif else "NONE",
                    arguments=prop.tool_args,
                    gain_recommendation=gain_rec,
                    is_blocked_by_failure=is_blocked,
                    block_reason=block_reason,
                    why_this_action=why,
                    utility_score=utility,
                )
                candidates.append(cand)

        # Sort candidates by descending utility score with deterministic tie-breaking
        candidates.sort(key=lambda c: (c.utility_score, c.novelty_score, c.expected_information_gain, c.candidate_id), reverse=True)
        return candidates

    @classmethod
    def select_best_candidate(
        cls,
        candidates: List[ActionCandidate],
    ) -> Optional[ActionCandidate]:
        """
        Deterministically selects the highest-utility unblocked candidate.
        """
        if not candidates:
            return None
        eligible = [c for c in candidates if not c.is_blocked_by_failure and c.frontier_stage != "EXHAUSTED"]
        if not eligible:
            # If all are blocked, return None so planner can pivot or explore new surface
            return None
        # Sort by utility, then by novelty, then gain, then candidate_id for deterministic tie-breaking
        eligible.sort(key=lambda c: (c.utility_score, c.novelty_score, c.expected_information_gain, c.candidate_id), reverse=True)
        return eligible[0]

    @classmethod
    def highest_priority_candidate(
        cls,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        history: Optional[ActionHistoryStore] = None,
        failure_memory: Optional[FailureAwareMemory] = None,
        max_candidates: int = 10,
    ) -> Optional[ActionCandidate]:
        """
        Deterministically selects the single highest-priority candidate for the current state.
        """
        candidates = cls.generate_candidates(
            state=state,
            graph=graph,
            history=history,
            failure_memory=failure_memory,
            max_candidates=max_candidates,
        )
        return cls.select_best_candidate(candidates)
