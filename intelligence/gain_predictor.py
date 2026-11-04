"""
Phase 15: Expected Information Gain, Novelty Scoring & Calibration Predictor.

Calculates pre-execution expected information gain, novelty scores, and post-execution
prediction error (calibration) for security actions.
A candidate on an unseen endpoint/service with high hypothesis confidence receives high expected gain,
while repeated actions on explored assets decay sharply toward zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from intelligence.action_identity import ActionIdentity, SemanticActionKey
from intelligence.action_history import ActionHistoryStore
from intelligence.frontier import FrontierEngine, FrontierStage
from intelligence.attack_graph import AttackGraph, NodeKind


@dataclass
class GainPredictionResult:
    """Detailed score breakdown for a candidate action."""
    expected_gain: float
    novelty_score: float
    frontier_relevance: float
    hypothesis_confidence_score: float
    repetition_decay_factor: float
    calibration_adjustment: float
    rationale: str


class GainPredictor:
    """
    Computes expected information gain, novelty scores, and tracks calibration errors.
    """

    @classmethod
    def calculate_novelty_score(
        cls,
        tool_name: str,
        parameters: Dict[str, Any],
        target: str,
        graph: Optional[AttackGraph],
        history: Optional[ActionHistoryStore],
        current_capabilities: Optional[Set[str]] = None,
    ) -> float:
        """
        Computes a novelty score [0.0 - 1.0] for a candidate action.
        Factors:
          - Unseen endpoint / target (+0.4)
          - Unseen tool or parameter set on this target (+0.3)
          - Action in newly acquired capability context (+0.2)
          - Unexplored node in AttackGraph (+0.1)
        """
        key_obj = ActionIdentity.generate_canonical_key(tool_name, parameters, target)
        canonical_key = key_obj.canonical_key
        caps = current_capabilities or set()
        ctx_sig = ActionIdentity.create_context_signature(list(caps))

        if history is None:
            return 1.0

        times_seen = history.get_repetition_count(canonical_key)
        if times_seen == 0:
            novelty = 0.8
            # If never seen even this target
            has_seen_target = any(r.target == key_obj.target for r in history.records)
            if not has_seen_target:
                novelty += 0.2
            return min(1.0, novelty)

        # If seen before, check if this is a new capability context
        seen_in_this_ctx = history.has_action_been_attempted(canonical_key, capability_context=ctx_sig)
        if not seen_in_this_ctx and len(caps) > 0:
            # Action attempted in previous context, but now in NEW capability context!
            return 0.7

        # Repeated in same context: decay exponentially
        return max(0.01, 0.4 / (1.0 + (times_seen * 2.0)))

    @classmethod
    def predict_expected_gain(
        cls,
        tool_name: str,
        parameters: Dict[str, Any],
        target: str,
        graph: Optional[AttackGraph] = None,
        history: Optional[ActionHistoryStore] = None,
        hypothesis_confidence: str = "MEDIUM",
        is_verification: bool = False,
        current_capabilities: Optional[Set[str]] = None,
        prior_attempts: int = 0,
    ) -> GainPredictionResult:
        """
        Calculates expected information gain combining novelty, graph stage, and hypothesis confidence.
        """
        key_obj = ActionIdentity.generate_canonical_key(tool_name, parameters, target)
        canonical_key = key_obj.canonical_key
        caps = current_capabilities or set()

        novelty = cls.calculate_novelty_score(tool_name, parameters, target, graph, history, caps)

        # 1. Base Gain by Tool Category & Confidence
        if is_verification:
            base_gain = 8.0  # Verifying an objective has immense value
        elif tool_name in ("verify_finding", "verify_objective"):
            base_gain = 7.0
        elif tool_name in ("sqlmap", "sqli_probe", "exploit", "attack", "sqlmap_attack"):
            base_gain = 5.0 if hypothesis_confidence == "HIGH" else 3.0
        elif tool_name in ("browser_navigate", "browser_fill", "browser_click"):
            base_gain = 3.5
        elif tool_name in ("nmap", "port_scan", "service_scan"):
            base_gain = 2.5
        elif tool_name in ("http_request", "http_client", "curl"):
            base_gain = 2.0
        else:
            base_gain = 1.5

        # 2. Hypothesis Confidence Multiplier
        hyp_mult = 1.5 if hypothesis_confidence == "HIGH" else (1.0 if hypothesis_confidence == "MEDIUM" else 0.6)

        # 3. Frontier Relevance
        frontier_relevance = 1.0
        if graph:
            # Match target or endpoint in graph
            matched_node = None
            for node in graph.nodes.values():
                if node.label == target or (key_obj.endpoint and key_obj.endpoint in node.label):
                    matched_node = node
                    break
            if matched_node:
                stage = FrontierEngine.classify_node_stage(matched_node, graph, caps)
                if stage in (FrontierStage.REACHABLE, FrontierStage.UNEXPLORED):
                    frontier_relevance = 1.3
                elif stage == FrontierStage.EXHAUSTED:
                    frontier_relevance = 0.2

        # 4. Repetition Decay Factor
        rep_count = max(prior_attempts, history.get_repetition_count(canonical_key) if history else 0)
        if rep_count == 0:
            decay = 1.0
        else:
            # Check if context changed
            ctx_sig = ActionIdentity.create_context_signature(list(caps))
            if history and not history.has_action_been_attempted(canonical_key, capability_context=ctx_sig) and len(caps) > 0:
                decay = 0.8  # Refreshed due to new context!
            elif rep_count == 1:
                decay = 0.25
            else:
                decay = 0.01

        # 5. Calibration adjustment from historical prediction error
        cal_adj = 1.0
        if history:
            avg_err = history.get_average_prediction_error(window=10)
            if avg_err > 2.0:
                cal_adj = 0.8  # Dampen over-optimistic predictions

        expected_gain = base_gain * hyp_mult * frontier_relevance * novelty * decay * cal_adj

        rationale = f"Base={base_gain:.1f}, HypMult={hyp_mult:.2f}, Novelty={novelty:.2f}, Decay={decay:.2f}"

        return GainPredictionResult(
            expected_gain=max(0.01, expected_gain),
            novelty_score=novelty,
            frontier_relevance=frontier_relevance,
            hypothesis_confidence_score=hyp_mult,
            repetition_decay_factor=decay,
            calibration_adjustment=cal_adj,
            rationale=rationale,
        )
