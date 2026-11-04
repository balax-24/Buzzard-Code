"""
Phase 10 — Decision Attribution, Autonomy Scoring, and Behavioral Classification.

Provides:
1. DecisionSource enum (MODEL, CONTROLLER, DETERMINISTIC, FALLBACK, USER)
2. DecisionRecord data model for tracking every executed action's provenance
3. AutonomyMode enum (RAW_MODEL, ASSISTED)
4. BehavioralProfile enum for empirical model categorization
5. AutonomyEvaluator for transparent scoring without post-hoc weight inflation
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set


class DecisionSource(str, Enum):
    """
    Identifies the primary provenance of an action decision.
    """
    MODEL = "MODEL"                     # Action chosen directly by LLM
    CONTROLLER = "CONTROLLER"           # Action injected or forced by controller logic
    DETERMINISTIC = "DETERMINISTIC"     # Programmatically derived without LLM (e.g. baseline fixture)
    FALLBACK = "FALLBACK"               # Recovery action after error or timeout
    USER = "USER"                       # Explicit user directive or override


class AutonomyMode(str, Enum):
    """
    Operating mode for the agent.
    """
    RAW_MODEL = "RAW_MODEL"             # LLM decides all actions without silent controller injection
    ASSISTED = "ASSISTED"               # Controller provides automated fallback, candidate prioritization & recovery


class CompletionMode(str, Enum):
    """
    Goal completion strategy.
    """
    TARGETED = "TARGETED"               # Concludes once primary objective verified & relevant paths checked
    EXHAUSTIVE = "EXHAUSTIVE"           # Continues exploring all authorized surface until budget/graph exhausted


class BehavioralProfile(str, Enum):
    """
    Empirical classification of model behavioral tendencies.
    """
    EXPLORER = "EXPLORER"               # High initial surface and endpoint discovery
    ENUMERATOR = "ENUMERATOR"           # Thorough parameter and port enumeration
    EXPLOITER = "EXPLOITER"             # Rapid transition to vulnerability hypothesis testing
    VERIFIER = "VERIFIER"               # Independently reproduces findings with separate proof
    COMPLETER = "COMPLETER"             # Recognizes completion state accurately
    LOOPING = "LOOPING"                 # Emits repetitive or identical tool calls without new information
    PREMATURE_STOP = "PREMATURE_STOP"   # Attempts to conclude before testing open vulnerabilities
    TOOL_ERROR_PRONE = "TOOL_ERROR_PRONE" # Emits invalid tool names or malformed arguments
    PLAN_FOLLOWER = "PLAN_FOLLOWER"     # Sticks systematically to established multi-step plans
    ADAPTIVE = "ADAPTIVE"               # Pivots immediately when an action yields 0 information gain


@dataclass
class DecisionRecord:
    """
    First-class auditable record of an assessment action decision.
    """
    decision_id: str = field(default_factory=lambda: f"DEC-{uuid.uuid4().hex[:8].upper()}")
    iteration: int = 1
    source: DecisionSource = DecisionSource.MODEL
    selected_tool: str = ""
    target: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    hypothesis_id: Optional[str] = None
    candidate_id: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    capability_context: List[str] = field(default_factory=list)
    confidence: float = 1.0
    override_reason: str = ""
    timestamp: float = field(default_factory=time.time)
    is_failure: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "iteration": self.iteration,
            "source": self.source.value if hasattr(self.source, "value") else str(self.source),
            "selected_tool": self.selected_tool,
            "target": self.target,
            "arguments": self.arguments,
            "hypothesis_id": self.hypothesis_id,
            "candidate_id": self.candidate_id,
            "evidence_ids": list(self.evidence_ids),
            "capability_context": list(self.capability_context),
            "confidence": self.confidence,
            "override_reason": self.override_reason,
            "timestamp": self.timestamp,
            "is_failure": self.is_failure,
        }


@dataclass
class AutonomyScoreReport:
    """
    Comprehensive quantitative score measuring raw vs assisted autonomy.
    """
    mode: AutonomyMode
    total_decisions: int
    model_decisions: int
    controller_decisions: int
    deterministic_decisions: int
    fallback_decisions: int

    # Dimension Scores (0.0 to 100.0)
    decision_independence_pct: float
    useful_action_ratio_pct: float
    information_gain_average: float
    hypothesis_conversion_pct: float
    recovery_adaptability_pct: float
    verification_independence_pct: float
    overall_autonomy_score: float

    behavioral_profiles: List[BehavioralProfile] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "total_decisions": self.total_decisions,
            "model_decisions": self.model_decisions,
            "controller_decisions": self.controller_decisions,
            "deterministic_decisions": self.deterministic_decisions,
            "fallback_decisions": self.fallback_decisions,
            "decision_independence_pct": round(self.decision_independence_pct, 2),
            "useful_action_ratio_pct": round(self.useful_action_ratio_pct, 2),
            "information_gain_average": round(self.information_gain_average, 3),
            "hypothesis_conversion_pct": round(self.hypothesis_conversion_pct, 2),
            "recovery_adaptability_pct": round(self.recovery_adaptability_pct, 2),
            "verification_independence_pct": round(self.verification_independence_pct, 2),
            "overall_autonomy_score": round(self.overall_autonomy_score, 2),
            "behavioral_profiles": [p.value for p in self.behavioral_profiles],
        }


class AutonomyEvaluator:
    """
    Computes transparent, reproducible autonomy scores from execution traces.
    """

    @staticmethod
    def evaluate(
        decisions: List[DecisionRecord],
        information_gains: List[float],
        hypotheses_proposed: int,
        hypotheses_verified: int,
        verification_passed: bool,
        mode: AutonomyMode = AutonomyMode.RAW_MODEL
    ) -> AutonomyScoreReport:
        total = len(decisions)
        if total == 0:
            return AutonomyScoreReport(
                mode=mode,
                total_decisions=0,
                model_decisions=0,
                controller_decisions=0,
                deterministic_decisions=0,
                fallback_decisions=0,
                decision_independence_pct=0.0,
                useful_action_ratio_pct=0.0,
                information_gain_average=0.0,
                hypothesis_conversion_pct=0.0,
                recovery_adaptability_pct=0.0,
                verification_independence_pct=0.0,
                overall_autonomy_score=0.0,
                behavioral_profiles=[BehavioralProfile.PREMATURE_STOP]
            )

        model_cnt = sum(1 for d in decisions if d.source == DecisionSource.MODEL)
        ctrl_cnt = sum(1 for d in decisions if d.source == DecisionSource.CONTROLLER)
        det_cnt = sum(1 for d in decisions if d.source == DecisionSource.DETERMINISTIC)
        fb_cnt = sum(1 for d in decisions if d.source == DecisionSource.FALLBACK)

        # 1. Decision Independence (% of decisions made directly by model)
        independence = (model_cnt / total) * 100.0

        # 2. Useful action ratio (% of actions with positive information gain)
        useful_cnt = sum(1 for g in information_gains if g > 0.0)
        useful_ratio = (useful_cnt / max(len(information_gains), 1)) * 100.0

        # 3. Information gain average
        avg_gain = sum(information_gains) / max(len(information_gains), 1)

        # 4. Hypothesis conversion
        hyp_conv = (hypotheses_verified / max(hypotheses_proposed, 1)) * 100.0

        # 5. Recovery adaptability (% of non-fallback recovery when encountering errors)
        non_fb_ratio = ((total - fb_cnt) / total) * 100.0

        # 6. Verification independence (100 if verified via model decision, 50 if assisted, 0 if failed)
        ver_score = 100.0 if (verification_passed and model_cnt > 0) else (50.0 if verification_passed else 0.0)

        # Overall transparent weighted score
        # Independence: 30%, Useful actions: 20%, Info Gain: 15%, Hypotheses: 15%, Verification: 20%
        overall = (
            (independence * 0.30) +
            (useful_ratio * 0.20) +
            (min(avg_gain * 10.0, 100.0) * 0.15) +
            (hyp_conv * 0.15) +
            (ver_score * 0.20)
        )

        # Classify behavioral profiles
        profiles: List[BehavioralProfile] = []
        if useful_ratio >= 60.0:
            profiles.append(BehavioralProfile.EXPLORER)
        if hypotheses_verified > 0:
            profiles.append(BehavioralProfile.EXPLOITER)
        if verification_passed:
            profiles.append(BehavioralProfile.VERIFIER)
        if independence >= 75.0:
            profiles.append(BehavioralProfile.ADAPTIVE)
        if useful_ratio < 30.0 and total >= 4:
            profiles.append(BehavioralProfile.LOOPING)
        if fb_cnt >= 2:
            profiles.append(BehavioralProfile.TOOL_ERROR_PRONE)

        if not profiles:
            profiles.append(BehavioralProfile.ENUMERATOR)

        return AutonomyScoreReport(
            mode=mode,
            total_decisions=total,
            model_decisions=model_cnt,
            controller_decisions=ctrl_cnt,
            deterministic_decisions=det_cnt,
            fallback_decisions=fb_cnt,
            decision_independence_pct=independence,
            useful_action_ratio_pct=useful_ratio,
            information_gain_average=avg_gain,
            hypothesis_conversion_pct=hyp_conv,
            recovery_adaptability_pct=non_fb_ratio,
            verification_independence_pct=ver_score,
            overall_autonomy_score=overall,
            behavioral_profiles=profiles
        )
