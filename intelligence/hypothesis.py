"""
Hypothesis Engine and Security Claim Progression.

Maintains security hypotheses through a formal lifecycle:
HYPOTHESIS -> TESTING -> VERIFIED / REJECTED
See plan sections 32, 33 and Phase D.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from events.bus import EventBus
from events.types import EventType, EventSeverity


class HypothesisStatus(str, Enum):
    HYPOTHESIS = "hypothesis"  # Initial unverified observation or model deduction
    TESTING = "testing"        # Under active automated or manual verification
    VERIFIED = "verified"      # Definitively confirmed with reproducible evidence
    REJECTED = "rejected"      # Proved to be a false positive or mitigated control


@dataclass
class SecurityHypothesis:
    """A testable claim regarding a possible security flaw."""
    id: str
    target_asset: str
    vulnerability_type: str
    description: str
    status: HypothesisStatus = HypothesisStatus.HYPOTHESIS
    confidence_score: float = 0.5  # 0.0 to 1.0
    evidence_ids: List[str] = field(default_factory=list)
    verification_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class HypothesisEngine:
    """
    Manages hypotheses and dispatches lifecycle update events.
    """
    def __init__(self, event_bus: Optional[EventBus] = None):
        self.hypotheses: Dict[str, SecurityHypothesis] = {}
        self.event_bus = event_bus
        self._counter = 1

    def create_hypothesis(
        self,
        target_asset: str,
        vulnerability_type: str,
        description: str,
        initial_confidence: float = 0.5,
        assessment_id: Optional[str] = None
    ) -> SecurityHypothesis:
        hypo_id = f"HYP-{self._counter:03d}"
        self._counter += 1

        hypo = SecurityHypothesis(
            id=hypo_id,
            target_asset=target_asset,
            vulnerability_type=vulnerability_type,
            description=description,
            confidence_score=initial_confidence
        )
        self.hypotheses[hypo_id] = hypo

        if self.event_bus:
            self.event_bus.emit(
                EventType.HYPOTHESIS_CREATED,
                hypo.to_dict(),
                assessment_id=assessment_id
            )
        return hypo

    def update_status(
        self,
        hypo_id: str,
        status: HypothesisStatus,
        evidence_id: Optional[str] = None,
        notes: str = "",
        assessment_id: Optional[str] = None
    ) -> Optional[SecurityHypothesis]:
        if hypo_id not in self.hypotheses:
            return None

        hypo = self.hypotheses[hypo_id]
        hypo.status = status
        if evidence_id and evidence_id not in hypo.evidence_ids:
            hypo.evidence_ids.append(evidence_id)
        if notes:
            hypo.verification_notes = notes

        if status == HypothesisStatus.VERIFIED:
            hypo.confidence_score = 1.0
        elif status == HypothesisStatus.REJECTED:
            hypo.confidence_score = 0.0

        if self.event_bus:
            self.event_bus.emit(
                EventType.HYPOTHESIS_UPDATED,
                hypo.to_dict(),
                assessment_id=assessment_id
            )
        return hypo

    def get_pending(self) -> List[SecurityHypothesis]:
        return [h for h in self.hypotheses.values() if h.status in (HypothesisStatus.HYPOTHESIS, HypothesisStatus.TESTING)]

    def get_verified(self) -> List[SecurityHypothesis]:
        return [h for h in self.hypotheses.values() if h.status == HypothesisStatus.VERIFIED]
