"""
Verification Pipeline and Reproducibility Engine.

Automates the verification of security hypotheses through reproducible test execution,
evidence collection, and judge validation.
See plan sections 38, 39, 40 and Phase E.
"""

import uuid
from typing import Dict, Any, List, Optional
from model.schemas import Finding, Evidence, EvidenceType, Severity, Confidence
from storage.db import StorageManager
from intelligence.hypothesis import SecurityHypothesis, HypothesisEngine, HypothesisStatus
from intelligence.judge import IndependentJudge, JudgeVerdict
from events.bus import EventBus
from events.types import EventType, EventSeverity


class VerificationPipeline:
    """
    Executes reproducible verification checks and records confirmed findings.
    """
    def __init__(
        self,
        storage_manager: Optional[StorageManager] = None,
        judge: Optional[IndependentJudge] = None,
        event_bus: Optional[EventBus] = None,
        state: Optional[Any] = None
    ):
        self.storage = storage_manager
        self.judge = judge or IndependentJudge(event_bus=event_bus)
        self.event_bus = event_bus
        self.state = state

    def verify_hypothesis(
        self,
        session_id: str,
        hypothesis: SecurityHypothesis,
        raw_evidence_data: Dict[str, Any],
        remediation_hint: str = "",
        state: Optional[Any] = None
    ) -> Optional[Finding]:
        """
        Runs candidate evidence through the IndependentJudge, stores evidence,
        and logs a validated Finding if confirmed. Canonical finding is recorded
        via AssessmentState when available.
        """
        verdict = self.judge.evaluate_finding(
            candidate_title=f"Vulnerability: {hypothesis.vulnerability_type}",
            affected_asset=hypothesis.target_asset,
            evidence_data=raw_evidence_data,
            vulnerability_type=hypothesis.vulnerability_type
        )

        active_state = state or self.state

        # 1. Store the raw evidence object
        ev_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        if active_state is not None and hasattr(active_state, "record_evidence"):
            active_state.record_evidence(
                evidence_id=ev_id,
                target=hypothesis.target_asset,
                description=f"Verification evidence for {hypothesis.vulnerability_type}",
                raw_data=raw_evidence_data,
            )

        evidence = Evidence(
            id=ev_id,
            type=EvidenceType.HTTP,
            target=hypothesis.target_asset,
            description=f"Verification evidence for {hypothesis.vulnerability_type}",
            data=raw_evidence_data,
            timestamp=str(int(__import__("time").time()))
        )
        if self.storage:
            self.storage.add_evidence(session_id, evidence)

        if self.event_bus:
            self.event_bus.emit(
                EventType.EVIDENCE_CREATED,
                {"evidence_id": ev_id, "target": hypothesis.target_asset},
                assessment_id=session_id
            )

        # 2. If confirmed, generate official Finding through canonical state SSOT
        if verdict.is_confirmed:
            finding_id = f"FIND-{uuid.uuid4().hex[:6].upper()}"
            sev_enum = verdict.severity if isinstance(verdict.severity, Severity) else Severity(verdict.severity)
            conf_enum = verdict.confidence if isinstance(verdict.confidence, Confidence) else Confidence(verdict.confidence)

            if active_state is not None and hasattr(active_state, "record_finding"):
                active_state.record_finding(
                    title=f"{hypothesis.vulnerability_type} on {hypothesis.target_asset}",
                    severity=str(sev_enum.value if hasattr(sev_enum, "value") else sev_enum),
                    description=hypothesis.description,
                    evidence_ids=[ev_id],
                    proof=f"Reproducible PoC: {verdict.reproducible_poc}",
                    finding_id=finding_id,
                )

            finding = Finding(
                id=finding_id,
                title=f"{hypothesis.vulnerability_type} on {hypothesis.target_asset}",
                severity=sev_enum,
                confidence=conf_enum,
                affected_asset=hypothesis.target_asset,
                description=hypothesis.description,
                evidence=[ev_id],
                impact=f"Confirmed security risk on {hypothesis.target_asset}: {verdict.reason}",
                verification=f"Reproducible PoC: {verdict.reproducible_poc}",
                remediation=remediation_hint or "Sanitize inputs and enforce defensive security controls.",
                status="active"
            )
            if self.storage:
                self.storage.add_finding(session_id, finding)
            hypothesis.status = HypothesisStatus.VERIFIED
            hypothesis.evidence_ids.append(ev_id)
            return finding
        else:
            hypothesis.status = HypothesisStatus.REJECTED
            return None
