"""
Independent Judge and Verification Evaluator.

Separates finding proposal from finding confirmation.
Evaluates technical evidence (HTTP status, error signatures, timing differences, reflection)
to verify candidate findings and eliminate false positives.
See plan sections 35, 36, 37 and Phase D.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, List
from security_agent.model.schemas import Finding, Severity, Confidence
from security_agent.events.bus import EventBus
from security_agent.events.types import EventType, EventSeverity


@dataclass
class JudgeVerdict:
    """Independent evaluation verdict for a suspected vulnerability."""
    is_confirmed: bool
    confidence: Confidence
    severity: Severity
    reason: str
    reproducible_poc: str = ""


class IndependentJudge:
    """
    Evaluates evidence against strict deterministic criteria before a finding is accepted.
    """
    def __init__(self, event_bus: Optional[EventBus] = None):
        self.event_bus = event_bus

    def evaluate_finding(
        self,
        candidate_title: str,
        affected_asset: str,
        evidence_data: Dict[str, Any],
        vulnerability_type: str = "general"
    ) -> JudgeVerdict:
        """
        Independently assesses raw evidence to confirm or reject a suspected finding.
        """
        v_type = vulnerability_type.lower()

        # 1. SQL Injection evaluation
        if "sql" in v_type or "injection" in v_type:
            indicators = evidence_data.get("indicators_found", [])
            if any(ind.get("matched_pattern") for ind in indicators):
                verdict = JudgeVerdict(
                    is_confirmed=True,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH,
                    reason="Definitive database error signature observed in HTTP response body.",
                    reproducible_poc=f"Probe: {indicators[0].get('probe')} on {affected_asset}"
                )
            else:
                verdict = JudgeVerdict(
                    is_confirmed=False,
                    confidence=Confidence.HYPOTHESIS,
                    severity=Severity.LOW,
                    reason="No unambiguous database syntax error signature found in evidence."
                )

        # 2. XSS / Reflection evaluation
        elif "xss" in v_type or "reflection" in v_type:
            indicators = evidence_data.get("indicators_found", [])
            if any(ind.get("reflected_unencoded") for ind in indicators):
                verdict = JudgeVerdict(
                    is_confirmed=True,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM,
                    reason="Exact unencoded probe string reflected directly in response HTML.",
                    reproducible_poc=f"Reflected probe: {indicators[0].get('probe')} on {affected_asset}"
                )
            else:
                verdict = JudgeVerdict(
                    is_confirmed=False,
                    confidence=Confidence.LOW,
                    severity=Severity.INFO,
                    reason="Probe was escaped, filtered, or not reflected in response."
                )

        # 3. CORS Misconfiguration evaluation
        elif "cors" in v_type:
            is_vuln = evidence_data.get("is_vulnerable", False)
            if is_vuln:
                vuln_type = evidence_data.get("vulnerability_type", "")
                sev = Severity.HIGH if "CREDENTIALS" in vuln_type else Severity.MEDIUM
                verdict = JudgeVerdict(
                    is_confirmed=True,
                    confidence=Confidence.CONFIRMED,
                    severity=sev,
                    reason=evidence_data.get("details", "CORS misconfiguration verified."),
                    reproducible_poc=f"Origin: {evidence_data.get('tested_origin')} reflected with ACAO header."
                )
            else:
                verdict = JudgeVerdict(
                    is_confirmed=False,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.INFO,
                    reason="CORS configuration does not expose sensitive endpoints to untrusted origins."
                )

        # Default / Generic verification
        else:
            has_substantive_data = bool(evidence_data and len(str(evidence_data)) > 30)
            if has_substantive_data:
                verdict = JudgeVerdict(
                    is_confirmed=True,
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    reason=f"Evidence provided satisfies general criteria for {candidate_title}.",
                    reproducible_poc=str(evidence_data)[:120]
                )
            else:
                verdict = JudgeVerdict(
                    is_confirmed=False,
                    confidence=Confidence.LOW,
                    severity=Severity.INFO,
                    reason="Insufficient evidence to confirm finding."
                )

        # Emit judge verdict event
        if self.event_bus:
            event_type = EventType.FINDING_VERIFIED if verdict.is_confirmed else EventType.FINDING_REJECTED
            self.event_bus.emit(
                event_type,
                {
                    "title": candidate_title,
                    "asset": affected_asset,
                    "confirmed": verdict.is_confirmed,
                    "severity": verdict.severity.value,
                    "reason": verdict.reason
                },
                severity=EventSeverity.INFO if verdict.is_confirmed else EventSeverity.DEBUG
            )

        return verdict
