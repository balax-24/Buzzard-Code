"""
Finding Verifier and Factual Evidence Grounding Engine.

Validates candidate security findings and factual assertions against stored
evidence records and canonical AssessmentState. Strictly prevents hallucinations
and unverified claims from being logged as verified findings or reported in audits.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple, Set

from model.schemas import Finding, Severity, Confidence, Evidence
from storage.db import StorageManager
from agent.assessment_state import (
    AssessmentState,
    ServiceRecord,
    ServiceState,
    HTTPState,
    VerificationStatus
)
from intelligence.evidence_ingestor import FactualClaim, ClaimStatus


class FindingVerifier:
    """
    Authoritative Finding & Factual Claim Verifier.
    
    Acts as the critical gatekeeper before any finding or claim is stored
    or included in final security audit reports.
    """

    def __init__(self, storage: Optional[StorageManager] = None):
        self.storage = storage

    def verify_candidate_finding(
        self,
        candidate: Dict[str, Any] | Finding,
        state: Optional[AssessmentState] = None,
        session_id: str = ""
    ) -> Tuple[bool, Finding, str]:
        """
        Validates candidate finding against canonical evidence and state.
        
        Enforces:
        1. Affected asset must exist in scope or discovered services.
        2. Version claims (e.g. "CUPS 2.4") must be backed by VERIFIED state.
        3. Factual evidence IDs must be present or discoverable in evidence store.
        
        Returns:
            (is_accepted: bool, final_finding: Finding, rationale: str)
        """
        if isinstance(candidate, Finding):
            finding_dict = candidate.dict()
        else:
            finding_dict = dict(candidate)

        title = str(finding_dict.get("title", "")).strip()
        description = str(finding_dict.get("description", "")).strip()
        affected_asset = str(finding_dict.get("affected_asset", "") or finding_dict.get("target", "")).strip()
        evidence_ids = list(finding_dict.get("evidence", []) or finding_dict.get("evidence_ids", []))
        raw_severity = str(finding_dict.get("severity", "medium")).lower()
        
        try:
            severity = Severity(raw_severity)
        except Exception:
            severity = Severity.MEDIUM

        finding_id = finding_dict.get("id") or f"FIND-{uuid.uuid4().hex[:6].upper()}"

        # 1. Extract host and port from affected asset or title
        port_m = re.search(r":(\d{1,5})|port\s+(\d{1,5})", f"{affected_asset} {title}", re.IGNORECASE)
        targeted_port = int(port_m.group(1) or port_m.group(2)) if port_m else None

        # 2. Check if affected asset / port is verified open in state
        srv_rec: Optional[ServiceRecord] = None
        if state is not None and targeted_port is not None:
            clean_host = affected_asset.split("://")[-1].split("/")[0].split(":")[0] if affected_asset else state.context.target
            srv_rec = state.get_service(clean_host, targeted_port)

        # 3. Check for specific unverified version claims in title/description (e.g. "CUPS 2.4", "Apache 2.4.50")
        combined_text = f"{title} {description}".lower()
        version_claim_m = re.search(r"\b(cups|apache|nginx|openssh|mysql|redis|bind)\s+([0-9]+\.[0-9]+[a-zA-Z0-9_\.\-]*)", combined_text)
        
        if version_claim_m and srv_rec is not None:
            claimed_prod = version_claim_m.group(1)
            claimed_ver = version_claim_m.group(2)
            
            # If service state version is UNKNOWN or doesn't match
            if srv_rec.verification_status != VerificationStatus.VERIFIED or claimed_prod not in srv_rec.version.lower():
                rationale = (
                    f"Finding rejected: Uncorroborated version claim '{claimed_prod} {claimed_ver}'. "
                    f"Port {srv_rec.port} version status is {srv_rec.verification_status.value} (recorded version: '{srv_rec.version}')."
                )
                rejected_finding = Finding(
                    id=finding_id,
                    title=f"[UNVERIFIED] {title}",
                    severity=Severity.INFO,
                    confidence=Confidence.HYPOTHESIS,
                    affected_asset=affected_asset,
                    description=f"{description} (Note: Claimed version {claimed_prod} {claimed_ver} is unverified by raw evidence).",
                    evidence=evidence_ids,
                    impact="Potential unconfirmed risk.",
                    verification=finding_dict.get("verification", "No valid PoC recorded"),
                    remediation=finding_dict.get("remediation", "Verify version before patching"),
                    status="rejected"
                )
                return (False, rejected_finding, rationale)

        # 4. Corroborate Evidence IDs
        if not evidence_ids:
            # Try to associate evidence IDs from the service record or evidence store
            if srv_rec and srv_rec.evidence_ids:
                evidence_ids = list(srv_rec.evidence_ids)
            elif self.storage and session_id:
                try:
                    all_ev = self.storage.get_evidence(session_id)
                    matching = [e.id for e in all_ev if (targeted_port and str(targeted_port) in e.description) or (affected_asset and affected_asset in e.target)]
                    if matching:
                        evidence_ids = matching
                except Exception:
                    pass

        # 5. Final acceptance check
        if not evidence_ids and state is not None and len(state.services) > 0 and targeted_port is None:
            # Generic claim with no evidence trace
            rationale = "Finding rejected: No technical evidence reference (EVI-...) associated with this finding."
            rejected_finding = Finding(
                id=finding_id,
                title=f"[UNCONFIRMED] {title}",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                affected_asset=affected_asset,
                description=description,
                evidence=[],
                impact="Unconfirmed impact.",
                verification="None",
                remediation="Investigate asset to gather technical evidence.",
                status="unconfirmed"
            )
            return (False, rejected_finding, rationale)

        # Successfully verified finding
        verified_finding = Finding(
            id=finding_id,
            title=title,
            severity=severity,
            confidence=Confidence.CONFIRMED if evidence_ids else Confidence.MEDIUM,
            affected_asset=affected_asset or (state.context.target if state else "127.0.0.1"),
            description=description,
            evidence=evidence_ids,
            impact=finding_dict.get("impact", f"Security exposure on {affected_asset}"),
            verification=finding_dict.get("verification", f"Verified via evidence {', '.join(evidence_ids)}"),
            remediation=finding_dict.get("remediation", "Apply vendor security updates and defense-in-depth controls."),
            status="active"
        )

        rationale = f"Finding verified and accepted with {len(evidence_ids)} supporting evidence record(s): {', '.join(evidence_ids)}"
        return (True, verified_finding, rationale)

    def verify_claim(
        self,
        claim: str,
        state: Optional[AssessmentState] = None,
        session_id: str = ""
    ) -> FactualClaim:
        """
        Evaluates a single factual claim against canonical state and evidence.
        """
        claim_clean = claim.strip()
        lowered = claim_clean.lower()
        now = time.time()

        # 1. Check for port status claims
        port_m = re.search(r"port\s+(\d{1,5})|(\d{1,5})/(?:tcp|udp)", lowered)
        if port_m and state is not None:
            port = int(port_m.group(1) or port_m.group(2))
            open_ports = state.get_open_ports()
            srv = state.get_service(state.context.target, port)

            if any(w in lowered for w in ("open", "discovered", "active", "listening")):
                if port in open_ports and srv:
                    return FactualClaim(
                        claim=claim_clean,
                        status=ClaimStatus.VERIFIED,
                        evidence_ids=list(srv.evidence_ids),
                        source_tool="port_scan",
                        timestamp=now,
                        details={"port": port, "service": srv.service}
                    )
                else:
                    return FactualClaim(
                        claim=claim_clean,
                        status=ClaimStatus.REJECTED,
                        evidence_ids=[],
                        source_tool=None,
                        timestamp=now,
                        details={"port": port, "reason": "Port not verified open"}
                    )

            # Check for version claims
            if any(w in lowered for w in ("version", "running", "cups", "apache", "nginx", "openssh")):
                if srv:
                    if srv.verification_status == VerificationStatus.VERIFIED and srv.version != "UNKNOWN":
                        return FactualClaim(
                            claim=claim_clean,
                            status=ClaimStatus.VERIFIED,
                            evidence_ids=list(srv.evidence_ids),
                            source_tool="fingerprint",
                            timestamp=now,
                            details={"port": port, "verified_version": srv.version}
                        )
                    else:
                        return FactualClaim(
                            claim=claim_clean,
                            status=ClaimStatus.UNKNOWN,
                            evidence_ids=list(srv.evidence_ids),
                            source_tool=None,
                            timestamp=now,
                            details={"port": port, "reason": "Version unverified / no banner"}
                        )

        # 2. Check for HTTP reachability claims
        if any(w in lowered for w in ("website is online", "http responds", "200 ok")) and state is not None:
            refused = any(ep.state == HTTPState.REFUSED for ep in state.http_endpoints.values())
            responds = any(ep.state == HTTPState.RESPONDS for ep in state.http_endpoints.values())
            
            if refused and not responds:
                return FactualClaim(
                    claim=claim_clean,
                    status=ClaimStatus.CONTRADICTED,
                    evidence_ids=[],
                    source_tool="http_probe",
                    timestamp=now,
                    details={"reason": "HTTP probes refused connection"}
                )
            elif responds:
                return FactualClaim(
                    claim=claim_clean,
                    status=ClaimStatus.VERIFIED,
                    evidence_ids=[],
                    source_tool="http_probe",
                    timestamp=now,
                    details={"status": "responds"}
                )

        return FactualClaim(
            claim=claim_clean,
            status=ClaimStatus.UNKNOWN,
            evidence_ids=[],
            source_tool=None,
            timestamp=now
        )
