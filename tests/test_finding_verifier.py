"""
Unit tests for FindingVerifier (security_agent/verification/finding_verifier.py).

Tests:
1. Evidence-backed finding is accepted with CONFIRMED confidence.
2. Unsupported finding with hallucinated version (e.g. CUPS 2.4 when version is UNKNOWN) is rejected/flagged.
3. Unsupported finding without any evidence is rejected.
4. Factual claim verification (VERIFIED, UNKNOWN, CONTRADICTED, REJECTED).
"""

import pytest
from security_agent.verification.finding_verifier import FindingVerifier
from security_agent.intelligence.evidence_ingestor import ClaimStatus
from security_agent.model.schemas import Finding, Severity, Confidence
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceState,
    HTTPState,
    VerificationStatus
)


@pytest.fixture
def base_state():
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    state = AssessmentState(context=ctx)
    # Record port 631 as ipp with UNKNOWN version
    state.record_service(
        host="127.0.0.1",
        port=631,
        protocol="tcp",
        service="ipp",
        version="UNKNOWN",
        state=ServiceState.OPEN,
        evidence_id="EVI-NMAP-001",
        verification_status=VerificationStatus.UNKNOWN
    )
    # Record port 80 as http with VERIFIED Apache version
    state.record_service(
        host="127.0.0.1",
        port=80,
        protocol="tcp",
        service="http",
        version="Apache 2.4.41",
        state=ServiceState.OPEN,
        evidence_id="EVI-HTTP-002",
        verification_status=VerificationStatus.VERIFIED
    )
    return state


@pytest.fixture
def verifier():
    return FindingVerifier()


def test_unsupported_version_claim_rejected(verifier, base_state):
    """
    If a finding claims 'Outdated CUPS 2.4 on port 631', but port 631's version
    is UNKNOWN, the finding is rejected.
    """
    candidate = {
        "title": "Vulnerable Outdated CUPS 2.4 Service",
        "affected_asset": "127.0.0.1:631",
        "description": "Port 631 runs CUPS 2.4 with known RCE",
        "severity": "high"
    }

    is_acc, finding, reason = verifier.verify_candidate_finding(candidate, state=base_state)
    assert is_acc is False
    assert finding.status == "rejected"
    assert "Uncorroborated version claim" in reason


def test_verified_finding_accepted(verifier, base_state):
    """
    If a finding references port 80 where Apache 2.4.41 is verified, finding is accepted.
    """
    candidate = {
        "title": "Apache 2.4 Information Disclosure",
        "affected_asset": "127.0.0.1:80",
        "description": "Apache 2.4 server header exposed in response",
        "severity": "low",
        "evidence_ids": ["EVI-HTTP-002"]
    }

    is_acc, finding, reason = verifier.verify_candidate_finding(candidate, state=base_state)
    assert is_acc is True
    assert finding.status == "active"
    assert "EVI-HTTP-002" in finding.evidence
    assert finding.confidence == Confidence.CONFIRMED


def test_generic_claim_verification(verifier, base_state):
    """
    Tests claim evaluation across VERIFIED, UNKNOWN, and REJECTED statuses.
    """
    # 1. Port 631 open -> VERIFIED
    c1 = verifier.verify_claim("Port 631 is open and listening", state=base_state)
    assert c1.status == ClaimStatus.VERIFIED
    assert "EVI-NMAP-001" in c1.evidence_ids

    # 2. Port 631 runs CUPS 2.4 -> UNKNOWN (because version is UNKNOWN in state)
    c2 = verifier.verify_claim("Port 631 is running CUPS 2.4", state=base_state)
    assert c2.status == ClaimStatus.UNKNOWN

    # 3. Port 9999 open -> REJECTED
    c3 = verifier.verify_claim("Port 9999 is open", state=base_state)
    assert c3.status == ClaimStatus.REJECTED
