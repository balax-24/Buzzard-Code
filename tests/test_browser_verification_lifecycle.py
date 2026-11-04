"""
Tests for independent verification lifecycle of findings discovered via browser automation.
"""

from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord, ServiceState
from security_agent.verification.finding_verifier import FindingVerifier


def test_browser_finding_verification_lifecycle():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.services["target.local:8080/tcp"] = ServiceRecord(
        host="target.local",
        port=8080,
        protocol="tcp",
        service="http",
        state=ServiceState.OPEN
    )

    verifier = FindingVerifier()

    # Candidate finding discovered via browser DOM injection
    finding_candidate = {
        "id": "FIND-01",
        "title": "Cross-Site Scripting (Reflected) in Search Parameter",
        "severity": "HIGH",
        "affected_asset": "http://target.local:8080/search",
        "description": "<script>alert(1)</script> reflected in DOM without escaping",
        "evidence": ["EVI-XSS-01"],
    }

    is_accepted, final_finding, rationale = verifier.verify_candidate_finding(
        candidate=finding_candidate,
        state=state
    )

    assert is_accepted is True
    assert final_finding.id == "FIND-01"
    assert "Cross-Site Scripting" in final_finding.title
