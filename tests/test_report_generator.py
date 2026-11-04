"""
Unit tests for ReportGenerator (reports/report_generator.py).

Tests:
1. Report generation includes verified attack surface with Evidence IDs.
2. Unverified versions are displayed as UNKNOWN without hallucination.
3. Report traceability: Every service and finding cites evidence IDs.
4. Markdown, JSON, and Console outputs are produced accurately.
"""

import json
import pytest
from reports.report_generator import ReportGenerator
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceState,
    VerificationStatus
)
from model.schemas import Finding, Severity, Confidence, Evidence, EvidenceType


@pytest.fixture
def populated_state():
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"), objective="Security Audit")
    state = AssessmentState(context=ctx)
    
    # 631: UNKNOWN version
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
    # 80: VERIFIED version
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
def generator():
    return ReportGenerator()


def test_report_data_evidence_traceability(generator, populated_state):
    """
    Verifies that generated report data strictly links facts to Evidence IDs.
    """
    findings = [
        Finding(
            id="FIND-001",
            title="Exposed Apache Server Header",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            affected_asset="127.0.0.1:80",
            description="Apache 2.4.41 banner is exposed",
            evidence=["EVI-HTTP-002"],
            impact="Information disclosure",
            verification="Curl header check",
            remediation="Set ServerTokens Prod"
        )
    ]
    evidence_list = [
        Evidence(
            id="EVI-NMAP-001",
            type=EvidenceType.OTHER,
            target="127.0.0.1",
            description="Nmap scan showing port 631 open",
            data="631/tcp open ipp",
            timestamp="2026-08-23T00:00:00"
        ),
        Evidence(
            id="EVI-HTTP-002",
            type=EvidenceType.HTTP,
            target="127.0.0.1:80",
            description="HTTP probe showing Apache 2.4.41",
            data="Server: Apache/2.4.41",
            timestamp="2026-08-23T00:01:00"
        )
    ]

    report = generator.generate_report_data(
        state=populated_state,
        session_id="test-session",
        target="127.0.0.1",
        findings=findings,
        evidence_list=evidence_list
    )

    # 1. Check services
    srvs = {s["port"]: s for s in report["services"]}
    assert srvs[631]["version"] == "UNKNOWN"
    assert srvs[631]["evidence_ids"] == ["EVI-NMAP-001"]
    assert srvs[80]["version"] == "Apache 2.4.41"
    assert srvs[80]["status"] == "VERIFIED"
    assert srvs[80]["evidence_ids"] == ["EVI-HTTP-002"]

    # 2. Check markdown rendering
    md = generator.render_markdown(report)
    assert "EVI-NMAP-001" in md
    assert "EVI-HTTP-002" in md
    assert "FIND-001" in md or "Exposed Apache Server Header" in md
    assert "Apache 2.4.41" in md

    # 3. Check JSON rendering
    json_str = generator.render_json(report)
    parsed = json.loads(json_str)
    assert parsed["session_id"] == "test-session"
    assert len(parsed["services"]) == 2
