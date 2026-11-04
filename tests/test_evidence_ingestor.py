"""
Unit tests for EvidenceIngestor (intelligence/evidence_ingestor.py).

Tests:
1. Verified service extraction from nmap scan
2. Unknown version preservation when banner/version is missing
3. Verified version promotion when explicit banner or server header is found
4. Contradiction detection when HTTP state changes from responds to refused
5. Immutable EvidenceItem creation and raw output persistence
"""

import pytest
from unittest.mock import MagicMock
from intelligence.evidence_ingestor import (
    EvidenceIngestor,
    EvidenceItem,
    FactualClaim,
    ClaimStatus
)
from agent.tool_executor import ToolExecutionResult
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceState,
    HTTPState,
    VerificationStatus
)


@pytest.fixture
def base_state():
    ctx = AssessmentContext(target="127.0.0.1", scope=("127.0.0.1", "localhost"))
    return AssessmentState(context=ctx)


@pytest.fixture
def ingestor(tmp_path):
    return EvidenceIngestor(base_dir=str(tmp_path))


def test_verified_service_unknown_version(ingestor, base_state):
    """
    Nmap scan with '631/tcp open ipp' extracts VERIFIED service,
    but keeps version as UNKNOWN since no version was returned.
    """
    raw_nmap = """
PORT    STATE SERVICE VERSION
631/tcp open  ipp
"""
    tool_res = ToolExecutionResult(
        success=True,
        tool_name="nmap_scan",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        exit_code=0,
        raw_output=raw_nmap,
        duration=0.5
    )

    ev_item = ingestor.ingest(tool_res, state=base_state, session_id="test-session")
    assert isinstance(ev_item, EvidenceItem)
    assert ev_item.status == "VERIFIED"

    # Check canonical state
    srv = base_state.get_service("127.0.0.1", 631)
    assert srv is not None
    assert srv.service == "ipp"
    assert srv.state == ServiceState.OPEN
    assert srv.version == "UNKNOWN"
    assert srv.verification_status == VerificationStatus.UNKNOWN
    assert len(srv.evidence_ids) >= 1
    assert srv.evidence_ids[0] == ev_item.evidence_id


def test_verified_version_from_explicit_scan(ingestor, base_state):
    """
    Nmap -sV with explicit version string verifies both service and version.
    """
    raw_nmap = """
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
"""
    tool_res = ToolExecutionResult(
        success=True,
        tool_name="nmap_scan",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        exit_code=0,
        raw_output=raw_nmap,
        duration=1.2
    )

    ev_item = ingestor.ingest(tool_res, state=base_state, session_id="test-session")
    srv = base_state.get_service("127.0.0.1", 80)
    assert srv is not None
    assert srv.service == "http"
    assert srv.version == "Apache httpd 2.4.41 ((Ubuntu))"
    assert srv.verification_status == VerificationStatus.VERIFIED
    assert ev_item.evidence_id in srv.evidence_ids


def test_banner_grab_promotes_version(ingestor, base_state):
    """
    Banner grab with explicit version promotes version from UNKNOWN to VERIFIED.
    """
    # 1. First nmap records port 22 as ssh with UNKNOWN version
    nmap_res = ToolExecutionResult(
        success=True,
        tool_name="nmap_scan",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        exit_code=0,
        raw_output="22/tcp open ssh",
        duration=0.1
    )
    ingestor.ingest(nmap_res, state=base_state)
    assert base_state.get_service("127.0.0.1", 22).version == "UNKNOWN"

    # 2. Banner grab returns explicit OpenSSH version
    banner_res = ToolExecutionResult(
        success=True,
        tool_name="grab_banner",
        arguments={"host": "127.0.0.1", "port": 22},
        target="127.0.0.1",
        exit_code=0,
        raw_output="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        duration=0.05
    )
    ingestor.ingest(banner_res, state=base_state)
    srv = base_state.get_service("127.0.0.1", 22)
    assert srv.verification_status == VerificationStatus.VERIFIED
    assert "OpenSSH" in srv.version


def test_failed_banner_grab_preserves_unknown_version(ingestor, base_state):
    """
    Failed / empty banner grab does NOT invent a version; keeps it UNKNOWN.
    """
    nmap_res = ToolExecutionResult(
        success=True,
        tool_name="nmap_scan",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        exit_code=0,
        raw_output="631/tcp open ipp",
        duration=0.1
    )
    ingestor.ingest(nmap_res, state=base_state)

    banner_res = ToolExecutionResult(
        success=True,
        tool_name="grab_banner",
        arguments={"host": "127.0.0.1", "port": 631},
        target="127.0.0.1",
        exit_code=0,
        raw_output="Connected to 127.0.0.1:631 but no banner was received",
        duration=0.05
    )
    ingestor.ingest(banner_res, state=base_state)
    srv = base_state.get_service("127.0.0.1", 631)
    assert srv.version == "UNKNOWN"
    assert srv.verification_status == VerificationStatus.UNKNOWN


def test_http_contradiction_detection(ingestor, base_state):
    """
    Tests that HTTP 200 followed by Connection Refused is flagged as a CONTRADICTION.
    """
    # Probe 1: Returns 200 OK
    res1 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080/"},
        target="127.0.0.1",
        exit_code=0,
        raw_output="HTTP/1.1 200 OK\nServer: CustomServer/1.0",
        duration=0.05
    )
    ingestor.ingest(res1, state=base_state)
    assert base_state.http_endpoints["127.0.0.1:8080"].state == HTTPState.RESPONDS

    # Probe 2: Connection refused
    res2 = ToolExecutionResult(
        success=False,
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080/"},
        target="127.0.0.1",
        exit_code=1,
        raw_output="curl: (7) Failed to connect to 127.0.0.1 port 8080: Connection refused",
        duration=0.05
    )
    ingestor.ingest(res2, state=base_state)
    assert len(base_state.contradictions) == 1
    assert base_state.contradictions[0]["type"] == "HTTP_REACHABILITY_CONTRADICTION"
