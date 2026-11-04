"""
Tests for Capability and SessionStore integration and AttackGraph bridging.
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    CapabilityType,
    VerificationStatus,
)
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind, EdgeKind
from security_agent.state.session_store import Cookie, SessionVerificationStatus


def test_session_creation_updates_capabilities():
    ctx = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=ctx)

    # Ingest authenticated HTTP response
    headers = {"Set-Cookie": "session=auth_adm_777; Path=/"}
    body = "<html><body>Welcome, Administrator! <a href='/admin/dashboard'>Admin</a></body></html>"

    session, endpoints = state.ingest_session_http_response(
        target_url="http://127.0.0.1:8080/login",
        status_code=200,
        headers=headers,
        body=body,
        evidence_id="EVID-LOGIN-001"
    )

    # State capabilities should now contain AUTHENTICATED
    assert state.has_capability(CapabilityType.AUTHENTICATED)
    caps = state.get_capabilities(CapabilityType.AUTHENTICATED)
    assert len(caps) >= 1
    assert "EVID-LOGIN-001" in caps[0].source_evidence_ids

    # Synchronize with AttackGraph
    graph = AttackGraph()
    graph.sync_from_state(state)

    # AttackGraph should have SESSION and CAPABILITY nodes
    sess_nodes = graph.get_nodes_by_kind(NodeKind.SESSION)
    assert len(sess_nodes) >= 1
    assert "SESSION:" in sess_nodes[0].label

    cap_nodes = graph.get_nodes_by_kind(NodeKind.CAPABILITY)
    assert len(cap_nodes) >= 1
    assert "CAP:AUTHENTICATED" in cap_nodes[0].label


def test_scope_isolation_prevents_credential_leakage():
    ctx = AssessmentContext(target="http://target-a.com", scope=["target-a.com"])
    state = AssessmentState(context=ctx)

    # Create session on target-a.com
    session_a = state.get_session_store().create_session("http://target-a.com")
    session_a.add_cookie(Cookie(name="jwt", value="secret_a", domain="target-a.com"))

    # Request to target-a.com should include cookie
    ctx_a = state.get_request_auth_context("http://target-a.com/api/data")
    assert "Cookie" in ctx_a["headers"]
    assert "jwt=secret_a" in ctx_a["headers"]["Cookie"]

    # Request to target-b.com must NEVER include Target A's credentials
    ctx_b = state.get_request_auth_context("http://target-b.com/api/data")
    assert "Cookie" not in ctx_b["headers"]
    assert ctx_b["session_id"] is None
