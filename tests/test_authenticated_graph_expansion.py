"""
Tests for automatic authenticated surface discovery and AttackGraph expansion.
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    CapabilityType,
    ServiceRecord,
    ServiceState,
)
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind
from security_agent.intelligence.hypothesis_engine import HypothesisEngine


def test_authenticated_endpoint_discovery_expands_graph_and_hypotheses():
    ctx = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=ctx)

    # Add open HTTP service
    state.services["127.0.0.1:8080/tcp"] = ServiceRecord(
        host="127.0.0.1", port=8080, protocol="tcp", service="http", state=ServiceState.OPEN
    )

    # Ingest response containing links to /view and /ping
    headers = {"Set-Cookie": "session=auth_sess_123; Path=/"}
    body = """
    <html>
        <body>
            <h1>Admin Control Panel</h1>
            <a href="/view?file=system.log">View Logs</a>
            <a href="/ping?host=127.0.0.1">Network Diagnostic</a>
        </body>
    </html>
    """

    state.ingest_session_http_response(
        target_url="http://127.0.0.1:8080/login",
        status_code=200,
        headers=headers,
        body=body,
        evidence_id="EVID-AUTH-001"
    )

    # Endpoints should be registered in state
    assert any("/view" in ep.url for ep in state.http_endpoints.values())
    assert any("/ping" in ep.url for ep in state.http_endpoints.values())

    # Build AttackGraph
    graph = AttackGraph()
    graph.sync_from_state(state)

    endpoint_nodes = graph.get_nodes_by_kind(NodeKind.ENDPOINT)
    urls = [n.metadata.get("url", "") for n in endpoint_nodes]
    assert any("/view" in u for u in urls)
    assert any("/ping" in u for u in urls)

    # HypothesisEngine should generate LFI and Command Injection proposals for newly discovered surfaces
    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, graph)
    vuln_types = [p.vulnerability_type for p in proposals]

    assert "lfi" in vuln_types or "path_traversal" in vuln_types
    assert "command_injection" in vuln_types
