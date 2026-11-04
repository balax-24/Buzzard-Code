"""
Tests for recursive exploration chain:
Network -> Browser Page -> Form -> Submission -> Auth Session -> Admin API -> Finding.
"""

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceRecord,
    Capability,
    CapabilityType,
)
from agent.tool_executor import ToolExecutionResult
from state.session_store import Cookie
from intelligence.evidence_ingestor import EvidenceIngestor
from intelligence.attack_graph import AttackGraph, NodeKind
from intelligence.hypothesis_engine import HypothesisEngine


def test_browser_recursive_exploitation_chain():
    # 1. Initial State
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    ingestor = EvidenceIngestor()

    # 2. Port discovery
    state.services["target.local:8080/tcp"] = ServiceRecord(
        host="target.local", port=8080, protocol="tcp", service="http"
    )

    # 3. Browser opens root page -> reveals login form
    login_html = """
    <html><body>
        <form id="auth" action="http://target.local:8080/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <button type="submit">Login</button>
        </form>
    </body></html>
    """
    res1 = ToolExecutionResult(
        success=True,
        tool_name="browser.snapshot",
        arguments={"url": "http://target.local:8080/"},
        raw_output=login_html,
        exit_code=0
    )
    ingestor.ingest(res1, state=state)
    assert len(state.forms) == 1

    # 4. Form submission / auth probe succeeds -> sets admin session cookie
    login_resp = """
    STATUS: 302 Found
    HEADERS:
    Set-Cookie: session_id=ADMIN_SECRET_COOKIE_123; Path=/; HttpOnly
    Location: /dashboard

    BODY:
    Redirecting to /dashboard...
    """
    res2 = ToolExecutionResult(
        success=True,
        tool_name="http.request",
        arguments={"url": "http://target.local:8080/login", "method": "POST"},
        raw_output=login_resp,
        exit_code=0
    )
    ingestor.ingest(res2, state=state)

    # 5. Admin capability granted
    state.capabilities["cap-auth"] = Capability(
        capability_id="cap-auth",
        capability_type=CapabilityType.AUTHENTICATED,
        target_scope="target.local",
        source_evidence_ids=["EVI-AUTH-01"],
        metadata={"unlocked_endpoints": ["http://target.local:8080/dashboard", "http://target.local:8080/api/admin/users"]}
    )

    # 6. Graph sync and hypothesis proposal
    graph = AttackGraph()
    graph.sync_from_state(state)

    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, graph=graph)

    # Must propose actions targeting newly discovered authenticated endpoints
    prop_targets = [p.target for p in proposals]
    assert any("dashboard" in t or "admin" in t for t in prop_targets)
