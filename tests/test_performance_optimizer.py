import json
import pytest
from unittest.mock import MagicMock

from security_agent.agent.loop import AgentLoop, TaskStatus
from security_agent.agent.assessment_state import (
    AssessmentContext,
    AssessmentState,
    FailureClassification,
    classify_failure
)
from security_agent.intelligence.evidence_parser import (
    EvidenceParser,
    AttackSurfaceSnapshot,
    DiscoveredService,
    ActionRecommendation,
    StructuredScanResult
)
from security_agent.tools.knowledge import select_next
from security_agent.intelligence.selector import ToolSelector
from security_agent.tools.registry import ToolRegistry
from security_agent.cli.renderer import render_performance_profile


def test_priority_queue_and_actionable_recommendations():
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    snapshot.services.append(DiscoveredService(port=18789, protocol="tcp", state="open", service="unknown", host="127.0.0.1"))
    snapshot.services.append(DiscoveredService(port=8384, protocol="tcp", state="open", service="http", host="127.0.0.1"))
    snapshot.services.append(DiscoveredService(port=631, protocol="tcp", state="open", service="ipp", host="127.0.0.1"))

    recs = snapshot.get_prioritized_pending_targets()
    assert len(recs) == 3
    # HTTP and unknown services must be HIGH priority
    assert recs[0].priority == "HIGH"
    assert recs[0].port in (8384, 18789)
    # Known daemon services must be MEDIUM priority
    assert any(r.port == 631 and r.priority == "MEDIUM" for r in recs)


def test_select_next_machine_actionable_json():
    selector = ToolSelector()
    res_json_str = select_next(selector, situation="authenticated jwt api endpoint")
    data = json.loads(res_json_str)
    assert data["status"] == "ready"
    assert "recommendations" in data
    assert len(data["recommendations"]) > 0
    assert "capability" in data["recommendations"][0]


def test_context_compression_minimizes_large_tool_outputs():
    parser = EvidenceParser()
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    snapshot.services.append(DiscoveredService(port=8080, protocol="tcp", state="open", service="http", host="127.0.0.1"))

    huge_nmap = "Starting Nmap 7.94...\n" + ("8080/tcp open http Apache\n" * 200) + "Nmap done: 1 IP address scanned."
    compressed = parser.compress_tool_output(
        tool_name="nmap_scan",
        raw_output=huge_nmap,
        snapshot=snapshot,
        max_chars=300
    )
    assert len(compressed) < len(huge_nmap)
    assert "8080" in compressed


def test_duplicate_tool_call_interception_and_caching():
    mock_provider = MagicMock()
    # Return two identical tool calls followed by complete
    mock_provider.chat.side_effect = [
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="ping_host"><host>127.0.0.1</host></tool_call>',
                "tool_calls": []
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="ping_host"><host>127.0.0.1</host></tool_call>',
                "tool_calls": []
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="complete"><summary>All done</summary></tool_call>',
                "tool_calls": []
            }
        }
    ]

    registry = ToolRegistry()
    call_counter = {"pings": 0}

    def mock_ping(host: str) -> str:
        call_counter["pings"] += 1
        return f"PING {host}: 0.04ms"

    registry.register("ping_host", "Ping host", mock_ping)
    registry.register("complete", "Complete task", lambda summary="": summary)

    loop = AgentLoop(
        provider=mock_provider,
        registry=registry,
        max_iterations=5,
        config={"max_actions": 10, "max_retries": 2}
    )

    result = loop.run(task_goal="Assess 127.0.0.1", target="127.0.0.1")
    assert result["status"] == "completed"
    assert call_counter["pings"] == 1
    assert loop.duplicate_calls_blocked == 1
    assert loop.cache_hits == 1


def test_action_budget_stops_agent():
    mock_provider = MagicMock()
    # Model generates infinite pings
    mock_provider.chat.return_value = {
        "message": {
            "role": "assistant",
            "content": '<tool_call name="ping_host"><host>127.0.0.1</host></tool_call>',
            "tool_calls": []
        }
    }

    registry = ToolRegistry()
    registry.register("ping_host", "Ping host", lambda host="": f"PONG {host}")
    registry.register("complete", "Complete task", lambda summary="": summary)

    loop = AgentLoop(
        provider=mock_provider,
        registry=registry,
        max_iterations=20,
        config={"max_actions": 3}
    )

    result = loop.run(task_goal="Assess 127.0.0.1", target="127.0.0.1")
    assert result["status"] == "completed"
    assert len(loop.observations) <= 3


def test_failure_classification():
    assert classify_failure("Command timed out after 120s", exit_code=124) == FailureClassification.TIMEOUT
    assert classify_failure("bash: nmap: command not found", exit_code=127) == FailureClassification.DEPENDENCY_MISSING
    assert classify_failure("nmap: unrecognized option '--invalid-flag'", exit_code=2) == FailureClassification.INVALID_ARGUMENT
    assert classify_failure("POLICY DENIED: target not in scope", exit_code=126) == FailureClassification.PERMISSION_ERROR
    assert classify_failure("connect: Connection refused", exit_code=1) in (FailureClassification.CONNECTION_REFUSED, FailureClassification.NETWORK_ERROR)
    assert classify_failure("General error occurred", exit_code=1) == FailureClassification.TOOL_FAILURE
    assert classify_failure("Nmap done: 1 IP address scanned in 0.4s", exit_code=0) == FailureClassification.NONE


def test_anti_duplicate_failed_action_tracking():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))

    # Record a failed action
    state.record_action_attempt(
        tool_name="nmap_scan",
        args={"host": "127.0.0.1", "ports": "1-65535"},
        target="127.0.0.1",
        success=False,
        failure_type=FailureClassification.TIMEOUT,
        output_snippet="Command timed out after 120s"
    )

    # Identical attempt must be blocked
    blocked, reason = state.is_action_blocked(
        tool_name="nmap_scan",
        args={"host": "127.0.0.1", "ports": "1-65535"},
        target="127.0.0.1"
    )
    assert blocked is True
    assert "TIMEOUT" in reason
    assert "BLOCKED" in reason

    # Different parameters (e.g. bounded ports 1-1000) must NOT be blocked
    blocked_diff, _ = state.is_action_blocked(
        tool_name="nmap_scan",
        args={"host": "127.0.0.1", "ports": "1-1000"},
        target="127.0.0.1"
    )
    assert blocked_diff is False


def test_structured_nmap_parser_fidelity_and_incomplete_handling():
    parser = EvidenceParser()

    # 1. Full successful scan with multiple ports
    raw_nmap = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-22 12:20 UTC
Nmap scan report for 127.0.0.1
Host is up (0.00010s latency).
Not shown: 984 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
631/tcp   open  ipp     CUPS 2.4
8384/tcp  open  http    Syncthing administrative web GUI
11434/tcp open  http    Ollama LLM API
18789/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
"""
    res = parser.parse_nmap_structured(raw_nmap, host="127.0.0.1")
    assert res.scan_status == "complete"
    assert res.open_port_count == 4
    assert any(p["port"] == 8384 and p["service"] == "http" for p in res.open_ports)
    assert any(p["port"] == 11434 for p in res.open_ports)

    # 2. Timeout / interrupted scan
    interrupted_nmap = "Starting Nmap 7.94 ( https://nmap.org )\n"
    res_interrupted = parser.parse_nmap_structured(interrupted_nmap, host="127.0.0.1", exit_code=124)
    assert res_interrupted.scan_status == "timeout"
    assert res_interrupted.open_port_count == 0


def test_hallucinated_target_interception():
    mock_provider = MagicMock()
    # LLM hallucinates and asks the user "What is the target host?"
    # Then probes the discovered service, then completes.
    mock_provider.chat.side_effect = [
        {
            "message": {
                "role": "assistant",
                "content": "What is the target host/IP? What is your objective?",
                "tool_calls": []
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="whatweb_scan"><url>http://localhost:8384/</url></tool_call>',
                "tool_calls": []
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="complete"><summary>Assessment completed: 8384 verified as Syncthing GUI.</summary></tool_call>',
                "tool_calls": []
            }
        }
    ]

    registry = ToolRegistry()
    scanned = []

    def mock_nmap(host: str, ports: str = "1-1000", options: str = ""):
        scanned.append(host)
        return f"Starting Nmap...\n8384/tcp open http Syncthing\nNmap done: 1 IP address scanned."

    def mock_whatweb(url: str):
        return f"{url} [200 OK] HTTPServer[Syncthing], Title[Syncthing]"

    registry.register("nmap_scan", "Scan host", mock_nmap)
    registry.register("whatweb_scan", "Web fingerprint", mock_whatweb)
    registry.register("complete", "Complete task", lambda summary="": summary)

    loop = AgentLoop(
        provider=mock_provider,
        registry=registry,
        max_iterations=5,
        config={"max_actions": 5},
        approval_callback=lambda tool, args, metadata: True,
    )

    result = loop.run(task_goal="Assess exposed services", target="localhost")
    assert result["status"] == "completed"
    # AgentLoop must have intercepted the hallucinated question and launched the discovery scan for localhost
    assert "localhost" in scanned or "127.0.0.1" in scanned or len(scanned) > 0


def test_performance_profile_rendering(capsys):
    profile_data = {
        "startup_time": 2.5,
        "toolchain_time": 4.1,
        "planner_time": 18.2,
        "tool_execution_time": 32.4,
        "parser_time": 0.4,
        "render_time": 0.1
    }
    render_performance_profile(profile_data)


def test_context_history_compaction():
    loop = AgentLoop(provider=MagicMock())
    messages = [
        {"role": "system", "content": "You are Buzzard Code"},
        {"role": "user", "content": "Initial task goal"},
        {"role": "assistant", "content": "thinking 1", "thinking": "verbose reasoning 1..."},
        {"role": "user", "content": "tool result 1"},
        {"role": "assistant", "content": "thinking 2", "thinking": "verbose reasoning 2..."},
        {"role": "user", "content": "tool result 2"},
        {"role": "assistant", "content": "thinking 3", "thinking": "verbose reasoning 3..."},
        {"role": "user", "content": "tool result 3"},
    ]
    compact = loop._compact_message_history(messages)
    assert len(compact) <= 7
    assert compact[0]["role"] == "system"
    assert compact[1]["role"] == "user"
    # Ensure thinking traces from prior turns are cleaned
    for msg in compact[2:]:
        if msg.get("role") == "assistant":
            assert msg.get("thinking", "") == ""


def test_scan_ports_auto_routing():
    mock_provider = MagicMock()
    mock_provider.chat.side_effect = [
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="scan_ports"><host></host><ports>1-1000</ports></tool_call>',
                "tool_calls": []
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": '<tool_call name="complete"><summary>Done</summary></tool_call>',
                "tool_calls": []
            }
        }
    ]

    registry = ToolRegistry()
    scanned_nmap = []

    def mock_nmap(host: str, ports: str = "1-1000", options: str = ""):
        scanned_nmap.append((host, ports))
        return "80/tcp open http"

    registry.register("nmap_scan", "Scan host", mock_nmap)
    registry.register("complete", "Complete task", lambda summary="": summary)

    loop = AgentLoop(
        provider=mock_provider,
        registry=registry,
        max_iterations=3,
        config={"max_actions": 5},
        approval_callback=lambda tool, args, metadata: True,
    )

    result = loop.run(task_goal="Scan all ports", target="127.0.0.1")
    assert result["status"] == "completed"
    # scan_ports with range >50 and empty host was auto-routed to nmap_scan with host=127.0.0.1
    assert len(scanned_nmap) == 1
    assert scanned_nmap[0][0] == "127.0.0.1"
    assert scanned_nmap[0][1] == "1-1000"

