"""
Phase 19: Real-Time Event Bus, IPC Protocol, and Operator Console Tests.
"""

import json
import pytest
from unittest.mock import MagicMock
from cli.server import AgentServer


def test_agent_server_event_sequence_numbering():
    """Verify AgentServer increments sequence_number monotonically for each event emitted."""
    server = AgentServer()
    server.sequence_number = 0
    server.engagement_id = "ENG-TEST-01"

    events_captured = []

    def mock_write(line):
        try:
            events_captured.append(json.loads(line))
        except Exception:
            pass

    server._lock = MagicMock()
    # Mock sys.stdout.write
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("sys.stdout.write", mock_write)
        mp.setattr("sys.stdout.flush", lambda: None)

        server.send_event("model.started", {"model": "qwythos:latest"})
        server.send_event("model.delta", {"delta": "Analyzing target..."})
        server.send_event("tool.started", {"tool_name": "port_scan"})
        server.send_event("tool.completed", {"tool_name": "port_scan", "success": True})

    assert len(events_captured) == 4
    assert events_captured[0]["sequence_number"] == 1
    assert events_captured[1]["sequence_number"] == 2
    assert events_captured[2]["sequence_number"] == 3
    assert events_captured[3]["sequence_number"] == 4
    assert events_captured[0]["engagement_id"] == "ENG-TEST-01"
    assert events_captured[0]["event_type"] == "model.started"


def test_agent_server_get_state_snapshot_and_redaction():
    """Verify GET_STATE returns serialized state snapshot with redacted sensitive credentials."""
    server = AgentServer()
    server.engagement_id = "ENG-REDACT-01"
    server.sequence_number = 15

    # Mock active loop and assessment state with credentials
    mock_loop = MagicMock()
    mock_ast = MagicMock()
    mock_ast.context.target = "192.168.1.100"
    mock_ast.context.scope = ["192.168.1.100"]
    mock_ast.current_phase.value = "EXPLOITATION"
    mock_ast.objective_status.value = "OBJECTIVE_UNREACHED"
    mock_ast.credentials = {"admin": "super_secret_password_123"}
    mock_ast.sessions = {"sess-auth": "jwt.bearer.token.abcdef"}
    mock_ast.capabilities = {}
    mock_ast.findings = []
    mock_ast.evidence = {}
    mock_loop.assessment_state = mock_ast
    mock_loop.attack_graph = None
    mock_loop.branches = None
    server.active_loop = mock_loop

    responses = []
    events = []

    def mock_write(line):
        try:
            data = json.loads(line)
            if data.get("type") == "RESPONSE":
                responses.append(data)
            elif "sequence_number" in data:
                events.append(data)
        except Exception:
            pass

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("sys.stdout.write", mock_write)
        mp.setattr("sys.stdout.flush", lambda: None)

        server.handle_command(json.dumps({
            "id": "cmd-snap-1",
            "command": "GET_STATE",
            "params": {}
        }))

    assert len(responses) == 1
    resp = responses[0]
    assert resp["success"] is True
    assert resp["data"]["target"] == "192.168.1.100"
    # Verify sensitive data is redacted
    assert resp["data"]["credentials"]["admin"] == "***REDACTED***"
    assert resp["data"]["sessions"]["sess-auth"] == "***REDACTED***"

    # Verify event snapshot was also emitted with next sequence number
    assert len(events) == 1
    assert events[0]["event_type"] == "state.snapshot"
    assert events[0]["sequence_number"] == 16
    assert events[0]["payload"]["credentials"]["admin"] == "***REDACTED***"


def test_agent_server_pause_resume_checkpoint():
    """Verify cooperative pause, resume, and atomic checkpoint commands."""
    server = AgentServer()
    server.active_loop = MagicMock()

    responses = []
    events = []

    def mock_write(line):
        try:
            data = json.loads(line)
            if data.get("type") == "RESPONSE":
                responses.append(data)
            elif "sequence_number" in data:
                events.append(data)
        except Exception:
            pass

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("sys.stdout.write", mock_write)
        mp.setattr("sys.stdout.flush", lambda: None)

        # 1. Pause
        server.handle_command(json.dumps({"id": "cmd-p", "command": "PAUSE_ASSESSMENT", "params": {}}))
        assert server.current_task_state == "WAITING_FOR_USER"

        # 2. Resume
        server.handle_command(json.dumps({"id": "cmd-r", "command": "RESUME_ASSESSMENT", "params": {}}))
        assert server.current_task_state == "EXECUTING"

        # 3. Checkpoint
        server.handle_command(json.dumps({"id": "cmd-c", "command": "CREATE_CHECKPOINT", "params": {}}))

        # 4. Approval decision
        server.handle_command(json.dumps({
            "id": "cmd-a",
            "command": "APPROVAL_DECISION",
            "params": {"approval_id": "appr-01", "decision": "APPROVE"}
        }))

    assert len(responses) == 4
    assert all(r["success"] is True for r in responses)
    event_types = [e["event_type"] for e in events]
    assert "assessment.paused" in event_types
    assert "assessment.resumed" in event_types
    assert "checkpoint.created" in event_types
    assert "approval.response" in event_types
