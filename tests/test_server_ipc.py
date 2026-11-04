import io
import json
import pytest
from unittest.mock import patch, MagicMock
from security_agent.cli.server import AgentServer
from security_agent.events.types import Event, EventType


def test_agent_server_event_mapping():
    server = AgentServer()
    emitted = []

    with patch.object(server, "send_event", side_effect=lambda t, p, i=None: emitted.append((t, p))):
        # 1. TASK
        evt_task = Event(
            type=EventType.ASSESSMENT_STARTED,
            payload={"goal": "Audit port 8080", "target": "127.0.0.1"},
            assessment_id="task-1",
        )
        server._on_internal_event(evt_task)
        assert len(emitted) == 1
        assert emitted[-1][0] == "TASK"
        assert emitted[-1][1]["goal"] == "Audit port 8080"

        # 2. PLAN
        evt_plan = Event(
            type=EventType.AGENT_PLAN_CREATED,
            payload={"strategy": "Port scan & exploit", "milestones": ["Scan", "Exploit"]},
        )
        server._on_internal_event(evt_plan)
        assert emitted[-1][0] == "PLAN"
        assert len(emitted[-1][1]["milestones"]) == 2

        # 3. TOOL & RESULT
        evt_tool = Event(
            type=EventType.TOOL_STARTED,
            payload={"tool": "http.request", "arguments": {"url": "http://127.0.0.1"}},
        )
        server._on_internal_event(evt_tool)
        assert emitted[-1][0] == "TOOL"
        assert emitted[-1][1]["tool"] == "http.request"

        evt_res = Event(
            type=EventType.TOOL_COMPLETED,
            payload={"tool": "http.request", "output": "HTTP 200 OK", "duration_ms": 100},
        )
        server._on_internal_event(evt_res)
        assert emitted[-1][0] == "RESULT"
        assert emitted[-1][1]["status"] == "SUCCESS"

        # 4. FINDING
        evt_finding = Event(
            type=EventType.FINDING_VERIFIED,
            payload={"id": "FIND-1", "title": "SQLi", "severity": "HIGH", "proof": "FLAG"},
        )
        server._on_internal_event(evt_finding)
        assert emitted[-1][0] == "FINDING"
        assert emitted[-1][1]["verified"] is True
        assert emitted[-1][1]["proof"] == "FLAG"


def test_agent_server_handle_commands():
    server = AgentServer()
    responses = []

    with patch.object(server, "send_response", side_effect=lambda cid, s, data=None, err=None: responses.append((cid, s, data))):
        server.handle_command(json.dumps({"id": "c1", "command": "status.get"}))
        assert len(responses) == 1
        assert responses[0][0] == "c1"
        assert responses[0][1] is True
        assert "model" in responses[0][2]

        server.handle_command(json.dumps({"id": "c2", "command": "models.list"}))
        assert len(responses) == 2
        assert responses[1][0] == "c2"
        assert "models" in responses[1][2]
