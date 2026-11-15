"""
Tests for BuzzardRuntimeClient (roadmap F6).

Verifies the high-level Python runtime client against a live stdio runtime server.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from runtime.client import BuzzardRuntimeClient, RpcClientError

ROOT = Path(__file__).resolve().parent.parent

HARNESS = r'''
import json, os, sys
sys.path.insert(0, os.environ["BUZZARD_ROOT"])
from runtime.stdio_server import serve_stdio

class ScriptedProvider:
    model_name = "scripted"
    def __init__(self, turns):
        self.turns = list(turns)
    def is_available(self):
        return True
    def capabilities(self):
        return {"native_tools": True}
    def chat(self, messages, tools=None, options=None):
        turn = self.turns.pop(0) if self.turns else {"content": "Done."}
        return {
            "message": {
                "role": "assistant",
                "content": turn.get("content", ""),
                "tool_calls": turn.get("tool_calls", [])
            },
            "done": True,
            "metrics": {}
        }
    def stream_chat(self, messages, tools=None, options=None):
        turn = self.turns.pop(0) if self.turns else {"content": "Done."}
        yield {"delta": turn.get("content", ""), "done": False}
        yield {
            "message": {
                "role": "assistant",
                "content": turn.get("content", ""),
                "tool_calls": turn.get("tool_calls", [])
            },
            "done": True,
            "metrics": {}
        }

turns = json.loads(os.environ.get("BUZZARD_SCRIPT", "[]"))
serve_stdio(provider_factory=lambda config: ScriptedProvider(turns))
'''


def make_client(tmp_path: Path, turns: List[Dict[str, Any]]) -> BuzzardRuntimeClient:
    env = {
        "BUZZARD_ROOT": str(ROOT),
        "BUZZARD_SCRIPT": json.dumps(turns),
        "BUZZARD_HOME": str(tmp_path / ".buzzard_home"),
    }
    client = BuzzardRuntimeClient(
        command=[sys.executable, "-u", "-c", HARNESS],
        workspace=str(tmp_path),
        env=env,
        cwd=tmp_path,
    )
    return client


def test_client_init_and_shutdown(tmp_path: Path):
    client = make_client(tmp_path, [])
    client.start()
    try:
        # initialize was called in start() because workspace was provided
        assert client.workspace == str(tmp_path.resolve())

        # Test plan mode
        assert client.set_plan_mode(True) is True
        assert client.set_plan_mode(False) is False

        # Test memory methods
        mem = client.list_memory()
        assert "enabled" in mem

        # Test task list
        tasks = client.list_tasks()
        assert isinstance(tasks, list)

        # Clean shutdown
        assert client.shutdown() is True
    finally:
        client.close()


def test_client_run_and_notifications(tmp_path: Path):
    turns = [
        {"content": "I am working on your goal."},
        {"content": "All done."},
    ]
    client = make_client(tmp_path, turns)
    client.start()

    deltas: List[str] = []
    client.on("run/delta", lambda p: deltas.append(p.get("text", "")))

    try:
        run_id = client.start_run(goal="Test goal")
        assert run_id.startswith(("run_", "task-"))

        finished = client.wait_for_notification("run/finished", timeout=20.0)
        assert finished.get("status") in ("completed", "failed")
        assert len(deltas) > 0
        assert "".join(deltas) != ""
    finally:
        client.shutdown()


def test_client_approval_flow(tmp_path: Path):
    # Model attempts to call an approval-gated tool
    turns = [
        {
            "content": "Let me write a file.",
            "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "file_write",
                    "arguments": {"path": "hello.txt", "content": "hello world"}
                }
            }]
        },
        {"content": "File has been written."}
    ]
    client = make_client(tmp_path, turns)
    client.start()

    approvals_requested: List[Dict[str, Any]] = []

    def on_approval(params: Dict[str, Any]):
        approvals_requested.append(params)
        req_id = params.get("requestId", "")
        # Client approves the edit
        client.respond_approval(req_id, "allow")

    client.on("approval/requested", on_approval)

    try:
        client.start_run(goal="Write hello.txt")
        finished = client.wait_for_notification("run/finished", timeout=20.0)
        assert len(approvals_requested) >= 1
        assert approvals_requested[0].get("tool") == "file_write"
        assert finished.get("status") in ("completed", "failed")
    finally:
        client.shutdown()


def test_client_cancel_run(tmp_path: Path):
    client = make_client(tmp_path, [{"content": "Waiting..."}])
    client.start()
    try:
        # Cancel when no run is active
        assert client.cancel_run() is False
    finally:
        client.shutdown()
