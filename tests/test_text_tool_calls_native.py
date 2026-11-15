"""Regression: tool calls a model writes as text must stay valid in native tool-call history.

Found on 13 November 2026 with gemini-3.5-flash-lite: the model answered with text containing a
<tool_call> tag, the loop ran it, but (1) the call had no id, so its result was dropped from
history and the next request ended with a model turn, and (2) Gemini 3 rejects function calls in
history that carry no thought signature.
"""

import json

from agent.run_session import ALLOW, RunSession
from model.tool_calls import UNSIGNED_CALL_SIGNATURE, repair_tool_call_pairs, to_gemini_contents
from sandbox.container import BlockedSandbox
from storage.db import StorageManager
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry


def test_unsigned_calls_are_marked_and_model_signatures_kept():
    _, contents = to_gemini_contents([
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "a", "function": {"name": "file_read", "arguments": {"path": "a.py"}}}]},
        {"role": "tool", "content": "x", "tool_call_id": "a"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "b", "function": {"name": "file_read", "arguments": {"path": "b.py"}}, "thought_signature": "SIG"},
            {"id": "c", "function": {"name": "file_read", "arguments": {"path": "c.py"}}}]},
    ])
    parsed_turn, parallel_turn = contents[1]["parts"], contents[3]["parts"]
    assert parsed_turn[0]["thoughtSignature"] == UNSIGNED_CALL_SIGNATURE
    assert parallel_turn[0]["thoughtSignature"] == "SIG"
    assert "thoughtSignature" not in parallel_turn[1]  # Gemini signs only the first parallel call


class TextToolCaller:
    """Writes its tool call as text the first time, like some models do, then answers."""

    model_name = "scripted"

    def __init__(self):
        self.requests = []

    def is_available(self):
        return True

    def capabilities(self):
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        self.requests.append(json.loads(json.dumps(messages, default=str)))
        if len(self.requests) == 1:
            text = '<tool_call>{"name": "file_read", "arguments": {"path": "calc.py"}}</tool_call>'
            return {"message": {"role": "assistant", "content": text, "tool_calls": []}, "done": True, "metrics": {}}
        return {"message": {"role": "assistant", "content": "calc.py defines add.", "tool_calls": []},
                "done": True, "metrics": {}}


def test_a_call_written_as_text_keeps_its_result_in_history(tmp_path, monkeypatch):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(str(tmp_path))
    provider = TextToolCaller()
    try:
        RunSession(provider=provider, registry=create_authoritative_registry(),
                   storage=StorageManager(db_path=str(tmp_path / "audit.db")), config={"workspace": str(tmp_path)},
                   ask_approval=lambda request: ALLOW, max_iterations=3).run(
            "Explain what calc.py does", "localhost", ["localhost"])
    finally:
        set_active_workspace(previous)
    assert len(provider.requests) >= 2
    second = repair_tool_call_pairs(provider.requests[1])
    calls = [call for message in second for call in message.get("tool_calls") or []]
    assert calls and all(call.get("id") for call in calls)
    results = [message for message in second if message.get("role") == "tool"]
    assert results and results[0]["tool_call_id"] == calls[0]["id"] and "def add" in results[0]["content"]
    assert second[-1]["role"] != "assistant"  # the request never ends with a model turn
