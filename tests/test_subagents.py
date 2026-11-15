"""Tests for subagents: role permission boundaries, nesting, failures and an end-to-end run."""

import subprocess
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from agent import subagents
from agent.loop import CODING_TOOL_NAMES, AgentLoop
from agent.subagents import ROLES, build_role_registry, delegate_task
from sandbox.container import BlockedSandbox
from storage.db import StorageManager
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry


def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class ScriptedProvider:
    """Answers each chat request with the next scripted turn; parent and child share it."""

    model_name = "scripted"

    def __init__(self, turns: List[Dict[str, Any]]):
        self.turns = list(turns)
        self.requests: List[List[Dict[str, Any]]] = []

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> Dict[str, Any]:
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        self.requests.append(list(messages))
        turn = self.turns.pop(0) if self.turns else {"content": "Done."}
        return {"message": {"role": "assistant", "content": turn.get("content", ""), "tool_calls": turn.get("tool_calls", [])}, "done": True, "metrics": {}}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    project = tmp_path / "shop"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BUZZARD_MCP_CONFIG", str(tmp_path / "no-mcp.json"))
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(str(project))
    yield project
    set_active_workspace(previous)
    subagents.set_parent_loop(None)


def test_role_registries_hold_only_their_tools():
    source = create_authoritative_registry()
    explore = set(build_role_registry(source, ROLES["explore"]).tools)
    assert "file_read" in explore and "code_symbols" in explore
    assert not explore & {"file_edit", "file_write", "terminal.execute", "git_commit", "delegate_task"}
    assert "terminal.execute" in build_role_registry(source, ROLES["test"]).tools
    assert "file_edit" not in build_role_registry(source, ROLES["test"]).tools
    code = build_role_registry(source, ROLES["code"]).tools
    assert "file_edit" in code and "terminal.execute" not in code and "git_commit" not in code
    for role in ROLES.values():
        assert "delegate_task" not in role.tools


def test_delegate_tool_is_registered_for_the_main_agent():
    assert "delegate_task" in CODING_TOOL_NAMES
    assert "delegate_task" in create_authoritative_registry().tools


def test_subagent_loop_does_not_add_tools_to_its_registry(repo):
    registry = build_role_registry(create_authoritative_registry(), ROLES["explore"])
    before = set(registry.tools)
    AgentLoop(provider=MagicMock(), registry=registry, storage_manager=MagicMock(), config={"subagent_role": "explore"}, quiet=True)
    assert set(registry.tools) == before


def test_invalid_requests_and_no_parent():
    subagents.set_parent_loop(None)
    assert delegate_task("hacker", "x").startswith("Error: role must be one of")
    assert delegate_task("explore", "  ").startswith("Error: describe")
    assert delegate_task("explore", "x" * 5000).startswith("Error: keep the task")
    assert "only available while" in delegate_task("explore", "look around")


def test_subagent_cannot_start_another(monkeypatch):
    subagents.set_parent_loop(MagicMock())
    monkeypatch.setattr(subagents, "_child_running", True)
    try:
        assert delegate_task("explore", "look") == "Error: a subagent cannot start another subagent."
    finally:
        subagents.set_parent_loop(None)


def test_child_failure_is_reported_not_raised(monkeypatch):
    parent = MagicMock()
    parent.stop_event.is_set.return_value = False
    subagents.set_parent_loop(parent)
    monkeypatch.setattr(subagents, "_make_child", lambda p, r: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        assert delegate_task("explore", "look") == "Error: the explore subagent failed: boom"
        assert subagents._child_running is False
    finally:
        subagents.set_parent_loop(None)


def _parent(provider, tmp_path, approve=True):
    return AgentLoop(
        provider=provider,
        storage_manager=StorageManager(db_path=str(tmp_path / "audit.db")),
        max_iterations=8,
        approval_callback=lambda tool, args, meta: approve,
        quiet=True,
    )


def test_end_to_end_explore_subagent_is_read_only(repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("delegate_task", role="explore", task="Find what add in calc.py returns")]},
        # child turns
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"tool_calls": [call("file_edit", path="calc.py", old_str="a - b", new_str="a + b")]},
        {"content": "add returns a - b, which is the bug."},
        # parent resumes with the report
        {"content": "The explore subagent found that add subtracts."},
    ])
    result = _parent(provider, tmp_path).run(task_goal="Explain why add in calc.py is wrong, without changing any files", target="workspace")
    assert (repo / "calc.py").read_text(encoding="utf-8") == "def add(a, b):\n    return a - b\n"
    tool_messages = [m["content"] for m in result["messages"] if m.get("role") == "tool"]
    report = next(text for text in tool_messages if "Subagent 'explore' finished" in text)
    assert "Tools used: file_read, file_edit" in report
    assert "add returns a - b" in report and "not verified" in report
    child_requests = provider.requests[1:4]
    assert all("[explore subagent]" in str(request) for request in child_requests)
    edit_results = [str(m.get("content")) for m in child_requests[2] if m.get("role") == "tool"]
    assert any("Tool 'file_edit' is not registered" in text for text in edit_results)
    assert subagents._parent is None


def test_code_subagent_edit_still_needs_approval(repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("delegate_task", role="code", task="Make add in calc.py add")]},
        {"tool_calls": [call("file_edit", path="calc.py", old_str="a - b", new_str="a + b")]},
        {"content": "Changed calc.py."},
        {"content": "The edit was refused, so nothing changed."},
    ])
    _parent(provider, tmp_path, approve=False).run(task_goal="Explain calc.py without changing any files", target="workspace")
    assert "a - b" in (repo / "calc.py").read_text(encoding="utf-8")
