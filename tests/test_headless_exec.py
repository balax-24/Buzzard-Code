"""Tests for headless `buzzard exec` runs (roadmap F4)."""

import json
import shutil
import subprocess
import sys
from typing import Any, Dict

import pytest

from agent.run_session import ALLOW, DENY, ApprovalRequest
from cli.headless import HeadlessPolicy, render_text, run_headless
from sandbox.container import BlockedSandbox
from tools.filesystem import get_active_workspace, set_active_workspace

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class FixProvider:
    model_name = "scripted"

    def is_available(self):
        return True

    def capabilities(self):
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        edited = any(m.get("role") == "tool" for m in messages)
        turn = {"content": "Fixed add."} if edited else {
            "tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str="return a + b")]}
        return {"message": {"role": "assistant", "content": turn.get("content", ""), "tool_calls": turn.get("tool_calls", [])},
                "done": True, "metrics": {}}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@t")
    git("config", "user.name", "T")
    (root / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (root / "test_calc.py").write_text("from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    (root / ".buzzard").mkdir()
    (root / ".buzzard" / "project.json").write_text(json.dumps({
        "test_command": f'"{sys.executable}" -m pytest -q -p no:cacheprovider', "coverage": "off", "reproduce_first": "off"}),
        encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "buggy add")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BUZZARD_MCP_CONFIG", str(tmp_path / "no-mcp.json"))
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    yield root
    set_active_workspace(previous)


def run(repo, policy, **kwargs):
    return run_headless("Fix the bug in calc.py so the tests pass", repo, policy,
                        provider_factory=lambda config: FixProvider(), max_iterations=4, **kwargs)


def test_policy_defaults_to_deny_and_records_refusals():
    policy = HeadlessPolicy()
    request = ApprovalRequest("r1", "file_edit", {"path": "a.py", "new_str": "x" * 500}, "R1", None)
    assert policy.decide(request) == DENY
    assert policy.denied == [{"tool": "file_edit", "arguments": {"path": "a.py", "new_str": "x" * 200}}]
    assert HeadlessPolicy(allow_edits=True).decide(request) == ALLOW
    command = ApprovalRequest("r2", "terminal.execute", {"command": "pytest"}, "R4", None)
    assert HeadlessPolicy(allow_edits=True).decide(command) == DENY
    assert HeadlessPolicy(allow_commands=True).decide(command) == ALLOW
    mcp = ApprovalRequest("r3", "mcp.docs.search", {}, "R3", None)
    assert HeadlessPolicy(allow_edits=True, allow_commands=True).decide(mcp) == DENY
    assert HeadlessPolicy(allow_all=True).decide(mcp) == ALLOW


def test_edits_and_commands_allowed_completes_with_exit_zero(repo):
    result = run(repo, HeadlessPolicy(allow_edits=True, allow_commands=True))
    assert result["status"] == "completed" and result["exitCode"] == 0, result
    assert "return a + b" in (repo / "calc.py").read_text(encoding="utf-8")
    assert "exit 0" in result["evidenceReport"] and result["deniedRequests"] == []
    assert result["evidenceBundle"] and result["model"] == "scripted"
    json.dumps(result)  # the --json output must serialize


def test_without_command_approval_the_gate_cannot_pass(repo):
    result = run(repo, HeadlessPolicy(allow_edits=True))
    assert result["exitCode"] == 1
    assert any(item["tool"] == "terminal.execute" for item in result["deniedRequests"])
    assert "Refused (no approval flag allowed them)" in render_text(result)


def test_plan_mode_changes_nothing(repo):
    result = run(repo, HeadlessPolicy(allow_all=True), plan=True)
    assert "return a - b" in (repo / "calc.py").read_text(encoding="utf-8")
    assert result["approvals"]["granted"] == 0


def test_cli_rejects_bad_attempts():
    from click.testing import CliRunner

    from cli.main import main

    result = CliRunner().invoke(main, ["exec", "fix it", "--attempts", "9"])
    assert result.exit_code == 2 and "attempts" in result.output.lower()
