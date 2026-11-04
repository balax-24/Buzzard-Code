"""
Drives the real AgentLoop, tools, verifier and git with a scripted model, so agent behaviour
is tested deterministically and independently of model quality.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest

from security_agent.agent.loop import CODING_TOOL_NAMES, AgentLoop
from security_agent.model.ollama import OllamaProvider
from security_agent.model.openai_provider import OpenAIProvider
from security_agent.sandbox.container import ApprovedHostSandbox, BlockedSandbox, ToolResult, ToolErrorType
from security_agent.storage.db import StorageManager
from security_agent.verification.coding_verifier import task_requires_edits
from security_agent.tools.filesystem import get_active_workspace, set_active_workspace


def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class ScriptedProvider:
    """Replays assistant turns; records the messages and tool schemas it was sent."""

    model_name = "scripted"

    def __init__(self, turns: List[Dict[str, Any]]):
        self.turns = list(turns)
        self.requests: List[Dict[str, Any]] = []

    def chat(self, messages, tools=None, options=None):
        self.requests.append({"messages": list(messages), "tools": tools})
        turn = self.turns.pop(0) if self.turns else {"content": "No further scripted turns."}
        return {
            "message": {"role": "assistant", "content": turn.get("content", ""), "tool_calls": turn.get("tool_calls", [])},
            "done": True,
            "metrics": {},
        }


@pytest.fixture
def buggy_repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    git("init")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@test.local")
    (repo / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0.1.0'\n", encoding="utf-8")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )
    git("add", ".")
    git("commit", "-m", "buggy")

    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    # Deterministic "no Docker" environment, whatever the machine has
    monkeypatch.setattr("security_agent.agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(repo)
    yield repo
    set_active_workspace(previous)


def APPROVE_ALL(tool_name, arguments, metadata):
    return True


def run_loop(provider: ScriptedProvider, task: str, tmp_path: Path, approvals=APPROVE_ALL) -> Dict[str, Any]:
    return AgentLoop(
        provider=provider,
        storage_manager=StorageManager(db_path=tmp_path / "audit.db"),
        max_iterations=8,
        native_tools=True,
        quiet=True,
        approval_callback=approvals,
    ).run(task_goal=task, target="localhost", scope=["localhost"])


FIX = call("file_edit", path="calc.py", old_str="return a - b", new_str="return a + b")
TASK = "Fix the bug in calc.py so the test suite passes."


def test_agent_fixes_bug_and_completes(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"tool_calls": [FIX]},
        {"content": "Fixed add to use addition."},
    ])
    result = run_loop(provider, TASK, tmp_path)
    assert "return a + b" in (buggy_repo / "calc.py").read_text(encoding="utf-8")
    assert result["status"] == "completed"


def test_final_text_with_failing_tests_is_rejected(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str="return a * b")]},
        {"content": "All done, tests pass."},
        {"tool_calls": [call("file_edit", path="calc.py", old_str="return a * b", new_str="return a + b")]},
        {"content": "Fixed after seeing the failure."},
    ])
    result = run_loop(provider, TASK, tmp_path)
    rejection_seen = any(
        "COMPLETION GATE REJECTED" in str(message.get("content")) for message in provider.requests[-1]["messages"]
    )
    assert rejection_seen
    assert result["status"] == "completed"
    assert "return a + b" in (buggy_repo / "calc.py").read_text(encoding="utf-8")


def test_complete_tool_cannot_bypass_failing_tests(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str="return a * b")]},
        {"tool_calls": [call("complete", summary="Tests pass, trust me.")]},
    ])
    result = run_loop(provider, TASK, tmp_path)
    assert result["status"] != "completed"


def test_xml_complete_cannot_bypass_failing_tests(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"content": '<tool_call name="complete"><summary>Done.</summary></tool_call>'},
    ])
    result = run_loop(provider, TASK, tmp_path)
    assert result["status"] != "completed"


def test_complete_tool_succeeds_after_real_fix(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [FIX]},
        {"tool_calls": [call("complete", summary="Fixed add.")]},
    ])
    assert run_loop(provider, TASK, tmp_path)["status"] == "completed"


def test_coding_task_sends_only_coding_tool_schemas(buggy_repo, tmp_path):
    provider = ScriptedProvider([{"tool_calls": [FIX]}, {"content": "Fixed."}])
    run_loop(provider, TASK, tmp_path)
    names = {schema["function"]["name"] for schema in provider.requests[0]["tools"]}
    assert names <= CODING_TOOL_NAMES
    assert "file_edit" in names


TEST_COMMAND = "python -m pytest -q -p no:cacheprovider"


def tool_messages(provider: ScriptedProvider, request_index: int = -1) -> str:
    return " ".join(
        str(message.get("content"))
        for message in provider.requests[request_index]["messages"]
        if message.get("role") == "tool"
    )


def test_approved_command_runs_on_host_and_shows_real_output(buggy_repo, tmp_path):
    seen = []

    def operator(tool_name, arguments, metadata):
        seen.append((tool_name, arguments.get("command")))
        return True

    provider = ScriptedProvider([
        {"tool_calls": [call("terminal.execute", command=TEST_COMMAND)]},
        {"tool_calls": [FIX]},
        {"content": "Fixed."},
    ])
    run_loop(provider, TASK, tmp_path, approvals=operator)
    assert ("terminal.execute", TEST_COMMAND) in seen
    assert "assert -1 == 5" in tool_messages(provider, 1)


def test_denied_command_does_not_run(buggy_repo, tmp_path):
    marker = buggy_repo / "ran.txt"
    command = f'python -c "open(\'ran.txt\', \'w\').close()"'
    provider = ScriptedProvider([{"tool_calls": [call("terminal.execute", command=command)]}])
    result = run_loop(provider, TASK, tmp_path, approvals=lambda *_: False)
    assert not marker.exists()
    assert "POLICY DENIED" in tool_messages(provider, 1)
    assert result["status"] != "completed"


def test_no_operator_means_commands_are_denied(buggy_repo, tmp_path):
    marker = buggy_repo / "ran.txt"
    command = f'python -c "open(\'ran.txt\', \'w\').close()"'
    provider = ScriptedProvider([{"tool_calls": [call("terminal.execute", command=command)]}])
    run_loop(provider, TASK, tmp_path, approvals=None)
    assert not marker.exists()


def test_every_repeat_of_a_command_needs_approval_and_sees_fresh_results(buggy_repo, tmp_path):
    approved = []

    def operator(tool_name, arguments, metadata):
        if arguments.get("command") == TEST_COMMAND:
            approved.append(arguments["command"])
        return True

    provider = ScriptedProvider([
        {"tool_calls": [call("terminal.execute", command=TEST_COMMAND)]},
        {"tool_calls": [FIX]},
        {"tool_calls": [call("terminal.execute", command=TEST_COMMAND)]},
        {"content": "Fixed."},
    ])
    run_loop(provider, TASK, tmp_path, approvals=operator)
    assert len(approved) >= 2
    assert "1 passed" in tool_messages(provider, 3)


def test_file_read_after_edit_is_not_stale(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"tool_calls": [FIX]},
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"content": "Fixed."},
    ])
    run_loop(provider, TASK, tmp_path)
    last_tool_result = [m for m in provider.requests[3]["messages"] if m.get("role") == "tool"][-1]
    assert "return a + b" in last_tool_result["content"]


def test_denied_test_command_blocks_completion(buggy_repo, tmp_path):
    def deny_everything_but_edits(tool_name, arguments, metadata):
        return tool_name != "terminal.execute"

    provider = ScriptedProvider([{"tool_calls": [FIX]}, {"content": "Fixed."}])
    result = run_loop(provider, TASK, tmp_path, approvals=deny_everything_but_edits)
    assert result["status"] != "completed"
    assert any(
        "was not approved" in str(message.get("content")) for message in provider.requests[-1]["messages"]
    )


def test_security_tools_stay_blocked_on_host(tmp_path):
    sandbox = ApprovedHostSandbox(workspace=str(tmp_path))
    for tool_name in ("nmap_scan", "python_executor", ""):
        result = sandbox.execute("echo should-not-run", tool_name=tool_name)
        assert result["exit_code"] == 126
        assert result["blocked"] is True
        assert "should-not-run" not in result["stdout"]
    assert sandbox.execute("echo ok", tool_name="terminal.execute")["exit_code"] == 0


def test_security_task_without_docker_stays_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("security_agent.agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    provider = ScriptedProvider([{"tool_calls": [call("terminal.execute", command="whoami")]}])
    run_loop(provider, "Run nmap port scan against the target", tmp_path)
    assert "SECURITY STOP" in tool_messages(provider, 1)


def test_blocked_execution_is_not_reported_as_connection_refused():
    result = ToolResult.from_raw_output("SECURITY STOP: Docker daemon is unreachable", tool_name="terminal.execute")
    assert result.error_type == ToolErrorType.EXECUTION_BLOCKED
    assert result.exit_code == 126


def test_scope_check_allows_real_files_but_not_domains(buggy_repo):
    from security_agent.security.policy import PolicyEngine

    engine = PolicyEngine(["localhost"])
    assert engine._check_scope("terminal.execute", {"command": "python -m pytest test_calc.py"})[0] is True
    assert engine._check_scope("terminal.execute", {"command": "curl evil.example.com"})[0] is False
    assert engine._check_scope("terminal.execute", {"command": "curl test_calc.py.evil.example.com"})[0] is False


# --- Native tool calling through the real provider and HTTP layer ---


def assert_valid_openai_history(messages: List[Dict[str, Any]]) -> None:
    """Enforces the API rule that each assistant tool call is answered before anything else."""
    pending: set = set()
    for message in messages:
        if message["role"] == "tool":
            assert message["tool_call_id"] in pending, f"orphan tool result: {message}"
            pending.discard(message["tool_call_id"])
            continue
        assert not pending, f"unanswered tool calls {pending} before {message['role']}"
        for tool_call in message.get("tool_calls") or []:
            assert "." not in tool_call["function"]["name"]
            assert isinstance(tool_call["function"]["arguments"], str)
            pending.add(tool_call["id"])
    assert not pending, f"unanswered tool calls {pending}"


def openai_provider_with_script(turns: List[Dict[str, Any]], requests: List[Dict[str, Any]]) -> OpenAIProvider:
    remaining = list(turns)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert_valid_openai_history(body["messages"])
        requests.append(body)
        turn = remaining.pop(0) if remaining else {"content": "No further scripted turns."}
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", **turn}}]})

    provider = OpenAIProvider(model_name="m", api_key="k", base_url="https://example.test/v1")
    provider.client = httpx.Client(transport=httpx.MockTransport(handler))
    return provider


def wire_call(call_id: str, name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}


def run_default_loop(provider, tmp_path: Path) -> Dict[str, Any]:
    return AgentLoop(
        provider=provider,
        storage_manager=StorageManager(db_path=tmp_path / "audit.db"),
        max_iterations=8,
        quiet=True,
        approval_callback=APPROVE_ALL,
    ).run(task_goal=TASK, target="localhost", scope=["localhost"])


def test_default_native_run_fixes_bug_over_real_provider_layer(buggy_repo, tmp_path):
    requests: List[Dict[str, Any]] = []
    provider = openai_provider_with_script([
        {"content": None, "tool_calls": [wire_call("c1", "terminal__execute", command=TEST_COMMAND)]},
        {"content": None, "tool_calls": [
            wire_call("c2", "file_read", path="calc.py"),
            wire_call("c3", "git_status"),
        ]},
        {"content": None, "tool_calls": [
            wire_call("c4", "file_edit", path="calc.py", old_str="return a - b", new_str="return a + b"),
        ]},
        {"content": "Fixed add."},
    ], requests)
    result = run_default_loop(provider, tmp_path)
    assert result["status"] == "completed"
    assert "return a + b" in (buggy_repo / "calc.py").read_text(encoding="utf-8")
    names = {tool["function"]["name"] for tool in requests[0]["tools"]}
    assert "terminal__execute" in names
    assert "Use the API's native tool calling" in requests[0]["messages"][0]["content"]


def test_native_completion_rejection_keeps_history_valid(buggy_repo, tmp_path):
    requests: List[Dict[str, Any]] = []
    provider = openai_provider_with_script([
        {"content": None, "tool_calls": [wire_call("c1", "complete", summary="Done.")]},
        {"content": None, "tool_calls": [
            wire_call("c2", "file_edit", path="calc.py", old_str="return a - b", new_str="return a + b"),
        ]},
        {"content": "Fixed."},
    ], requests)
    assert run_default_loop(provider, tmp_path)["status"] == "completed"
    assert len(requests) >= 3


def test_native_history_stays_valid_through_compaction(buggy_repo, tmp_path):
    requests: List[Dict[str, Any]] = []
    (buggy_repo / "big.txt").write_text("line of content\n" * 4000, encoding="utf-8")
    turns = [
        {"content": None, "tool_calls": [wire_call(f"r{index}", "file_read", path="./" * index + "big.txt")]}
        for index in range(6)
    ]
    run_default_loop(openai_provider_with_script(turns, requests), tmp_path)
    assert len(requests) >= 6


def test_native_mode_selection():
    cloud = OpenAIProvider(model_name="m", api_key="k")
    local = OllamaProvider(model_name="m")
    local._capabilities_cache = ("m", ["completion"])
    assert AgentLoop(provider=cloud, storage_manager=None, quiet=True).native_tools is True
    assert AgentLoop(provider=local, storage_manager=None, quiet=True).native_tools is False
    assert AgentLoop(provider=cloud, storage_manager=None, quiet=True, native_tools=False).native_tools is False
    assert AgentLoop(provider=cloud, storage_manager=None, quiet=True, config={"native_tools": False}).native_tools is False
    assert AgentLoop(provider=local, storage_manager=None, quiet=True, native_tools=True).native_tools is True


def test_read_only_task_completes_despite_failing_tests(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"content": "add subtracts instead of adding."},
    ])
    result = run_loop(provider, "Identify the bug in calc.py. Do not change any files.", tmp_path)
    assert result["status"] == "completed"
    assert "return a - b" in (buggy_repo / "calc.py").read_text(encoding="utf-8")
    assert len(provider.requests) == 2


def test_verified_fix_finishes_without_security_completion_gates(buggy_repo, tmp_path):
    provider = ScriptedProvider([{"tool_calls": [FIX]}, {"content": "Fixed."}])
    result = run_loop(provider, TASK, tmp_path)
    assert result["status"] == "completed"
    assert len(provider.requests) == 2


@pytest.mark.parametrize("edit", [
    FIX,
    call("file_write", path="calc.py", content="def add(a, b):\n    return a + b\n"),
])
def test_denied_edit_does_not_change_file(buggy_repo, tmp_path, edit):
    provider = ScriptedProvider([{"tool_calls": [edit]}])
    result = run_loop(provider, TASK, tmp_path, approvals=lambda *_: False)
    assert "return a - b" in (buggy_repo / "calc.py").read_text(encoding="utf-8")
    assert result["status"] != "completed"


@pytest.mark.parametrize("task,expected", [
    ("Fix the bug in calc.py", True),
    ("Create a new module", True),
    ("Explain the architecture of this repository", False),
    ("Identify the bug. Do not change any files.", False),
    ("Explain this without changing anything", False),
    ("What address does this project use?", False),
    ("The test suite is failing. Fix inventory.py so all tests pass. Do not modify the tests.", True),
    ("Fix the bug without changing the public API", True),
    ("Do not change any files; produce a plan.", False),
    ("Review this. No code changes.", False),
])
def test_task_requires_edits(task, expected):
    assert task_requires_edits(task) is expected


def test_coding_context_contains_no_security_assessment_text(buggy_repo, tmp_path):
    provider = ScriptedProvider([
        {"tool_calls": [call("file_read", path="calc.py")]},
        {"tool_calls": [call("terminal.execute", command=TEST_COMMAND)]},
        {"tool_calls": [FIX]},
        {"content": "Fixed."},
    ])
    run_loop(provider, TASK, tmp_path)
    sent = " ".join(str(message.get("content")) for request in provider.requests for message in request["messages"])
    for marker in ("CANONICAL", "ATTACK SURFACE", "HYPOTHES", "port scan"):
        assert marker not in sent, marker


def test_read_only_prompt_does_not_plan_edits(buggy_repo, tmp_path):
    provider = ScriptedProvider([{"content": "It is a small calculator."}])
    run_loop(provider, "Explain the architecture of this project repository.", tmp_path)
    first_user_message = provider.requests[0]["messages"][1]["content"]
    assert "file_edit" not in first_user_message
    assert "Do not change any files" in first_user_message


def test_ollama_model_declaring_tools_uses_native_mode():
    local = OllamaProvider(model_name="m")
    local._capabilities_cache = ("m", ["completion", "tools"])
    assert AgentLoop(provider=local, storage_manager=None, quiet=True).native_tools is True


def test_follow_up_task_receives_earlier_conversation(buggy_repo, tmp_path):
    provider = ScriptedProvider([{"content": "It subtracts."}])
    AgentLoop(
        provider=provider,
        storage_manager=StorageManager(db_path=tmp_path / "audit.db"),
        max_iterations=3,
        native_tools=True,
        quiet=True,
        approval_callback=APPROVE_ALL,
    ).run(
        task_goal="Explain why this function is wrong in calc.py.",
        target="localhost",
        scope=["localhost"],
        conversation_history=[
            {"role": "user", "content": "Which file has add?"},
            {"role": "assistant", "content": "calc.py"},
        ],
    )
    sent = provider.requests[0]["messages"]
    assert sent[1]["content"] == "Which file has add?"
    assert sent[2]["content"] == "calc.py"
    assert "Explain why" in sent[3]["content"]


def test_repeating_model_is_redirected_then_stopped(buggy_repo, tmp_path):
    repeated = {"tool_calls": [call("file_read", path="calc.py")]}
    provider = ScriptedProvider([repeated] * 8)
    result = run_loop(provider, TASK, tmp_path)
    assert result["status"] == "failed"
    assert len(provider.requests) == 4
    assert "repeated your previous action" in str(provider.requests[2]["messages"])


def test_repeat_warning_lets_a_model_recover(buggy_repo, tmp_path):
    repeated = {"tool_calls": [call("file_read", path="calc.py")]}
    provider = ScriptedProvider([repeated, repeated, {"tool_calls": [FIX]}, {"content": "Fixed."}])
    assert run_loop(provider, TASK, tmp_path)["status"] == "completed"


def test_same_command_after_an_edit_is_not_a_repeat(buggy_repo, tmp_path):
    tests = {"tool_calls": [call("terminal.execute", command=TEST_COMMAND)]}
    provider = ScriptedProvider([tests, {"tool_calls": [FIX]}, tests, {"content": "Fixed."}])
    assert run_loop(provider, TASK, tmp_path)["status"] == "completed"


def test_project_instructions_reach_coding_prompt(buggy_repo, tmp_path):
    (buggy_repo / "AGENTS.md").write_text("Always use tabs.", encoding="utf-8")
    provider = ScriptedProvider([{"content": "ok"}])
    run_loop(provider, "Explain this repository.", tmp_path)
    assert "Always use tabs." in provider.requests[0]["messages"][0]["content"]


def test_protecting_tests_does_not_disable_the_completion_gate(buggy_repo, tmp_path):
    """Found live on Muse Glimmer: the agent reported completed while tests still failed."""
    provider = ScriptedProvider([{"content": "To fix it, you should change calc.py."}])
    result = run_loop(provider, "Fix calc.py so all tests pass. Do not modify the tests.", tmp_path)
    assert result["status"] != "completed"
    assert "COMPLETION GATE REJECTED" in str(provider.requests[-1]["messages"])
