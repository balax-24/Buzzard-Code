"""Regression tests for defects found in the coding-runtime baseline audit."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from agent.loop import CODING_TOOL_NAMES, AgentLoop
from cli.banner import banner_lines
from core.usage import SessionUsage, budget_limit_usd, context_window_for, usage_to_metrics
from model.meta_muse import MetaMuseProvider
from sandbox.container import ControlledHostSandbox
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry
from verification.coding_verifier import CodingVerifier

CHAT_URL = "https://api.meta.ai/v1/chat/completions"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@test.local")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "init")
    return tmp_path


# --- ControlledHostSandbox ---


def test_sandbox_removes_secrets_but_keeps_ordinary_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "leak-probe")
    monkeypatch.setenv("GITHUB_TOKEN", "leak-probe")
    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "kept-probe")
    script = "import os; print(sorted(k for k, v in os.environ.items() if 'probe' in v))"
    result = ControlledHostSandbox(workspace=str(tmp_path)).execute(f'"{sys.executable}" -c "{script}"')
    assert result["exit_code"] == 0
    assert "TOKENIZERS_PARALLELISM" in result["stdout"]
    assert "META_API_KEY" not in result["stdout"]
    assert "GITHUB_TOKEN" not in result["stdout"]


def test_sandbox_timeout_kills_process_tree_promptly(tmp_path):
    marker = tmp_path / "survived.txt"
    child = f"import time; time.sleep(4); open(r'{marker}', 'w').close()"
    (tmp_path / "parent.py").write_text(
        "import subprocess, sys\n"
        f"subprocess.run([sys.executable, '-c', {child!r}])\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    result = ControlledHostSandbox(workspace=str(tmp_path)).execute(f'"{sys.executable}" parent.py', timeout=1)
    elapsed = time.monotonic() - started
    assert result["exit_code"] == 124
    assert "timed out" in result["stderr"]
    assert elapsed < 3.5
    time.sleep(4)
    assert not marker.exists(), "descendant process outlived the timeout"


def test_sandbox_bounds_output(tmp_path):
    command = f'"{sys.executable}" -c "print(\'x\' * 300000)"'
    result = ControlledHostSandbox(workspace=str(tmp_path)).execute(command)
    assert result["exit_code"] == 0
    assert len(result["stdout"]) < 101 * 1024
    assert "truncated" in result["stdout"]


def test_sandbox_blocks_when_kill_switch_cannot_be_checked(tmp_path):
    with patch("security.kill_switch.KillSwitch.get_instance", side_effect=RuntimeError("broken")):
        result = ControlledHostSandbox(workspace=str(tmp_path)).execute("echo should-not-run")
    assert result["exit_code"] == 126
    assert result["blocked"] is True
    assert "should-not-run" not in result["stdout"]


# --- CodingVerifier ---


def test_verifier_accepts_new_untracked_file(repo):
    (repo / "new_module.py").write_text("value = 2\n", encoding="utf-8")
    assert CodingVerifier(workspace=str(repo)).verify_task("Create new_module.py", auto_run_tests=False).passed


def test_verifier_accepts_staged_only_change(repo):
    (repo / "app.py").write_text("value = 2\n", encoding="utf-8")
    _git(repo, "add", ".")
    assert CodingVerifier(workspace=str(repo)).verify_task("Fix app.py", auto_run_tests=False).passed


def test_verifier_rejects_syntax_error_in_path_with_spaces(repo):
    nested = repo / "dir with space"
    nested.mkdir()
    (nested / "broken.py").write_text("def broken(\n", encoding="utf-8")
    result = CodingVerifier(workspace=str(repo)).verify_task("Create broken.py", auto_run_tests=False)
    assert result.passed is False
    assert "broken.py" in result.message


def test_verifier_inspects_its_workspace_not_the_active_one(repo, tmp_path_factory):
    other = tmp_path_factory.mktemp("other")
    _git(other, "init")
    (other / "other.py").write_text("value = 1\n", encoding="utf-8")
    previous = get_active_workspace()
    set_active_workspace(other)
    try:
        result = CodingVerifier(workspace=str(repo)).verify_task("Fix app.py", auto_run_tests=False)
    finally:
        set_active_workspace(previous)
    assert result.passed is False
    assert "No modifications were made" in result.message


def test_real_gate_rejects_failing_tests_then_passes_after_fix(repo, monkeypatch):
    """Acceptance path with no mocks: the gate runs the project's real test suite."""
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])
    (repo / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0.1.0'\n", encoding="utf-8")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "buggy")
    verifier = CodingVerifier(workspace=str(repo))

    (repo / "calc.py").write_text("def add(a, b):\n    return a * b\n", encoding="utf-8")
    wrong_fix = verifier.verify_task("Fix add in calc.py")
    assert wrong_fix.passed is False
    assert wrong_fix.test_exit_code == 1

    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    correct_fix = verifier.verify_task("Fix add in calc.py")
    assert correct_fix.passed is True
    assert correct_fix.test_exit_code == 0


# --- MetaMuseProvider ---


def _meta_provider() -> MetaMuseProvider:
    return MetaMuseProvider(model_name="muse-spark-1.1", api_key="test-key")


def test_meta_chat_returns_native_tool_calls_with_dict_arguments():
    response = httpx.Response(
        200,
        json={"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": "file_read", "arguments": "{\"path\": \"a.py\"}"}},
        ]}}]},
        request=httpx.Request("POST", CHAT_URL),
    )
    provider = _meta_provider()
    with patch.object(provider.client, "post", return_value=response):
        message = provider.chat([{"role": "user", "content": "read"}])["message"]
    assert message["content"] == ""
    assert message["tool_calls"][0]["id"] == "call_1"
    assert message["tool_calls"][0]["function"] == {"name": "file_read", "arguments": {"path": "a.py"}}


def test_meta_chat_discards_malformed_tool_arguments():
    response = httpx.Response(
        200,
        json={"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "call_1", "function": {"name": "file_read", "arguments": "{not json"}},
        ]}}]},
        request=httpx.Request("POST", CHAT_URL),
    )
    provider = _meta_provider()
    with patch.object(provider.client, "post", return_value=response):
        message = provider.chat([{"role": "user", "content": "read"}])["message"]
    assert message["tool_calls"][0]["function"]["arguments"] == {}


def test_meta_chat_sends_history_arguments_as_json_strings():
    response = httpx.Response(
        200,
        json={"choices": [{"message": {"content": "done"}}]},
        request=httpx.Request("POST", CHAT_URL),
    )
    history = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_1", "function": {"name": "file_read", "arguments": {"path": "a.py"}}},
        ]},
        {"role": "tool", "content": "data", "tool_call_id": "call_1"},
    ]
    provider = _meta_provider()
    with patch.object(provider.client, "post", return_value=response) as post:
        provider.chat(history)
    sent = post.call_args.kwargs["json"]["messages"]
    assert json.loads(sent[0]["tool_calls"][0]["function"]["arguments"]) == {"path": "a.py"}
    assert history[0]["tool_calls"][0]["function"]["arguments"] == {"path": "a.py"}


def test_meta_stream_assembles_fragmented_tool_calls():
    def sse(delta: dict) -> str:
        return "data: " + json.dumps({"choices": [{"delta": delta}]})

    lines = [
        sse({"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "file_read", "arguments": "{\"pa"}}]}),
        sse({"tool_calls": [{"index": 0, "function": {"arguments": "th\": \"a.py\"}"}}]}),
        "data: [DONE]",
    ]
    stream_response = MagicMock(status_code=200)
    stream_response.iter_lines.return_value = lines
    provider = _meta_provider()
    with patch.object(provider.client, "stream") as stream:
        stream.return_value.__enter__.return_value = stream_response
        chunks = list(provider.stream_chat([{"role": "user", "content": "read"}]))
    assert chunks[-1]["done"] is True
    assert chunks[-1]["message"]["tool_calls"][0]["function"] == {
        "name": "file_read",
        "arguments": {"path": "a.py"},
    }


def test_meta_default_model_is_a_published_non_contributor_id():
    assert MetaMuseProvider.DEFAULT_MODEL in MetaMuseProvider.KNOWN_MODELS
    assert not any("contributor" in model for model in MetaMuseProvider.KNOWN_MODELS)


# --- AgentLoop coding tasks ---


def test_coding_task_never_gets_synthetic_security_action():
    loop = AgentLoop(provider=MagicMock(model_name="slow-model"), storage_manager=MagicMock(), quiet=True)
    holder = {"response": None, "error": None}
    loop._is_coding_task = True
    assert loop._check_planner_timeout(loop.max_planner_time + 1, holder) is False
    assert holder["response"] is None
    assert loop.planner_timeouts_count == 0


def test_security_task_keeps_planner_fallback():
    loop = AgentLoop(provider=MagicMock(model_name="slow-model"), storage_manager=MagicMock(), quiet=True)
    holder = {"response": None, "error": None}
    assert loop._check_planner_timeout(loop.max_planner_time + 1, holder) is True
    assert holder["response"] is not None


def test_coding_prompt_describes_only_coding_tools():
    registry = create_authoritative_registry()
    description = registry.get_tools_description(only=CODING_TOOL_NAMES)
    assert CODING_TOOL_NAMES <= set(registry.tools), "every coding tool must be registered"
    assert "file_edit" in description and "terminal.execute" in description
    assert "nmap_scan" not in description


# --- Registry ---


def test_registry_exposes_the_coding_tools():
    coding_tools = {
        "file_edit", "file.edit", "file_view", "file.view",
        "git_status", "git.status", "git_diff", "git.diff", "git_log", "git.log",
    }
    assert coding_tools <= set(create_authoritative_registry().definitions)


# --- Usage accounting and banner ---


@pytest.mark.parametrize("usage,expected", [
    ({"prompt_tokens": 5, "completion_tokens": 2}, {"prompt_eval_count": 5, "eval_count": 2}),
    ({"input_tokens": 7, "output_tokens": 3}, {"prompt_eval_count": 7, "eval_count": 3}),
    (None, {}),
])
def test_usage_formats_normalize(usage, expected):
    assert usage_to_metrics(usage) == expected


def test_unknown_context_window_shows_no_guessed_percentage():
    usage = SessionUsage()
    usage.record(100, 10, estimated=True)
    assert "ctx" not in usage.status_text(None)
    assert usage.status_text(None).startswith("~")
    assert "ctx 10%" in usage.status_text(1000)
    assert context_window_for("muse-spark-1.3") == 1_048_576
    assert context_window_for("some-new-model") is None


@pytest.mark.parametrize("width", [40, 60, 80, 100, 200])
def test_banner_never_exceeds_terminal_width(width):
    assert all(len(line) <= width for line in banner_lines(width))


def test_cost_is_estimated_only_for_known_prices(monkeypatch):
    usage = SessionUsage()
    usage.record(1000, 1000, model_name="unlisted-model")
    assert usage.cost_known is False and "$" not in usage.status_text(None)
    usage.record(1_000_000, 1_000_000, model_name="meta/muse-glimmer-30b")
    assert round(usage.cost_usd, 2) == 1.50
    assert "~$1.5000" in usage.status_text(None)


@pytest.mark.parametrize("value,expected", [("2.5", 2.5), ("0", None), ("-1", None), ("lots", None), ("", None)])
def test_budget_setting(monkeypatch, value, expected):
    monkeypatch.setenv("BUZZARD_BUDGET_USD", value)
    assert budget_limit_usd() == expected
