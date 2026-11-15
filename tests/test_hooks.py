"""Tests for user hooks around tool calls (roadmap F2), with real hook processes."""

import json
import sys

import pytest

from agent import hooks
from agent.hooks import HookConfigError, load_hooks, run_after_tool, run_before_tool, run_task_end
from agent.tool_executor import ToolExecutor
from tools.filesystem import set_active_workspace
from tools.registry import create_authoritative_registry

PY = sys.executable


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    config = tmp_path / "hooks.json"
    monkeypatch.setenv("BUZZARD_HOOKS_CONFIG", str(config))
    set_active_workspace(str(root))
    yield root, config, tmp_path
    set_active_workspace(None)


def script(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path)


def write_hooks(config, entries):
    config.write_text(json.dumps({"hooks": entries}), encoding="utf-8")


def test_no_config_changes_nothing(workspace):
    root, _, _ = workspace
    assert run_before_tool("file_read", {}, str(root), "s") is None
    assert run_after_tool("file_read", {}, "ok", str(root), "s") == ""


def test_before_hook_blocks_matching_tools_with_its_message(workspace):
    root, config, tmp = workspace
    guard = script(tmp, "guard.py",
                   "import json, sys\nevent = json.load(sys.stdin)\n"
                   "if 'migrations' in event['arguments'].get('path', ''):\n"
                   "    print('migrations are read-only'); sys.exit(1)\n")
    write_hooks(config, [{"event": "before_tool", "tools": ["file_*"], "command": [PY, guard]}])
    assert "migrations are read-only" in run_before_tool("file_write", {"path": "migrations/001.sql"}, str(root), "s")
    assert run_before_tool("file_write", {"path": "app.py"}, str(root), "s") is None
    assert run_before_tool("directory_list", {"path": "migrations"}, str(root), "s") is None  # not matched


def test_after_hook_output_is_appended(workspace):
    root, config, tmp = workspace
    formatter = script(tmp, "fmt.py", "import json, sys\nevent = json.load(sys.stdin)\nprint('formatted', event['tool'])\n")
    write_hooks(config, [{"event": "after_tool", "tools": ["directory_list"], "command": [PY, formatter]}])
    out = run_after_tool("directory_list", {"path": "."}, "a.txt", str(root), "s")
    assert "formatted directory_list" in out


def test_broken_guard_fails_closed(workspace):
    root, config, tmp = workspace
    slow = script(tmp, "slow.py", "import time\ntime.sleep(5)\n")
    write_hooks(config, [{"event": "before_tool", "command": [PY, slow], "timeout": 1}])
    assert "timed out" in run_before_tool("file_read", {}, str(root), "s")
    write_hooks(config, [{"event": "before_tool", "command": ["no-such-hook-binary-xyz"]}])
    assert "could not start" in run_before_tool("file_read", {}, str(root), "s")
    config.write_text("{broken", encoding="utf-8")
    assert "hooks file is invalid" in run_before_tool("file_read", {}, str(root), "s")


@pytest.mark.parametrize("entry, message", [
    ({"event": "sometimes", "command": ["x"]}, "event must be"),
    ({"event": "before_tool", "command": "x"}, "non-empty list"),
    ({"event": "before_tool", "command": ["x"], "tools": "file_*"}, "tools"),
    ({"event": "before_tool", "command": ["x"], "timeout": 500}, "timeout"),
])
def test_config_validation(workspace, entry, message):
    _, config, _ = workspace
    write_hooks(config, [entry])
    with pytest.raises(HookConfigError, match=message):
        load_hooks()


def test_task_end_hook_runs(workspace):
    root, config, tmp = workspace
    marker = tmp / "ended.json"
    recorder = script(tmp, "rec.py", f"import sys\nopen(r'{marker}', 'w').write(sys.stdin.read())\n")
    write_hooks(config, [{"event": "task_end", "command": [PY, recorder]}])
    run_task_end(str(root), "task-1", "completed")
    assert json.loads(marker.read_text(encoding="utf-8"))["status"] == "completed"


def test_executor_honours_hooks_end_to_end(workspace):
    root, config, tmp = workspace
    guard = script(tmp, "deny.py", "print('no listing today'); raise SystemExit(3)\n")
    write_hooks(config, [{"event": "before_tool", "tools": ["directory_list"], "command": [PY, guard]}])
    result = ToolExecutor(create_authoritative_registry()).execute("directory_list", {"path": "."})
    assert not result.success and "no listing today" in result.raw_output
    note = script(tmp, "note.py", "print('checked by hook')\n")
    write_hooks(config, [{"event": "after_tool", "tools": ["directory_list"], "command": [PY, note]}])
    result = ToolExecutor(create_authoritative_registry()).execute("directory_list", {"path": "."})
    assert result.success and "a.txt" in result.raw_output and "checked by hook" in result.raw_output


def test_repository_hooks_file_is_ignored(tmp_path, monkeypatch):
    monkeypatch.delenv("BUZZARD_HOOKS_CONFIG", raising=False)
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    (tmp_path / ".buzzard").mkdir()
    (tmp_path / ".buzzard" / "hooks.json").write_text(json.dumps({"hooks": [{"event": "before_tool", "command": ["evil"]}]}))
    monkeypatch.chdir(tmp_path)
    assert hooks.hooks_config_path() == tmp_path / "home" / "hooks.json"
    assert load_hooks() == []
