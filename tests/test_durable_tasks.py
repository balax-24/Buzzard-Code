"""Tests for durable coding tasks (roadmap E4): the journal, listing and RunSession.resume."""

import json
import shutil
import subprocess
import sys
from typing import Any, Dict

import pytest

from agent import durable_tasks
from agent.durable_tasks import (
    JournalError,
    TaskJournal,
    list_journals,
    load_journal,
    save_journal,
)
from agent.run_session import ALLOW, RunSession
from sandbox.container import BlockedSandbox
from storage.db import StorageManager
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def journal(session_id="task-1", workspace=".", status="running", messages=None, goal="Fix add"):
    return TaskJournal(session_id, goal, "localhost", ["localhost"], str(workspace), status=status, turn=2,
                       messages=messages if messages is not None else [])


def test_round_trip_drops_the_system_prompt(home, tmp_path):
    messages = [{"role": "system", "content": "secret rules"}, {"role": "user", "content": "fix it"},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]}, {"role": "tool", "content": "ok"}]
    path = save_journal(journal(workspace=tmp_path, messages=messages))
    assert path == home / "tasks" / "task-1.json"
    loaded = load_journal("task-1")
    assert [m["role"] for m in loaded.messages] == ["user", "assistant", "tool"]
    assert loaded.workspace == str(tmp_path.resolve()) and loaded.turn == 2 and loaded.unfinished
    assert not list((home / "tasks").glob("*.tmp"))  # the temporary file was renamed into place


@pytest.mark.parametrize("bad_id", ["../escape", "a/b", "", "..", "x" * 200])
def test_unsafe_task_ids_are_rejected(home, bad_id):
    with pytest.raises(JournalError):
        load_journal(bad_id)


def test_missing_and_corrupt_journals_are_clear_errors(home):
    with pytest.raises(JournalError, match="No saved task"):
        load_journal("task-404")
    (home / "tasks").mkdir(parents=True)
    (home / "tasks" / "task-bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(JournalError, match="cannot be read"):
        load_journal("task-bad")
    (home / "tasks" / "task-old.json").write_text(json.dumps({"version": 99, "messages": []}), encoding="utf-8")
    with pytest.raises(JournalError, match="unknown format"):
        load_journal("task-old")


def test_oversized_history_keeps_the_newest_turns_without_orphan_tool_results(home, tmp_path, monkeypatch):
    monkeypatch.setattr(durable_tasks, "MAX_JOURNAL_BYTES", 400)
    messages = [{"role": "user", "content": "x" * 150},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "a"}]},
                {"role": "tool", "content": "y" * 150},
                {"role": "assistant", "content": "latest answer"}]
    save_journal(journal(workspace=tmp_path, messages=messages))
    kept = load_journal("task-1").messages
    assert kept[-1]["content"] == "latest answer"
    assert kept[0]["role"] != "tool"


def test_listing_filters_by_workspace_and_status_and_skips_broken_files(home, tmp_path):
    here, elsewhere = tmp_path / "here", tmp_path / "elsewhere"
    here.mkdir(), elsewhere.mkdir()
    save_journal(journal("task-a", here, "failed"))
    save_journal(journal("task-b", here, "completed"))
    save_journal(journal("task-c", elsewhere, "paused"))
    (home / "tasks" / "task-junk.json").write_text("[]", encoding="utf-8")
    assert {item.session_id for item in list_journals(here)} == {"task-a", "task-b"}
    assert [item.session_id for item in list_journals(here, unfinished_only=True)] == ["task-a"]
    assert {item.session_id for item in list_journals(unfinished_only=True)} == {"task-a", "task-c"}


def plain_session(tmp_path):
    return RunSession(provider=object(), registry=None, storage=None, config={}, ask_approval=lambda request: ALLOW)


def test_resume_refuses_missing_foreign_and_finished_tasks(home, tmp_path):
    previous = get_active_workspace()
    here, elsewhere = tmp_path / "here", tmp_path / "elsewhere"
    here.mkdir(), elsewhere.mkdir()
    set_active_workspace(str(here))
    try:
        session = plain_session(tmp_path)
        assert "No saved task" in session.resume("task-missing").error
        save_journal(journal("task-x", elsewhere, "failed"))
        assert "belongs to" in session.resume("task-x").error
        save_journal(journal("task-y", here, "completed"))
        assert "already finished" in session.resume("task-y").error
        assert not session.is_running  # the run lock was never taken or was released
    finally:
        set_active_workspace(previous)


# -- end to end: a crash mid-task, then a resume that sees the earlier work --------------------

def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


def reply(content="", tool_calls=None):
    return {"message": {"role": "assistant", "content": content, "tool_calls": tool_calls or []}, "done": True, "metrics": {}}


class CrashesAfterEditing:
    model_name = "scripted"

    def __init__(self):
        self.calls = 0

    def is_available(self):
        return True

    def capabilities(self):
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        self.calls += 1
        if self.calls == 1:
            return reply(tool_calls=[call("file_edit", path="calc.py", old_str="return a - b", new_str="return a + b")])
        raise RuntimeError("connection lost")


class FinishesFromHistory(CrashesAfterEditing):
    def __init__(self):
        super().__init__()
        self.saw_earlier_edit = False
        self.saw_continuation = False

    def chat(self, messages, tools=None, options=None):
        text = json.dumps(messages)
        self.saw_earlier_edit = self.saw_earlier_edit or any(m.get("role") == "tool" and "calc.py" in json.dumps(m) for m in messages)
        self.saw_continuation = self.saw_continuation or "Continue the interrupted task" in text
        return reply(content="add() is fixed; the edit from before the interruption is in place.")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_a_crashed_task_resumes_with_its_history(home, tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "T"]):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (root / "test_calc.py").write_text("from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    (root / ".buzzard").mkdir()
    (root / ".buzzard" / "project.json").write_text(json.dumps({
        "test_command": f'"{sys.executable}" -m pytest -q -p no:cacheprovider', "coverage": "off",
        "reproduce_first": "off"}), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "buggy add"], cwd=root, check=True, capture_output=True)
    monkeypatch.setenv("BUZZARD_MCP_CONFIG", str(tmp_path / "no-mcp.json"))
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(str(root))
    try:
        def session_with(provider):
            return RunSession(provider=provider, registry=create_authoritative_registry(),
                              storage=StorageManager(db_path=str(tmp_path / "audit.db")),
                              config={"workspace": str(root)}, ask_approval=lambda request: ALLOW, max_iterations=4)

        first = session_with(CrashesAfterEditing()).run(
            "Fix the bug in calc.py so the tests pass", target="localhost", scope=["localhost"], session_id="task-crash")
        assert first.status == "failed"
        saved = load_journal("task-crash")
        assert saved.unfinished and any(m.get("role") == "tool" for m in saved.messages)
        assert [item.session_id for item in list_journals(root, unfinished_only=True)] == ["task-crash"]

        provider = FinishesFromHistory()
        resumed = session_with(provider).resume("task-crash")
        assert provider.saw_earlier_edit and provider.saw_continuation
        assert resumed.session_id == "task-crash" and resumed.status == "completed", resumed.error
        assert load_journal("task-crash").status == "completed"
        assert list_journals(root, unfinished_only=True) == []
    finally:
        set_active_workspace(previous)


def test_journaling_can_be_turned_off(home, tmp_path, monkeypatch):
    previous = get_active_workspace()
    set_active_workspace(str(tmp_path))
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    try:
        provider = FinishesFromHistory()
        session = RunSession(provider=provider, registry=create_authoritative_registry(),
                             storage=StorageManager(db_path=str(tmp_path / "audit.db")),
                             config={"workspace": str(tmp_path), "durable_tasks": False},
                             ask_approval=lambda request: ALLOW, max_iterations=2)
        session.run("Fix the bug in calc.py", target="localhost", scope=["localhost"], session_id="task-off")
        assert not (home / "tasks" / "task-off.json").exists()
    finally:
        set_active_workspace(previous)


def test_exec_lists_and_rejects_resuming_unknown_tasks(home, tmp_path):
    from click.testing import CliRunner

    from cli.main import main

    save_journal(journal("task-open", tmp_path, "paused", goal="Add a price check"))
    listing = CliRunner().invoke(main, ["exec", "-", "--list", "--json", "--workspace", str(tmp_path)])
    assert listing.exit_code == 0, listing.output
    assert json.loads(listing.output) == [{"id": "task-open", "status": "paused", "turn": 2, "goal": "Add a price check"}]
    empty = CliRunner().invoke(main, ["exec", "-", "--list", "--workspace", str(tmp_path / "..")])
    assert "No unfinished tasks." in empty.output


def test_headless_resume_reports_an_unknown_task(home, tmp_path):
    from cli.headless import HeadlessPolicy, run_headless

    previous = get_active_workspace()
    try:
        result = run_headless("task-nope", tmp_path, HeadlessPolicy(), resume=True,
                              provider_factory=lambda config: object())
    finally:
        set_active_workspace(previous)
    assert result["status"] == "rejected" and result["exitCode"] == 1 and "No saved task" in result["error"]
