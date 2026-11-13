"""Tests for best-of-N attempts with the completion gate as judge (roadmap E2)."""

import json
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from agent import best_of
from agent.best_of import score_attempt
from agent.run_session import ALLOW, RunSession
from sandbox.container import BlockedSandbox
from storage.db import StorageManager
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class AttemptAwareProvider:
    """Attempt 1 makes a wrong fix, attempt 2 the right one; each then reports back once."""

    model_name = "scripted"

    def __init__(self):
        self.calls = 0

    def is_available(self):
        return True

    def capabilities(self):
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        self.calls += 1
        text = json.dumps(messages)
        second = "attempt 2 of 2" in text
        already_edited = any(m.get("role") == "tool" for m in messages)
        if not already_edited:
            new = "return a + b" if second else "return a * b"
            turn = {"tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str=new)]}
        else:
            turn = {"content": "Fixed add." if second else "Done."}
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
        "test_command": f'"{sys.executable}" -m pytest -q -p no:cacheprovider', "coverage": "off"}), encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "buggy add")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BUZZARD_MCP_CONFIG", str(tmp_path / "no-mcp.json"))
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(str(root))
    yield root
    set_active_workspace(previous)


def session_for(root, tmp_path, provider):
    return RunSession(
        provider=provider, registry=create_authoritative_registry(),
        storage=StorageManager(db_path=str(tmp_path / "audit.db")),
        config={"workspace": str(root)}, ask_approval=lambda request: ALLOW, max_iterations=3,
    )


def test_scoring_prefers_passing_reproduced_covered_small():
    passing = SimpleNamespace(passed=True, reproduction={"status": "reproduced"},
                              changed_line_coverage={"measured": True, "percent": 80.0}, lint_status="passed")
    weaker = SimpleNamespace(passed=True, reproduction={"status": "not_reproduced"},
                             changed_line_coverage={"measured": True, "percent": 100.0}, lint_status="passed")
    assert score_attempt(passing, 10) > score_attempt(weaker, 2)
    assert score_attempt(passing, 2) > score_attempt(passing, 10)
    failed = SimpleNamespace(passed=False, reproduction={}, changed_line_coverage={}, lint_status="")
    assert score_attempt(passing, 999) > score_attempt(failed, 1)


def test_best_attempt_wins_and_only_its_changes_are_applied(repo, tmp_path):
    (repo / "notes.txt").write_text("user work in progress\n", encoding="utf-8")  # untracked, must survive
    session = session_for(repo, tmp_path, AttemptAwareProvider())
    outcome = session.run("Fix the bug in calc.py so the tests pass", target="localhost", scope=["localhost"], attempts=2)
    assert outcome.status == "completed", (outcome.error, outcome.evidence_report)
    assert "return a + b" in (repo / "calc.py").read_text(encoding="utf-8")
    assert (repo / "notes.txt").read_text(encoding="utf-8") == "user work in progress\n"
    report = outcome.evidence_report
    assert "Attempt 1: gate rejected" in report and "Attempt 2: tests passed" in report
    assert "Kept attempt 2" in report
    listing = subprocess.run(["git", "-C", str(repo), "worktree", "list"], capture_output=True, text=True).stdout
    assert listing.count("\n") == 1, listing
    assert get_active_workspace() == str(repo)
    assert [turn["role"] for turn in session.conversation] == ["user", "assistant"]


def test_no_passing_attempt_changes_nothing(repo, tmp_path):
    class AlwaysWrong(AttemptAwareProvider):
        def chat(self, messages, tools=None, options=None):
            already_edited = any(m.get("role") == "tool" for m in messages)
            turn = {"content": "Done."} if already_edited else {
                "tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str="return a * b")]}
            return {"message": {"role": "assistant", "content": turn.get("content", ""), "tool_calls": turn.get("tool_calls", [])},
                    "done": True, "metrics": {}}

    session = session_for(repo, tmp_path, AlwaysWrong())
    outcome = session.run("Fix the bug in calc.py", target="localhost", scope=["localhost"], attempts=2)
    assert outcome.status == "failed" and "No attempt passed" in outcome.error
    assert "return a - b" in (repo / "calc.py").read_text(encoding="utf-8")


def test_not_a_git_repository(tmp_path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    set_active_workspace(str(plain))
    try:
        session = session_for(plain, tmp_path, AttemptAwareProvider())
        outcome = session.run("Fix it", target="localhost", scope=["localhost"], attempts=3)
        assert outcome.status == "failed" and "git repository" in outcome.error
    finally:
        set_active_workspace(None)


def test_plan_mode_ignores_attempts(repo, tmp_path, monkeypatch):
    session = session_for(repo, tmp_path, AttemptAwareProvider())
    session.plan_mode = True
    called = []
    monkeypatch.setattr(best_of, "run_best_of", lambda *a, **k: called.append(1))
    session.run("Explain calc.py", target="localhost", scope=["localhost"], attempts=3)
    assert called == []
