"""Tests for planner, workers and reviewer (roadmap E3)."""

import json
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agent.team import plan_subtasks, review_diff, run_team

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

WORKER = r'''
import json, sys
from pathlib import Path
task, workspace = sys.argv[1], Path(sys.argv[2])
name, _, text = task.partition("=")
(workspace / name).write_text(text + "\n", encoding="utf-8")
print(json.dumps({"status": "completed"}))
'''


class Model:
    """Answers the planner and the reviewer with fixed replies, and records what it was asked."""

    def __init__(self, plan, review):
        self.replies = [plan, review]
        self.asked = []

    def chat(self, messages, tools=None, options=None):
        self.asked.append(messages[-1]["content"])
        reply = self.replies.pop(0) if self.replies else ""
        return {"message": {"role": "assistant", "content": reply}}


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    (root / "a.py").write_text("original\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "start")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    worker = tmp_path / "worker.py"
    worker.write_text(WORKER, encoding="utf-8")
    return root, (lambda task, workspace: [sys.executable, str(worker), task, str(workspace)])


def passing_gate(merged):
    return SimpleNamespace(passed=True, message="ok")


PLAN = json.dumps({"subtasks": ["a.py=alpha", "new_module.py=beta"]})


def test_plan_work_gate_review_then_apply(repo):
    root, workers = repo
    model = Model(PLAN, 'Looks good: {"approve": true, "issues": []}')
    result = run_team(root, "Add alpha and a new module", model, workers, passing_gate)
    assert result.subtasks == ["a.py=alpha", "new_module.py=beta"]
    assert result.applied and result.review_approved
    assert (root / "a.py").read_text(encoding="utf-8") == "alpha\n"
    assert (root / "new_module.py").read_text(encoding="utf-8") == "beta\n"
    assert "+beta" in model.asked[1] and "+alpha" in model.asked[1]  # the reviewer saw new files too


def test_a_reviewer_rejection_applies_nothing(repo):
    root, workers = repo
    model = Model(PLAN, json.dumps({"approve": False, "issues": ["alpha breaks the API"]}))
    result = run_team(root, "Add alpha", model, workers, passing_gate)
    assert not result.applied and result.review_issues == ["alpha breaks the API"]
    assert "reviewer did not approve" in result.error or "did not pass" in result.error
    assert (root / "a.py").read_text(encoding="utf-8") == "original\n" and not (root / "new_module.py").exists()


def test_an_unreadable_review_is_not_an_approval(repo):
    root, workers = repo
    result = run_team(root, "Add alpha", Model(PLAN, "sure, ship it"), workers, passing_gate)
    assert not result.applied and "could not be read" in result.review_issues[0]


def test_the_gate_still_decides_without_review(repo):
    root, workers = repo
    model = Model(PLAN, "")
    result = run_team(root, "Add alpha", model, workers, lambda merged: SimpleNamespace(passed=False, message="tests failed"),
                      review=True)
    assert not result.applied and len(model.asked) == 1  # a failing gate never reaches the reviewer
    skipped = run_team(root, "Add alpha", Model(PLAN, ""), workers, passing_gate, review=False)
    assert skipped.applied


def test_planner_falls_back_to_one_subtask_and_caps_the_count():
    assert plan_subtasks(Model("no json here", ""), "Do the thing") == ["Do the thing"]
    many = json.dumps({"subtasks": [f"task {n}" for n in range(10)]})
    assert len(plan_subtasks(Model(many, ""), "goal")) == 6
    assert review_diff(Model('{"approve": "yes"}', ""), "goal", "diff")[0] is False
