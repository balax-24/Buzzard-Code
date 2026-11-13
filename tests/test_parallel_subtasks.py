"""Tests for parallel subtasks in git worktrees (roadmap E1)."""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.parallel import ParallelError, default_worker_command, render, run_parallel

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

# A stand-in for `buzzard exec`: sleeps, then makes the edit named in the task ("file=text").
WORKER = r'''
import json, sys, time
from pathlib import Path
task, workspace = sys.argv[1], Path(sys.argv[2])
time.sleep(float(sys.argv[3]))
name, _, text = task.partition("=")
if name == "fail":
    print(json.dumps({"status": "failed", "error": "could not do it"}))
    sys.exit(1)
(workspace / name).write_text(text + "\n", encoding="utf-8")
print(json.dumps({"status": "completed", "finalAnswer": "edited " + name}))
'''


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    for name in ("a.py", "b.py", "c.py"):
        (root / name).write_text("original\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "start")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    worker = tmp_path / "worker.py"
    worker.write_text(WORKER, encoding="utf-8")
    return root, worker


def workers(worker, seconds=0.0):
    return lambda task, workspace: [sys.executable, str(worker), task, str(workspace), str(seconds)]


def gate(passed=True, seen=None):
    def verify(merged: Path):
        if seen is not None:
            seen.append({name: (merged / name).read_text(encoding="utf-8") for name in ("a.py", "b.py", "c.py")})
        return SimpleNamespace(passed=passed, message="gate passed" if passed else "Test suite failed")
    return verify


def test_three_subtasks_run_concurrently_and_merge(repo):
    root, worker = repo
    seen = []
    result = run_parallel(root, ["a.py=alpha", "b.py=beta", "c.py=gamma"], workers(worker, 3.0), gate(seen=seen))
    assert result.status == "completed" and result.applied and result.gate_passed, render(result)
    assert all(item.seconds >= 3.0 for item in result.subtasks)
    # three 3-second subtasks in parallel: well under the 9 s they would take one after another
    assert result.seconds < 7.5, result.seconds
    assert seen == [{"a.py": "alpha\n", "b.py": "beta\n", "c.py": "gamma\n"}]  # the gate saw the merged result
    assert [(root / name).read_text(encoding="utf-8") for name in ("a.py", "b.py", "c.py")] == ["alpha\n", "beta\n", "gamma\n"]
    assert not any((Path(item) for item in git(root, "worktree", "list").splitlines()[1:]))  # worktrees removed


def test_a_conflicting_subtask_is_left_out(repo):
    root, worker = repo
    result = run_parallel(root, ["a.py=first", "a.py=second", "b.py=beta"], workers(worker), gate())
    assert result.applied and result.status == "partial"
    merged = [item.merged for item in result.subtasks]
    assert merged == [True, False, True]
    assert "conflict" in result.subtasks[1].error
    assert (root / "a.py").read_text(encoding="utf-8") == "first\n" and (root / "b.py").read_text(encoding="utf-8") == "beta\n"


def test_nothing_is_applied_when_the_merged_gate_fails(repo):
    root, worker = repo
    result = run_parallel(root, ["a.py=alpha", "b.py=beta"], workers(worker), gate(passed=False))
    assert not result.applied and "did not pass" in result.error
    assert (root / "a.py").read_text(encoding="utf-8") == "original\n"


def test_failed_subtasks_are_reported_and_not_merged(repo):
    root, worker = repo
    result = run_parallel(root, ["fail=x", "b.py=beta"], workers(worker), gate())
    assert result.subtasks[0].status == "failed" and not result.subtasks[0].merged
    assert result.applied and (root / "b.py").read_text(encoding="utf-8") == "beta\n"


def test_uncommitted_user_work_is_the_starting_point_and_survives(repo):
    root, worker = repo
    (root / "c.py").write_text("my work in progress\n", encoding="utf-8")
    (root / "notes.txt").write_text("untracked notes\n", encoding="utf-8")
    result = run_parallel(root, ["a.py=alpha", "b.py=beta"], workers(worker), gate())
    assert result.applied
    assert (root / "c.py").read_text(encoding="utf-8") == "my work in progress\n"
    assert (root / "notes.txt").read_text(encoding="utf-8") == "untracked notes\n"


def test_bad_requests(repo, tmp_path):
    root, worker = repo
    with pytest.raises(ParallelError, match="between 2"):
        run_parallel(root, ["only one"], workers(worker), gate())
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ParallelError, match="git repository"):
        run_parallel(plain, ["a", "b"], workers(worker), gate())


def test_default_worker_runs_buzzard_exec_with_only_the_given_permissions(tmp_path):
    argv = default_worker_command(allow_edits=True, allow_commands=False, model="gemini/x")("Add a flag", tmp_path)
    assert argv[1:5] == ["-m", "cli.main", "exec", "Add a flag"]
    assert "--allow-edits" in argv and "--allow-commands" not in argv and argv[-2:] == ["--model", "gemini/x"]
    assert "--json" in argv and str(tmp_path) in argv


def test_the_real_worker_entry_point_starts():
    ran = subprocess.run([sys.executable, "-m", "cli.main", "exec", "--help"],
                         cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True, timeout=120)
    assert ran.returncode == 0 and "--allow-edits" in ran.stdout and "--json" in ran.stdout
