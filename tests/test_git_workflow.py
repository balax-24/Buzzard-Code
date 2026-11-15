"""Tests for branch, commit and PR-draft tools against a real temporary repository."""

import shutil
import subprocess

import pytest

from security.risk import get_tool_risk_metadata
from tools.filesystem import set_active_workspace
from tools.git_workflow import (
    git_branch_create,
    git_commit,
    git_prepare_commit,
    git_prepare_pr,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-q", "-m", "chore: initial commit")
    set_active_workspace(str(tmp_path))
    yield tmp_path
    set_active_workspace(None)


def test_write_tools_always_require_approval():
    assert get_tool_risk_metadata("git_commit").requires_approval
    assert get_tool_risk_metadata("git_branch_create").requires_approval
    assert not get_tool_risk_metadata("git_prepare_commit").requires_approval
    assert not get_tool_risk_metadata("git_prepare_pr").requires_approval


def test_prepare_commit_lists_changes_style_and_secrets(repo):
    (repo / "app.py").write_text("x = 2\n", encoding="utf-8")
    (repo / "new.py").write_text("y = 1\n", encoding="utf-8")
    (repo / ".env").write_text("KEY=1\n", encoding="utf-8")
    out = git_prepare_commit()
    assert "Modified, not staged (1): app.py" in out
    assert "new.py" in out and "chore: initial commit" in out
    assert "Do not commit (look like secrets): .env" in out


def test_prepare_commit_clean_tree(repo):
    assert git_prepare_commit().startswith("Nothing to commit")


def test_branch_then_commit_named_paths_only(repo):
    assert "Created and switched to branch 'fix/rounding'" in git_branch_create("fix/rounding")
    (repo / "app.py").write_text("x = 2\n", encoding="utf-8")
    (repo / "other.py").write_text("z = 1\n", encoding="utf-8")
    out = git_commit("fix: round discounts correctly", "app.py")
    assert "Committed" in out and "Nothing was pushed" in out
    assert _git(repo, "log", "-1", "--format=%s") == "fix: round discounts correctly"
    assert _git(repo, "show", "--name-only", "--format=", "HEAD") == "app.py"
    assert "?? other.py" in _git(repo, "status", "--porcelain")


def test_commit_refuses_secrets_bad_messages_and_escapes(repo):
    (repo / ".env").write_text("KEY=1\n", encoding="utf-8")
    assert "look like secrets" in git_commit("add env", ".env")
    assert "empty" in git_commit("", "app.py")
    assert "keep it to 72" in git_commit("x" * 80, "app.py")
    assert git_commit("msg", "../outside.py").startswith("Error")
    assert git_commit("msg", "--amend").startswith("Error")
    assert git_commit("msg", "missing.py").startswith("Error")
    assert "nothing is staged" in git_commit("msg")
    assert _git(repo, "rev-list", "--count", "HEAD") == "1"


def test_commit_reports_hook_failure_and_keeps_hooks(repo):
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'lint failed' >&2\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    (repo / "app.py").write_text("x = 3\n", encoding="utf-8")
    out = git_commit("feat: change x", "app.py")
    assert "hook" in out.lower() or out.startswith("Error committing")
    assert _git(repo, "rev-list", "--count", "HEAD") == "1"


def test_branch_name_validation(repo):
    assert git_branch_create("bad name").startswith("Error")
    assert git_branch_create("-D").startswith("Error")
    assert git_branch_create("a..b").startswith("Error")
    assert git_branch_create("main").startswith("Error: branch 'main' already exists")
    assert git_branch_create("ok", base="--orphan").startswith("Error")


def test_prepare_pr_drafts_without_pushing(repo):
    assert git_prepare_pr().startswith("Error: you are on 'main'")
    git_branch_create("feat/total")
    assert "no commits" in git_prepare_pr()
    (repo / "app.py").write_text("x = 5\n", encoding="utf-8")
    git_commit("feat: add totals", "app.py")
    out = git_prepare_pr("main")
    assert "Suggested title: feat: add totals" in out
    assert "app.py" in out and "git push -u origin feat/total" in out
    assert "Nothing has been pushed" in out
    assert git_prepare_pr("no-such-branch").startswith("Error")


def test_not_a_repository(tmp_path):
    set_active_workspace(str(tmp_path))
    try:
        assert "not a git repository" in git_prepare_commit()
        assert "not a git repository" in git_branch_create("x")
        assert "not a git repository" in git_prepare_pr()
    finally:
        set_active_workspace(None)
