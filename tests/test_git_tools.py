import os
import subprocess
import tempfile
import pytest
from pathlib import Path
from tools.filesystem import set_active_workspace, get_active_workspace
from tools.git_tools import git_status, git_diff, git_log, register_git_tools
from tools.registry import ToolRegistry


@pytest.fixture
def temp_git_repo():
    old_ws = get_active_workspace()
    temp_dir = tempfile.TemporaryDirectory()
    repo_path = Path(temp_dir.name).resolve()
    
    # Initialize a clean git repo
    subprocess.run(["git", "init"], cwd=str(repo_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(repo_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_path), check=True, capture_output=True)
    
    # Create an initial commit
    hello_file = repo_path / "hello.txt"
    hello_file.write_text("Hello, World!\n", encoding="utf-8")
    subprocess.run(["git", "add", "hello.txt"], cwd=str(repo_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True, capture_output=True)

    set_active_workspace(repo_path)
    try:
        yield repo_path
    finally:
        set_active_workspace(old_ws)
        temp_dir.cleanup()


def test_git_status_clean(temp_git_repo):
    res = git_status()
    assert "Repository Clean" in res or "No working tree changes" in res


def test_git_status_dirty(temp_git_repo):
    hello_file = temp_git_repo / "hello.txt"
    hello_file.write_text("Hello, Buzzard!\n", encoding="utf-8")
    
    new_file = temp_git_repo / "new.py"
    new_file.write_text("print('buzzard')\n", encoding="utf-8")

    res = git_status()
    assert "hello.txt" in res
    assert "new.py" in res


def test_git_diff(temp_git_repo):
    # Before modification
    diff_before = git_diff()
    assert "No working tree changes" in diff_before

    # Modify file
    hello_file = temp_git_repo / "hello.txt"
    hello_file.write_text("Hello, Buzzard!\nSecond line.\n", encoding="utf-8")

    diff_after = git_diff()
    assert "-Hello, World!" in diff_after
    assert "+Hello, Buzzard!" in diff_after


def test_git_log(temp_git_repo):
    res = git_log(max_count=5)
    assert not res.startswith("Error")
    assert "Initial commit" in res


def test_git_tools_registration():
    registry = ToolRegistry()
    register_git_tools(registry)
    
    assert "git_status" in registry.tools
    assert "git_diff" in registry.tools
    assert "git_log" in registry.tools
    assert "git.status" in registry.tools
    assert "git.diff" in registry.tools
    assert "git.log" in registry.tools
