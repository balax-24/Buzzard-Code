from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent.workspace_checkpoints import (
    CheckpointError,
    create_workspace_checkpoint,
    list_workspace_checkpoints,
    restore_workspace_checkpoint,
)
from tools.registry import ToolRegistry


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Checkpoint Test")
    _git(tmp_path, "config", "user.email", "checkpoint@test.local")
    (tmp_path / "app.py").write_text("value = 'initial'\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "initial")
    return tmp_path


def test_checkpoint_captures_worktree_without_moving_head_or_index(repository: Path) -> None:
    head_before = _git(repository, "rev-parse", "HEAD")
    staged = repository / "staged.py"
    staged.write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "staged.py")
    staged_diff_before = _git(repository, "diff", "--cached")
    (repository / "app.py").write_text("value = 'edited'\n", encoding="utf-8")
    (repository / "new.py").write_text("value = 'new'\n", encoding="utf-8")

    reference = create_workspace_checkpoint(repository, "task-123", 2)

    assert reference == "refs/buzzard/checkpoints/task-123/turn-000002"
    assert _git(repository, "rev-parse", "HEAD") == head_before
    assert _git(repository, "diff", "--cached") == staged_diff_before
    assert _git(repository, "show", f"{reference}:app.py") == "value = 'edited'"
    assert _git(repository, "show", f"{reference}:new.py") == "value = 'new'"
    assert [item["turn"] for item in list_workspace_checkpoints(repository, "task-123")] == [2]


def test_rewind_restores_checkpoint_and_keeps_recovery_ref(repository: Path) -> None:
    head_before = _git(repository, "rev-parse", "HEAD")
    create_workspace_checkpoint(repository, "task-123", 0)
    (repository / "app.py").write_text("value = 'later'\n", encoding="utf-8")
    (repository / "later.py").write_text("value = 'later'\n", encoding="utf-8")
    create_workspace_checkpoint(repository, "task-123", 1)

    result = restore_workspace_checkpoint(repository, "task-123", 0)

    assert (repository / "app.py").read_text(encoding="utf-8") == "value = 'initial'\n"
    assert not (repository / "later.py").exists()
    assert _git(repository, "rev-parse", "HEAD") == head_before
    assert result["recovered_untracked_files"] == 1
    assert _git(repository, "show", f"{result['recovery_ref']}:later.py") == "value = 'later'"
    assert "later.py" not in _git(repository, "status", "--porcelain")


@pytest.mark.parametrize("session_id,turn", [("../outside", 0), ("valid", -1), ("valid", True)])
def test_checkpoint_rejects_unsafe_identity(repository: Path, session_id: str, turn: int) -> None:
    with pytest.raises(CheckpointError):
        create_workspace_checkpoint(repository, session_id, turn)


def test_rewind_rejects_unknown_task_checkpoint(repository: Path) -> None:
    with pytest.raises(CheckpointError, match="No workspace checkpoint exists"):
        restore_workspace_checkpoint(repository, "another-task", 0)


def test_rewind_tool_restores_matching_conversation_and_requires_approval(repository: Path, monkeypatch) -> None:
    create_workspace_checkpoint(repository, "task-123", 0)
    (repository / "app.py").write_text("value = 'later'\n", encoding="utf-8")
    create_workspace_checkpoint(repository, "task-123", 1)

    initial_messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "Fix the bug"},
    ]
    assistant_message = {
        "role": "assistant",
        "tool_calls": [
            {"id": "rewind-id", "function": {"name": "workspace_rewind", "arguments": {"turn": 0}}},
            {"id": "later-id", "function": {"name": "file_edit", "arguments": {"path": "app.py"}}},
        ],
    }
    messages = [*initial_messages, assistant_message]
    history = {0: initial_messages, 1: [*initial_messages, {"role": "tool", "content": "later"}]}
    registry = ToolRegistry()
    from agent.workspace_checkpoints import register_checkpoint_tools

    register_checkpoint_tools(registry)
    monkeypatch.setattr("agent.workspace_checkpoints._workspace", lambda: str(repository))
    response = registry.execute(
        "workspace_rewind",
        {"turn": 0},
        context={
            "session_id": "task-123",
            "conversation_messages": messages,
            "checkpoint_history": history,
            "current_assistant_message": assistant_message,
            "tool_call_id": "rewind-id",
        },
    )

    assert "Restored workspace to turn 0" in response
    assert (repository / "app.py").read_text(encoding="utf-8") == "value = 'initial'\n"
    assert messages == [
        *initial_messages,
        {"role": "assistant", "tool_calls": [assistant_message["tool_calls"][0]]},
    ]
    assert list(history) == [0]
    assert registry.definitions["workspace_rewind"].approval_required is True
    schema = registry.tools["workspace_rewind"].get_schema()
    assert schema["function"]["parameters"]["required"] == ["turn"]


def test_checkpoint_requires_initialized_git_repository(tmp_path: Path) -> None:
    with pytest.raises(CheckpointError, match="not a git repository"):
        create_workspace_checkpoint(tmp_path, "task-123", 0)
