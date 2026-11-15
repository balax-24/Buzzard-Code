"""Workspace and undo tests for the approval-gated file move tool."""

from pathlib import Path

from tools.filesystem import (
    _edit_history,
    file_move,
    register_filesystem_tools,
    set_active_workspace,
    undo_last_edit,
)
from tools.registry import ToolRegistry


def test_file_move_relocates_file_and_undo_restores_it(tmp_path: Path) -> None:
    set_active_workspace(str(tmp_path))
    _edit_history.clear()
    (tmp_path / "source.txt").write_bytes(b"original\x00bytes")
    try:
        result = file_move("source.txt", "nested/destination.txt")
        assert "destination parent" in result

        (tmp_path / "nested").mkdir()
        result = file_move("source.txt", "nested/destination.txt")
        assert result == "Successfully moved 'source.txt' to 'nested/destination.txt'."
        assert not (tmp_path / "source.txt").exists()
        assert (tmp_path / "nested/destination.txt").read_bytes() == b"original\x00bytes"

        assert "Undid move" in undo_last_edit()
        assert (tmp_path / "source.txt").read_bytes() == b"original\x00bytes"
        assert not (tmp_path / "nested/destination.txt").exists()
    finally:
        _edit_history.clear()
        set_active_workspace(None)


def test_file_move_rejects_overwrite_and_escape(tmp_path: Path) -> None:
    set_active_workspace(str(tmp_path))
    (tmp_path / "source.txt").write_text("source", encoding="utf-8")
    (tmp_path / "destination.txt").write_text("keep", encoding="utf-8")
    try:
        assert "already exists" in file_move("source.txt", "destination.txt")
        assert "Failed to move" in file_move("source.txt", "../outside.txt")
        assert (tmp_path / "source.txt").read_text(encoding="utf-8") == "source"
        assert (tmp_path / "destination.txt").read_text(encoding="utf-8") == "keep"
    finally:
        set_active_workspace(None)


def test_file_move_is_registered_with_approval() -> None:
    registry = ToolRegistry()
    register_filesystem_tools(registry)
    definition = registry.definitions["file_move"]
    assert definition.approval_required is True
    assert definition.destructive is True
