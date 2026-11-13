"""Workspace boundary, preflight, and rollback tests for unified patching."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import filesystem
from tools.registry import ToolRegistry


@pytest.fixture
def workspace(tmp_path: Path):
    filesystem.set_active_workspace(str(tmp_path))
    yield tmp_path
    filesystem.set_active_workspace(None)


def test_apply_patch_updates_multiple_files_and_creates_new_files(workspace: Path) -> None:
    (workspace / "a.py").write_text("x = 1\ny = 3\n", encoding="utf-8")
    patch = (
        "diff --git a/a.py b/a.py\n"
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n"
        "-x = 1\n+x = 2\n y = 3\n"
        "diff --git a/new.py b/new.py\n"
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+one\n+two\n"
    )

    result = filesystem.apply_patch(patch)

    assert result == "Successfully applied patch to 2 file(s)."
    assert (workspace / "a.py").read_text(encoding="utf-8") == "x = 2\ny = 3\n"
    assert (workspace / "new.py").read_text(encoding="utf-8") == "one\ntwo\n"


def test_apply_patch_preflights_every_file_before_writing(workspace: Path) -> None:
    (workspace / "a.py").write_text("value = 1\n", encoding="utf-8")
    (workspace / "b.py").write_text("value = 2\n", encoding="utf-8")
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-value = 1\n+value = 10\n"
        "--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-missing\n+value = 20\n"
    )

    result = filesystem.apply_patch(patch)

    assert "hunk context did not match 'b.py'" in result
    assert (workspace / "a.py").read_text(encoding="utf-8") == "value = 1\n"
    assert (workspace / "b.py").read_text(encoding="utf-8") == "value = 2\n"


def test_apply_patch_rolls_back_earlier_file_when_later_replace_fails(
    workspace: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("a.py", "b.py"):
        (workspace / name).write_text("value = 1\n", encoding="utf-8")
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-value = 1\n+value = 10\n"
        "--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-value = 1\n+value = 20\n"
    )
    original_replace = filesystem.os.replace
    calls = 0

    def fail_second_replace(source, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated replacement failure")
        return original_replace(source, target)

    monkeypatch.setattr(filesystem.os, "replace", fail_second_replace)
    result = filesystem.apply_patch(patch)

    assert "Patch transaction failed" in result
    assert (workspace / "a.py").read_text(encoding="utf-8") == "value = 1\n"
    assert (workspace / "b.py").read_text(encoding="utf-8") == "value = 1\n"


def test_apply_patch_rejects_traversal_and_requires_registry_approval(workspace: Path) -> None:
    result = filesystem.apply_patch(
        "--- a/../outside.py\n+++ b/../outside.py\n@@ -1 +1 @@\n-a\n+b\n"
    )
    assert "Patch rejected without changes" in result

    registry = ToolRegistry()
    filesystem.register_filesystem_tools(registry)
    definition = registry.definitions["apply_patch"]
    assert definition.approval_required is True
    assert definition.destructive is True


def test_apply_patch_errors_are_treated_as_tool_failures(workspace: Path) -> None:
    from sandbox.container import ToolResult

    result = filesystem.apply_patch("not a diff")
    parsed = ToolResult.from_raw_output(result, tool_name="apply_patch")

    assert parsed.success is False
    assert parsed.exit_code == 1


def test_apply_patch_supports_file_deletion_and_undo(workspace: Path) -> None:
    target = workspace / "remove.txt"
    target.write_text("remove me\n", encoding="utf-8")
    result = filesystem.apply_patch(
        "--- a/remove.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-remove me\n"
    )

    assert "Successfully applied patch to 1 file" in result
    assert not target.exists()
    assert "Undid edit" in filesystem.undo_last_edit()
    assert target.read_text(encoding="utf-8") == "remove me\n"
