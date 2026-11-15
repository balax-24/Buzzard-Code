"""Regression tests for immediate, local edit syntax feedback."""

from pathlib import Path

from agent.tool_executor import ToolExecutor
from tools.filesystem import set_active_workspace
from verification.edit_diagnostics import diagnose_edited_files, edited_paths


def test_diagnostics_report_python_and_json_syntax_errors(tmp_path: Path) -> None:
    set_active_workspace(str(tmp_path))
    try:
        (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        (tmp_path / "broken.json").write_text('{"missing": }', encoding="utf-8")

        assert diagnose_edited_files("file_write", {"path": "broken.py"}) == [
            "broken.py:1: Python syntax error: invalid syntax"
        ]
        assert diagnose_edited_files("file_write", {"path": "broken.json"}) == [
            "broken.json:1: JSON syntax error: Expecting value"
        ]
    finally:
        set_active_workspace(None)


def test_patch_path_extraction_ignores_creation_headers(tmp_path: Path) -> None:
    set_active_workspace(str(tmp_path))
    patch = (
        "--- a/existing.py\n+++ b/existing.py\n@@ -1 +1 @@\n-x\n+y\n"
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n"
    )
    assert edited_paths("apply_patch", {"patch": patch}) == ["existing.py", "new.py"]
    try:
        assert diagnose_edited_files("apply_patch", {"patch": patch}) == []
    finally:
        set_active_workspace(None)


def test_executor_appends_diagnostics_without_reclassifying_success(
    tmp_path: Path,
) -> None:
    set_active_workspace(str(tmp_path))
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    class Registry:
        tools = {"file_write": lambda **_arguments: "Wrote file."}
        quarantine = set()

        def execute(self, name, args, context=None):
            return self.tools[name](**args)

    try:
        result = ToolExecutor(Registry()).execute("file_write", {"path": "broken.py"})
    finally:
        set_active_workspace(None)

    assert result.success is True
    assert result.exit_code == 0
    assert "Immediate syntax diagnostics" in result.raw_output
    assert "broken.py:1: Python syntax error" in result.raw_output
