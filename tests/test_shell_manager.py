from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tools.registry import ToolRegistry
from tools.shell_manager import (
    _SHELLS,
    cleanup_session_shells,
    register_shell_tool,
    shell_execute,
)


@pytest.fixture(autouse=True)
def clean_shells():
    for session_id in list(_SHELLS):
        cleanup_session_shells(session_id)
    yield
    for session_id in list(_SHELLS):
        cleanup_session_shells(session_id)


def test_persistent_shell_keeps_directory_and_environment(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "subdir").mkdir()
    monkeypatch.setattr("tools.shell_manager.get_active_workspace", lambda: str(tmp_path))
    if os.name == "nt":
        first = "Set-Location subdir; $env:BUZZARD_SHELL_PROBE='persist'; Get-Location"
        second = 'Write-Output "$env:BUZZARD_SHELL_PROBE|$PWD"'
    else:
        first = "cd subdir; export BUZZARD_SHELL_PROBE=persist; pwd"
        second = 'printf "%s|%s" "$BUZZARD_SHELL_PROBE" "$PWD"'

    first_result = shell_execute(first, session_id="task-persist")
    second_result = shell_execute(second, session_id="task-persist")

    assert "Exit code: 0" in first_result
    assert "persist" in second_result
    assert str(tmp_path / "subdir") in second_result


def test_shell_rejects_dangerous_commands_without_starting_process() -> None:
    result = shell_execute("rm -rf /", session_id="task-danger")

    assert result.startswith("TOOL ERROR: command matches restricted dangerous pattern")
    assert "task-danger" not in _SHELLS


def test_shell_timeout_stops_session_and_allows_a_fresh_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("tools.shell_manager.get_active_workspace", lambda: str(tmp_path))
    command = "Start-Sleep -Seconds 5" if os.name == "nt" else "sleep 5"

    timed_out = shell_execute(command, timeout=0.1, session_id="task-timeout")
    fresh = shell_execute("Write-Output ready" if os.name == "nt" else "printf ready", session_id="task-timeout")

    assert "timed out" in timed_out
    assert "Exit code: 0" in fresh and "ready" in fresh


def test_shell_output_is_bounded_and_cleanup_terminates_process(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("tools.shell_manager.get_active_workspace", lambda: str(tmp_path))
    code = "print('x' * 200000)"
    if os.name == "nt":
        command = f'& "{sys.executable}" -c "{code}"'
    else:
        command = f'"{sys.executable}" -c \'{code}\''

    result = shell_execute(command, session_id="task-cleanup")
    process = _SHELLS["task-cleanup"].process
    assert len(result.encode("utf-8")) <= 129_000
    assert cleanup_session_shells("task-cleanup") == 1
    process.wait(timeout=2)
    assert process.poll() is not None
    assert "task-cleanup" not in _SHELLS


def test_shell_tool_requires_approval_and_hides_session_context() -> None:
    registry = ToolRegistry()
    register_shell_tool(registry)

    definition = registry.definitions["shell_execute"]
    schema = registry.tools["shell_execute"].get_schema()
    properties = schema["function"]["parameters"]["properties"]
    assert definition.approval_required is True
    assert schema["function"]["parameters"]["required"] == ["command"]
    assert "session_id" not in properties
