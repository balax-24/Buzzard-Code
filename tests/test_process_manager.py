"""Task-owned background process lifecycle and boundary tests."""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tools.filesystem import set_active_workspace
from tools.process_manager import (
    MAX_LOG_BYTES,
    MAX_LOG_CHARS,
    _PROCESSES,
    cleanup_session_processes,
    process_logs,
    process_start,
    process_stop,
    register_process_tools,
)
from tools.registry import ToolRegistry


@pytest.fixture
def workspace(tmp_path: Path):
    set_active_workspace(str(tmp_path))
    yield tmp_path
    for session_id in {managed.session_id for managed in _PROCESSES.values()}:
        cleanup_session_processes(session_id)
    set_active_workspace(None)


def _process_id(result: str) -> str:
    match = re.search(r"process (proc-[a-f0-9]+)", result)
    assert match is not None, result
    return match.group(1)


def test_process_start_captures_logs_and_stop_ends_process(workspace: Path) -> None:
    started = process_start(
        [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(30)"],
        session_id="task-one",
    )
    process_id = _process_id(started)

    logs = ""
    for _ in range(30):
        logs = process_logs(process_id, session_id="task-one")
        if "ready" in logs:
            break
        time.sleep(0.05)
    assert "ready" in logs
    assert "belongs to another task" in process_logs(process_id, session_id="task-two")

    stopped = process_stop(process_id, session_id="task-one")
    assert "Stopped process" in stopped
    assert "exited with code" in process_logs(process_id, session_id="task-one")


def test_process_start_rejects_invalid_commands_and_outside_working_directory(workspace: Path) -> None:
    assert "argument array" in process_start([], session_id="task-invalid")
    assert "non-empty string" in process_start([sys.executable, ""], session_id="task-invalid")
    assert "Access denied" in process_start(
        [sys.executable, "-c", "pass"], cwd="../outside", session_id="task-invalid",
    )
    assert "working directory" in process_start(
        [sys.executable, "-c", "pass"], cwd="missing", session_id="task-invalid",
    )


def test_process_output_buffers_and_responses_are_bounded(workspace: Path) -> None:
    process_id = _process_id(process_start(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"],
        session_id="task-output-limit",
    ))
    managed = _PROCESSES[process_id]
    managed.process.wait(timeout=10)
    if managed.reader is not None:
        managed.reader.join(timeout=2)

    result = process_logs(process_id, max_chars=MAX_LOG_CHARS * 5, session_id="task-output-limit")

    assert len(managed.log_buffer) <= MAX_LOG_BYTES
    assert len(result) < MAX_LOG_CHARS + 80


def test_cleanup_stops_and_forgets_all_processes_for_one_session(workspace: Path) -> None:
    process_id = _process_id(process_start(
        [sys.executable, "-c", "import time; time.sleep(30)"], session_id="task-cleanup",
    ))
    other_id = _process_id(process_start(
        [sys.executable, "-c", "import time; time.sleep(30)"], session_id="task-other",
    ))

    assert cleanup_session_processes("task-cleanup") == 1
    assert "unknown" in process_logs(process_id, session_id="task-cleanup")
    assert "running" in process_logs(other_id, session_id="task-other")


def test_registered_process_tools_require_approval_where_they_mutate() -> None:
    registry = ToolRegistry()
    register_process_tools(registry)
    assert registry.definitions["process_start"].approval_required is True
    assert registry.definitions["process_stop"].approval_required is True
    assert registry.definitions["process_logs"].approval_required is False


def test_run_cleanup_reaps_process_even_when_run_body_raises(monkeypatch, workspace: Path) -> None:
    process_id = _process_id(process_start(
        [sys.executable, "-c", "import time; time.sleep(30)"], session_id="task-run",
    ))

    class Boom:
        def __init__(self, **_kwargs):
            raise RuntimeError("startup failed")

    from agent.run_session import RunSession

    monkeypatch.setattr("agent.loop.AgentLoop", Boom)
    session = RunSession(None, None, None, {}, ask_approval=lambda _request: "deny")
    outcome = session.run("fix code", target="localhost", scope=["localhost"], session_id="task-run")

    assert outcome.status == "failed"
    assert "startup failed" in outcome.error
    assert "unknown" in process_logs(process_id, session_id="task-run")
