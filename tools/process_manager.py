"""Per-run, bounded background process management for coding tasks."""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import psutil

from tools.filesystem import get_active_workspace, get_safe_path


MAX_PROCESSES_PER_SESSION = 8
MAX_COMMAND_ARGUMENTS = 64
MAX_COMMAND_CHARS = 16_000
MAX_LOG_BYTES = 128_000
MAX_LOG_CHARS = 12_000
PROCESS_START_TIMEOUT = 5.0
_LOCK = threading.RLock()


@dataclass
class _ManagedProcess:
    process: subprocess.Popen[bytes]
    session_id: str
    log_buffer: bytearray = field(default_factory=bytearray)
    log_lock: threading.Lock = field(default_factory=threading.Lock)
    reader: threading.Thread | None = None


_PROCESSES: dict[str, _ManagedProcess] = {}


def _read_output(managed: _ManagedProcess) -> None:
    stream = managed.process.stdout
    if stream is None:
        return
    try:
        while chunk := stream.read1(4096):
            with managed.log_lock:
                managed.log_buffer.extend(chunk)
                excess = len(managed.log_buffer) - MAX_LOG_BYTES
                if excess > 0:
                    del managed.log_buffer[:excess]
    except OSError:
        # The process may close its pipe while cleanup is running.
        return
    finally:
        stream.close()


def _lookup(process_id: str, session_id: str) -> _ManagedProcess | None:
    with _LOCK:
        managed = _PROCESSES.get(process_id)
        if managed is None or managed.session_id != session_id:
            return None
        return managed


def process_start(command: list[str], cwd: str = ".", session_id: str = "") -> str:
    """Start an approved process using argv (no shell), isolated to the task workspace."""
    if not session_id:
        return "TOOL ERROR: process_start requires a task session."
    if not isinstance(command, list) or not command or len(command) > MAX_COMMAND_ARGUMENTS:
        return f"TOOL ERROR: command must be an argument array with 1 to {MAX_COMMAND_ARGUMENTS} entries."
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in command):
        return "TOOL ERROR: every command argument must be a non-empty string without NUL characters."
    if sum(len(argument) for argument in command) > MAX_COMMAND_CHARS:
        return f"TOOL ERROR: command exceeds the {MAX_COMMAND_CHARS}-character limit."

    try:
        safe_cwd = get_safe_path(cwd)
        if not os.path.isdir(safe_cwd):
            return f"TOOL ERROR: working directory '{cwd}' does not exist or is not a directory."
        with _LOCK:
            live_count = sum(
                managed.session_id == session_id and managed.process.poll() is None
                for managed in _PROCESSES.values()
            )
            if live_count >= MAX_PROCESSES_PER_SESSION:
                return f"TOOL ERROR: this task already has {MAX_PROCESSES_PER_SESSION} running processes."
            process = subprocess.Popen(
                command,
                cwd=safe_cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                close_fds=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                start_new_session=os.name != "nt",
            )
            process_id = f"proc-{uuid.uuid4().hex[:12]}"
            managed = _ManagedProcess(process=process, session_id=session_id)
            reader = threading.Thread(
                target=_read_output,
                args=(managed,),
                name=f"buzzard-process-log-{process_id}",
                daemon=True,
            )
            managed.reader = reader
            _PROCESSES[process_id] = managed
            try:
                reader.start()
            except RuntimeError:
                _PROCESSES.pop(process_id, None)
                process.kill()
                process.wait(timeout=PROCESS_START_TIMEOUT)
                raise
        time.sleep(0.05)
        state = "running" if process.poll() is None else f"exited with code {process.returncode}"
        return f"Started process {process_id} ({state}). Use process_logs to inspect output and process_stop to stop it."
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return f"TOOL ERROR: Could not start process: {error}"


def process_logs(process_id: str, max_chars: int = 4000, session_id: str = "") -> str:
    """Return the bounded recent output and state for a process owned by this task."""
    if not isinstance(process_id, str) or not process_id:
        return "TOOL ERROR: process_id must be a non-empty string."
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars < 1:
        return "TOOL ERROR: max_chars must be a positive integer."
    managed = _lookup(process_id, session_id)
    if managed is None:
        return "TOOL ERROR: process ID is unknown or belongs to another task."
    if managed.process.poll() is not None and managed.reader is not None:
        managed.reader.join(timeout=0.2)
    with managed.log_lock:
        output = bytes(managed.log_buffer[-min(max_chars, MAX_LOG_CHARS):]).decode("utf-8", errors="replace")
    code = managed.process.poll()
    state = "running" if code is None else f"exited with code {code}"
    return f"Process {process_id} {state}.\n{output}".rstrip()


def _terminate_process(managed: _ManagedProcess) -> None:
    process = managed.process
    if process.poll() is None:
        try:
            root = psutil.Process(process.pid)
            descendants = root.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            descendants = []
        for child in reversed(descendants):
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            process.terminate()
        except OSError:
            pass
        _gone, alive = psutil.wait_procs(descendants, timeout=1.0)
        for child in alive:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if alive:
            psutil.wait_procs(alive, timeout=1.0)
        try:
            process.wait(timeout=PROCESS_START_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=PROCESS_START_TIMEOUT)
    if managed.reader is not None:
        managed.reader.join(timeout=1.0)


def process_stop(process_id: str, session_id: str = "") -> str:
    """Stop a task-owned process tree and retain its final logs until task cleanup."""
    if not isinstance(process_id, str) or not process_id:
        return "TOOL ERROR: process_id must be a non-empty string."
    managed = _lookup(process_id, session_id)
    if managed is None:
        return "TOOL ERROR: process ID is unknown or belongs to another task."
    try:
        _terminate_process(managed)
    except (OSError, psutil.Error, subprocess.SubprocessError) as error:
        return f"TOOL ERROR: Could not stop process {process_id}: {error}"
    return f"Stopped process {process_id} (exit code {managed.process.poll()})."


def cleanup_session_processes(session_id: str) -> int:
    """Stop and forget every managed process owned by a completed or cancelled run."""
    with _LOCK:
        owned = [
            (process_id, managed) for process_id, managed in _PROCESSES.items()
            if managed.session_id == session_id
        ]
    for _process_id, managed in owned:
        _terminate_process(managed)
    with _LOCK:
        for process_id, _managed in owned:
            _PROCESSES.pop(process_id, None)
    return len(owned)


def register_process_tools(registry: Any) -> None:
    """Register the managed process lifecycle tools."""
    from tools.registry import ToolCategory

    registry.register(
        name="process_start",
        description="Starts a task-owned background process using an argument array, without shell expansion. Requires approval. Arguments: command (array of strings), cwd (workspace-relative directory, optional).",
        func=process_start,
        category=ToolCategory.AUTOMATION,
        risk_level="HIGH",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=15,
        schema={
            "type": "object",
            "properties": {
                "command": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
            },
            "required": ["command"],
        },
    )
    registry.register(
        name="process_logs",
        description="Reads bounded recent logs and state from a process started by this task. Arguments: process_id (str), max_chars (int, optional).",
        func=process_logs,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10,
        schema={
            "type": "object",
            "properties": {
                "process_id": {"type": "string"},
                "max_chars": {"type": "integer"},
            },
            "required": ["process_id"],
        },
    )
    registry.register(
        name="process_stop",
        description="Stops the process tree started by this task. Requires approval. Arguments: process_id (str).",
        func=process_stop,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=True,
        timeout=15,
        schema={
            "type": "object",
            "properties": {"process_id": {"type": "string"}},
            "required": ["process_id"],
        },
    )
