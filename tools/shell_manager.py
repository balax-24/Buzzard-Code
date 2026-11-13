"""Approval-gated persistent shell sessions scoped to one coding task."""

from __future__ import annotations

import logging
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandbox.container import (
    DANGEROUS_COMMAND_PATTERNS,
    _scrubbed_host_env,
    _terminate_process_tree,
)
from tools.filesystem import get_active_workspace

logger = logging.getLogger(__name__)

MAX_SHELL_SESSIONS = 16
MAX_COMMAND_CHARS = 16_000
MAX_OUTPUT_BYTES = 128_000
MAX_TIMEOUT_SECONDS = 120.0
_SHELLS_LOCK = threading.RLock()


@dataclass
class _ShellSession:
    session_id: str
    process: subprocess.Popen[bytes]
    flavor: str
    output_queue: queue.Queue[bytes | None] = field(default_factory=queue.Queue)
    pending_output: bytearray = field(default_factory=bytearray)
    command_lock: threading.Lock = field(default_factory=threading.Lock)
    reader: threading.Thread | None = None


_SHELLS: dict[str, _ShellSession] = {}


def _shell_command() -> tuple[list[str], str]:
    if os.name == "nt":
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell:
            return [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"], "powershell"
        command_processor = os.environ.get("COMSPEC") or shutil.which("cmd.exe")
        if command_processor:
            return [command_processor, "/Q", "/D"], "cmd"
        raise RuntimeError("No supported command shell (PowerShell or cmd.exe) is available.")
    bash = shutil.which("bash")
    if bash:
        return [bash, "--noprofile", "--norc"], "bash"
    shell = shutil.which("sh")
    if shell:
        return [shell], "sh"
    raise RuntimeError("No supported command shell (bash or sh) is available.")


def _read_shell_output(shell: _ShellSession) -> None:
    stream = shell.process.stdout
    if stream is None:
        shell.output_queue.put(None)
        return
    try:
        while chunk := stream.read1(4096):
            shell.output_queue.put(chunk)
    except OSError:
        logger.debug("Persistent shell output pipe closed for task %s", shell.session_id)
    finally:
        stream.close()
        shell.output_queue.put(None)


def _new_shell(session_id: str) -> _ShellSession:
    command, flavor = _shell_command()
    workspace = Path(get_active_workspace()).resolve(strict=True)
    if not workspace.is_dir():
        raise RuntimeError("The active workspace is not a directory.")
    process = subprocess.Popen(
        command,
        cwd=workspace,
        env=_scrubbed_host_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        close_fds=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        start_new_session=os.name != "nt",
    )
    shell = _ShellSession(session_id=session_id, process=process, flavor=flavor)
    shell.reader = threading.Thread(
        target=_read_shell_output,
        args=(shell,),
        name=f"buzzard-shell-output-{session_id}",
        daemon=True,
    )
    try:
        shell.reader.start()
    except RuntimeError:
        _terminate_process_tree(process)
        raise
    return shell


def _get_shell(session_id: str) -> _ShellSession:
    with _SHELLS_LOCK:
        shell = _SHELLS.get(session_id)
        if shell is not None and shell.process.poll() is None:
            return shell
        if shell is not None:
            _SHELLS.pop(session_id, None)
            _stop_shell(shell)
        if len(_SHELLS) >= MAX_SHELL_SESSIONS:
            raise RuntimeError(f"At most {MAX_SHELL_SESSIONS} persistent shell sessions may be active.")
        shell = _new_shell(session_id)
        _SHELLS[session_id] = shell
        return shell


def _stop_shell(shell: _ShellSession) -> None:
    if shell.process.poll() is None:
        _terminate_process_tree(shell.process)
    if shell.process.stdin is not None:
        shell.process.stdin.close()
    if shell.reader is not None:
        shell.reader.join(timeout=1.0)


def _discard_shell(session_id: str, shell: _ShellSession) -> None:
    with _SHELLS_LOCK:
        if _SHELLS.get(session_id) is shell:
            _SHELLS.pop(session_id, None)
    _stop_shell(shell)


def _append_bounded(output: bytearray, data: bytes) -> None:
    output.extend(data)
    excess = len(output) - MAX_OUTPUT_BYTES
    if excess > 0:
        del output[:excess]


def _command_envelope(command: str, flavor: str, nonce: str) -> tuple[bytes, bytes]:
    marker = f"__BUZZARD_SHELL_{nonce}__:".encode("ascii")
    if flavor == "bash":
        script = f"{command}\n__buzzard_status=$?\nprintf '\\n{marker.decode()}%s\\n' \"$__buzzard_status\"\n"
    elif flavor == "sh":
        script = f"{command}\n__buzzard_status=$?\nprintf '\\n{marker.decode()}%s\\n' \"$__buzzard_status\"\n"
    elif flavor == "powershell":
        script = (
            f"{command}\n$__buzzard_status = if ($?) {{ 0 }} else {{ 1 }}\n"
            f"[Console]::Out.WriteLine('{marker.decode()}' + $__buzzard_status)\n"
        )
    else:
        script = f"{command}\n@echo {marker.decode()}%ERRORLEVEL%\n"
    return script.encode("utf-8"), marker


def _execute_in_shell(shell: _ShellSession, command: str, timeout: float) -> tuple[int, str]:
    if shell.process.stdin is None:
        raise RuntimeError("Persistent shell input is unavailable.")
    nonce = uuid.uuid4().hex
    script, marker = _command_envelope(command, shell.flavor, nonce)
    output = bytearray()
    scan = shell.pending_output
    shell.pending_output = bytearray()
    deadline = time.monotonic() + timeout
    shell.process.stdin.write(script)
    shell.process.stdin.flush()

    while True:
        marker_start = scan.find(marker)
        if marker_start >= 0:
            status_end = scan.find(b"\n", marker_start + len(marker))
            if status_end >= 0:
                _append_bounded(output, bytes(scan[:marker_start]))
                raw_status = bytes(scan[marker_start + len(marker):status_end]).strip()
                try:
                    exit_code = int(raw_status)
                except ValueError as error:
                    raise RuntimeError("Persistent shell returned an invalid command status.") from error
                shell.pending_output.extend(scan[status_end + 1:])
                return exit_code, bytes(output).decode("utf-8", errors="replace")

        retain = len(marker) + 16
        if len(scan) > retain:
            flushed = len(scan) - retain
            _append_bounded(output, bytes(scan[:flushed]))
            del scan[:flushed]

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _append_bounded(output, bytes(scan))
            raise subprocess.TimeoutExpired(command, timeout, output=bytes(output))
        try:
            chunk = shell.output_queue.get(timeout=remaining)
        except queue.Empty as error:
            _append_bounded(output, bytes(scan))
            raise subprocess.TimeoutExpired(command, timeout, output=bytes(output)) from error
        if chunk is None:
            _append_bounded(output, bytes(scan))
            raise RuntimeError("Persistent shell exited before returning a command status.")
        scan.extend(chunk)


def shell_execute(command: str, timeout: float = 30.0, session_id: str = "") -> str:
    """Run one approved command in a task's persistent shell, preserving cwd and environment."""
    if not session_id:
        return "TOOL ERROR: shell_execute requires a task session."
    if not isinstance(command, str) or not command.strip() or "\x00" in command:
        return "TOOL ERROR: command must be non-empty and contain no NUL characters."
    if len(command) > MAX_COMMAND_CHARS:
        return f"TOOL ERROR: command exceeds the {MAX_COMMAND_CHARS}-character limit."
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        return f"TOOL ERROR: timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS} seconds."

    try:
        from security.kill_switch import KillSwitch

        if KillSwitch.get_instance().is_triggered():
            return "TOOL ERROR: execution blocked because the kill switch is active."
    except Exception as error:
        logger.exception("Could not check kill switch before persistent shell execution")
        return f"TOOL ERROR: execution blocked because kill switch state could not be checked: {error}"

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern.search(command):
            return f"TOOL ERROR: command matches restricted dangerous pattern ({pattern.pattern})."

    try:
        shell = _get_shell(session_id)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        return f"TOOL ERROR: could not start persistent shell: {error}"

    try:
        with shell.command_lock:
            exit_code, output = _execute_in_shell(shell, command, float(timeout))
    except subprocess.TimeoutExpired as error:
        partial = error.output.decode("utf-8", errors="replace") if isinstance(error.output, bytes) else ""
        _discard_shell(session_id, shell)
        return f"TOOL ERROR: command timed out after {timeout:g} seconds; the shell session was stopped.\n{partial}".rstrip()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        _discard_shell(session_id, shell)
        return f"TOOL ERROR: persistent shell failed: {error}"

    if exit_code != 0:
        return f"TOOL ERROR: command exited with code {exit_code}.\n{output}".rstrip()
    return f"Exit code: 0\n{output}".rstrip()


def cleanup_session_shells(session_id: str) -> int:
    """Terminate and forget every persistent shell owned by a task."""
    with _SHELLS_LOCK:
        owned = [shell for shell in _SHELLS.values() if shell.session_id == session_id]
        for shell in owned:
            _SHELLS.pop(session_id, None)
    for shell in owned:
        _stop_shell(shell)
    return len(owned)


def register_shell_tool(registry: Any) -> None:
    """Register the approval-gated persistent shell command tool."""
    from tools.registry import ToolCategory

    registry.register(
        name="shell_execute",
        description="Runs an approved command in this task's persistent host shell. `cd` and environment changes persist between calls. Commands start in the active workspace; this is not an isolation boundary. Arguments: command (str), timeout (seconds, optional).",
        func=shell_execute,
        category=ToolCategory.AUTOMATION,
        risk_level="HIGH",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=MAX_TIMEOUT_SECONDS + 5,
        schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "number"},
            },
            "required": ["command"],
        },
    )
