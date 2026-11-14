"""
Thin JSON-RPC client library for the Buzzard Code runtime protocol (roadmap F6).

Connects to `buzzard serve --stdio` over stdin/stdout, sending JSON-RPC 2.0 requests
and receiving asynchronous notifications and responses.

Can be used by:
- IDE plugins (JetBrains, NeoVim, Emacs)
- Desktop GUI applications (Buzzard Go)
- Automated CI scripts and test harnesses
"""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

DEFAULT_PROTOCOL_VERSION = "1.0"


class RpcClientError(Exception):
    """Raised when an RPC call returns an error object."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


class BuzzardRuntimeClient:
    """
    Client for `buzzard serve --stdio`.
    Spawns a child process and coordinates bidirectional JSON-RPC 2.0.
    """

    def __init__(
        self,
        command: Optional[List[str]] = None,
        workspace: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Union[str, Path]] = None,
    ):
        self.command = command or [sys.executable, "-m", "cli.main", "serve", "--stdio"]
        self.workspace = str(Path(workspace).resolve()) if workspace else None
        self.env = env
        self.cwd = Path(cwd or (workspace if workspace else Path.cwd())).resolve()

        self.process: Optional[subprocess.Popen] = None
        self._next_id = 0
        self._id_lock = threading.Lock()

        # Pending request tracking: id -> (threading.Event, response_holder)
        self._pending_requests: Dict[int, Tuple[threading.Event, List[Dict[str, Any]]]] = {}
        self._pending_lock = threading.Lock()

        # Notification handlers: method -> list of callables
        self._handlers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._handlers_lock = threading.Lock()

        # All received notifications queue for sequential waiters
        self._notifications: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        self._read_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self.stderr_lines: List[str] = []
        self._is_closed = threading.Event()

    def start(self) -> None:
        """Start the stdio runtime child process and listener threads."""
        if self.process is not None:
            return

        run_env = os.environ.copy()
        if self.env:
            run_env.update(self.env)

        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=run_env,
            cwd=str(self.cwd),
        )

        self._read_thread = threading.Thread(target=self._reader_loop, daemon=True, name="buzzard-rpc-reader")
        self._read_thread.start()

        self._stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True, name="buzzard-rpc-stderr")
        self._stderr_thread.start()

        if self.workspace:
            self.initialize(self.workspace)

    def _reader_loop(self) -> None:
        """Reads stdout lines from child process and dispatches responses or notifications."""
        assert self.process is not None and self.process.stdout is not None
        try:
            for line in self.process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception as e:
                    logger.warning("Failed to parse JSON line from runtime: %r (%s)", line, e)
                    continue

                if not isinstance(msg, dict):
                    continue

                # Check if it's a response to a pending request
                msg_id = msg.get("id")
                if msg_id is not None and isinstance(msg_id, int):
                    with self._pending_lock:
                        pending = self._pending_requests.get(msg_id)
                    if pending:
                        event, container = pending
                        container.append(msg)
                        event.set()
                        continue

                # Otherwise it's a notification from the server
                method = msg.get("method")
                if method:
                    self._notifications.put(msg)
                    params = msg.get("params", {})
                    with self._handlers_lock:
                        handlers = list(self._handlers.get(method, []))
                        all_handlers = list(self._handlers.get("*", []))
                    for h in handlers + all_handlers:
                        # Dispatch handlers in separate thread to avoid deadlocking the reader loop
                        # if the handler issues another synchronous RPC request (e.g. approval/respond)
                        threading.Thread(
                            target=self._run_handler_safe,
                            args=(h, method, params),
                            daemon=True
                        ).start()
        except Exception:
            pass
        finally:
            self._is_closed.set()
            # Unblock any waiters
            with self._pending_lock:
                for event, _ in self._pending_requests.values():
                    event.set()

    def _run_handler_safe(self, handler: Callable[[Dict[str, Any]], None], method: str, params: Dict[str, Any]) -> None:
        try:
            handler(params)
        except Exception as e:
            logger.exception("Error in notification handler for %s: %s", method, e)

    def _stderr_loop(self) -> None:
        """Drains stderr continually to prevent OS pipe deadlocks."""
        assert self.process is not None and self.process.stderr is not None
        try:
            for line in self.process.stderr:
                self.stderr_lines.append(line)
        except Exception:
            pass

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 60.0) -> Any:
        """Send a JSON-RPC 2.0 request and wait synchronously for the response."""
        if self.process is None or self.process.stdin is None or self._is_closed.is_set():
            raise RpcClientError(-32000, "Runtime process is not running or has closed.")

        with self._id_lock:
            self._next_id += 1
            req_id = self._next_id

        event = threading.Event()
        container: List[Dict[str, Any]] = []
        with self._pending_lock:
            self._pending_requests[req_id] = (event, container)

        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params if params is not None else {},
        }
        raw = json.dumps(payload) + "\n"

        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            with self._pending_lock:
                self._pending_requests.pop(req_id, None)
            raise RpcClientError(-32000, f"Failed to send request: {e}")

        # Wait for response
        finished = event.wait(timeout=timeout)
        with self._pending_lock:
            self._pending_requests.pop(req_id, None)

        if not finished:
            raise RpcClientError(-32000, f"Request '{method}' timed out after {timeout}s.")

        if not container:
            raise RpcClientError(-32000, "No response received from runtime (process closed).")

        resp = container[0]
        if "error" in resp:
            err = resp["error"]
            raise RpcClientError(err.get("code", -32603), err.get("message", "Unknown error"), err.get("data"))

        return resp.get("result")

    def on(self, method: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Register a notification handler (e.g. 'run/delta', 'tool/started', '*')."""
        with self._handlers_lock:
            self._handlers.setdefault(method, []).append(handler)

    def wait_for_notification(self, method: str, timeout: float = 30.0) -> Dict[str, Any]:
        """Wait for a specific notification method from the queue."""
        deadline = time.time() + timeout
        skipped: List[Dict[str, Any]] = []
        try:
            while time.time() < deadline:
                remaining = max(0.05, deadline - time.time())
                try:
                    msg = self._notifications.get(timeout=remaining)
                    if msg.get("method") == method:
                        return msg.get("params", {})
                    skipped.append(msg)
                except queue.Empty:
                    break
        finally:
            for s in skipped:
                self._notifications.put(s)
        raise TimeoutError(f"Timed out waiting for notification '{method}'.")

    # -- High-level Protocol Methods -----------------------------------------------

    def initialize(self, workspace: Union[str, Path], protocol_version: str = DEFAULT_PROTOCOL_VERSION) -> Dict[str, Any]:
        """Initialize workspace and negotiate protocol version."""
        res = self.request("initialize", {
            "protocolVersion": protocol_version,
            "workspace": str(Path(workspace).resolve()),
        })
        self.workspace = str(Path(workspace).resolve())
        return res

    def start_run(self, goal: str, plan_mode: bool = False, attempts: int = 1) -> str:
        """Start a new task run. Returns runId."""
        res = self.request("run/start", {
            "goal": goal,
            "planMode": plan_mode,
            "attempts": attempts,
        })
        return res.get("runId", "")

    def cancel_run(self) -> bool:
        """Cancel the currently active run."""
        res = self.request("run/cancel")
        return bool(res.get("cancelled", False))

    def list_tasks(self) -> List[Dict[str, Any]]:
        """List unfinished tasks for the current workspace."""
        res = self.request("task/list")
        return res.get("tasks", [])

    def resume_run(self, task_id: str) -> str:
        """Resume a saved task session. Returns runId."""
        res = self.request("run/resume", {"taskId": task_id})
        return res.get("runId", "")

    def respond_approval(self, request_id: str, decision: str = "allow") -> bool:
        """
        Respond to an approval request.
        decision must be 'allow', 'allow_session', or 'deny'.
        """
        res = self.request("approval/respond", {
            "requestId": request_id,
            "decision": decision,
        })
        return bool(res.get("accepted", False))

    def set_plan_mode(self, enabled: bool) -> bool:
        """Toggle plan mode on or off."""
        res = self.request("session/setPlanMode", {"enabled": enabled})
        return bool(res.get("planMode", False))

    def list_memory(self) -> Dict[str, Any]:
        """List project memory items."""
        return self.request("memory/list")

    def forget_memory(self, number: int) -> str:
        """Forget a specific memory item by 1-based index."""
        res = self.request("memory/forget", {"number": number})
        return res.get("message", "")

    def clear_memory(self) -> str:
        """Clear all project memory."""
        res = self.request("memory/clear")
        return res.get("message", "")

    def set_memory_enabled(self, enabled: bool) -> str:
        """Enable or disable project memory."""
        res = self.request("memory/setEnabled", {"enabled": enabled})
        return res.get("message", "")

    def undo_edit(self) -> str:
        """Undo the last edit operation."""
        res = self.request("edit/undo")
        return res.get("message", "")

    def shutdown(self) -> bool:
        """Send clean shutdown request and close process."""
        try:
            res = self.request("shutdown", timeout=5.0)
            ok = bool(res.get("ok", False))
        except Exception:
            ok = False
        self.close()
        return ok

    def close(self) -> None:
        """Terminate child process and wait for threads."""
        self._is_closed.set()
        if self.process is not None:
            try:
                if self.process.stdin:
                    self.process.stdin.close()
            except Exception:
                pass
            try:
                self.process.terminate()
                self.process.wait(timeout=2.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    def __enter__(self) -> "BuzzardRuntimeClient":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def run_client_cli(goal: str, workspace: str = ".", auto_approve: bool = True) -> int:
    """Convenience CLI function to run a goal over the runtime client."""
    client = BuzzardRuntimeClient(workspace=workspace)
    client.start()

    print(f"Connecting to Buzzard runtime for workspace: {workspace}...")

    def on_delta(params: Dict[str, Any]) -> None:
        text = params.get("text", "")
        sys.stdout.write(text)
        sys.stdout.flush()

    def on_tool(params: Dict[str, Any]) -> None:
        tool = params.get("tool")
        args = params.get("arguments", {})
        print(f"\n[Tool: {tool}] {args}")

    def on_approval(params: Dict[str, Any]) -> None:
        req_id = params.get("requestId", "")
        tool = params.get("tool", "")
        print(f"\n[Approval Requested] {tool} (id: {req_id})")
        if auto_approve:
            print("Auto-approving...")
            client.respond_approval(req_id, "allow")
        else:
            print("Denying (non-interactive)...")
            client.respond_approval(req_id, "deny")

    client.on("run/delta", on_delta)
    client.on("tool/started", on_tool)
    client.on("approval/requested", on_approval)

    try:
        run_id = client.start_run(goal=goal)
        print(f"Started run: {run_id}")
        finished = client.wait_for_notification("run/finished", timeout=120.0)
        status = finished.get("status")
        print(f"\nRun finished with status: {status}")
        return 0 if status == "completed" else 1
    finally:
        client.shutdown()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m runtime.client <goal> [workspace]")
        sys.exit(1)
    target_goal = sys.argv[1]
    ws = sys.argv[2] if len(sys.argv) > 2 else "."
    sys.exit(run_client_cli(target_goal, workspace=ws))
