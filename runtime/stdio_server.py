"""
Headless Buzzard Code runtime: `buzzard serve --stdio`.

Speaks newline-delimited JSON-RPC 2.0 on stdin and stdout, for editor extensions and the
desktop app. The client starts this process itself, so there is no network listener and no
other process can connect. The protocol is described in docs/architecture/RUNTIME_PROTOCOL.md.

Guarantees:
- Approvals are decided by RunSession. A client only answers approval/requested questions;
  answering an unknown or already-answered request is an error, and a disconnect or cancel
  denies whatever is pending.
- Plan mode and the workspace boundary are enforced here, not by the client. The workspace is
  fixed by `initialize` and cannot change afterwards.
- Everything sent to the client passes through secret redaction.
- stdout carries protocol messages only; anything else the runtime prints goes to stderr.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from typing import Any, Callable, Dict, IO, Optional

from agent.run_session import ALLOW, ALLOW_SESSION, DECISIONS, DENY, ApprovalRequest, RunSession
from core.config import redact_secrets

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.0"
APPROVAL_POLL_SECONDS = 0.2

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
NOT_INITIALIZED = -32002
BUSY = -32001

FORWARDED_EVENTS = {"tool.started": "tool/started", "tool.completed": "tool/completed", "tool.failed": "tool/failed"}


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _PendingApproval:
    def __init__(self, request: ApprovalRequest):
        self.request = request
        self.decision: Optional[str] = None
        self.answered = threading.Event()


class StdioRuntimeServer:
    """One runtime for one workspace, driven by one client over a pair of streams."""

    def __init__(self, reader: IO[str], writer: IO[str], provider_factory: Optional[Callable[[Dict[str, Any]], Any]] = None):
        self._reader = reader
        self._writer = writer
        self._write_lock = threading.Lock()
        self._provider_factory = provider_factory
        self._pending: Dict[str, _PendingApproval] = {}
        self._pending_lock = threading.Lock()
        self._closed = threading.Event()
        self._run_thread: Optional[threading.Thread] = None
        self.session: Optional[RunSession] = None
        self.workspace: Optional[str] = None

    # -- transport -----------------------------------------------------------------------
    def _send(self, message: Dict[str, Any]) -> None:
        line = json.dumps(redact_secrets(message), default=str)
        with self._write_lock:
            try:
                self._writer.write(line + "\n")
                self._writer.flush()
            except (OSError, ValueError):
                self._closed.set()

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def serve(self) -> None:
        """Reads requests until the client closes stdin or calls shutdown."""
        try:
            for line in self._reader:
                if not line.strip():
                    continue
                self._handle_line(line)
                if self._closed.is_set():
                    break
        finally:
            self._close()

    def _handle_line(self, line: str) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self._send({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Invalid JSON."}})
            return
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            self._send({"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                        "error": {"code": INVALID_REQUEST, "message": "Expected a JSON-RPC 2.0 request."}})
            return
        request_id = message.get("id")
        params = message.get("params") or {}
        try:
            if not isinstance(params, dict):
                raise RpcError(INVALID_PARAMS, "params must be an object.")
            result = self._dispatch(message["method"], params)
        except RpcError as error:
            if request_id is not None:
                self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": error.code, "message": error.message}})
            return
        except Exception as error:  # report, never crash the runtime on one bad request
            logger.exception("Request %s failed", message.get("method"))
            if request_id is not None:
                self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": f"Internal error: {error}"}})
            return
        if request_id is not None:
            self._send({"jsonrpc": "2.0", "id": request_id, "result": result})

    # -- methods -------------------------------------------------------------------------
    def _dispatch(self, method: str, params: Dict[str, Any]) -> Any:
        if method == "initialize":
            return self._initialize(params)
        if method == "shutdown":
            return self._shutdown(params)
        if self.session is None:
            raise RpcError(NOT_INITIALIZED, "Call initialize first.")
        handlers = {
            "run/start": self._run_start,
            "run/cancel": self._run_cancel,
            "approval/respond": self._approval_respond,
            "session/setPlanMode": self._set_plan_mode,
            "memory/list": self._memory_list,
            "memory/forget": self._memory_forget,
            "memory/clear": self._memory_clear,
            "memory/setEnabled": self._memory_set_enabled,
            "edit/undo": self._edit_undo,
            "shutdown": self._shutdown,
        }
        handler = handlers.get(method)
        if handler is None:
            raise RpcError(METHOD_NOT_FOUND, f"Unknown method '{method}'.")
        return handler(params)

    def _initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.session is not None:
            raise RpcError(INVALID_REQUEST, "Already initialized; the workspace cannot change.")
        version = str(params.get("protocolVersion", ""))
        if version.split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
            raise RpcError(INVALID_PARAMS, f"Protocol version {version or '(none)'} is not supported; this runtime speaks {PROTOCOL_VERSION}.")
        workspace = params.get("workspace")
        if not isinstance(workspace, str) or not os.path.isdir(workspace):
            raise RpcError(INVALID_PARAMS, "workspace must be an existing folder.")

        from core.config import load_merged_config
        from events.bus import EventBus
        from storage.db import StorageManager
        from tools.filesystem import set_active_workspace
        from tools.registry import create_authoritative_registry

        self.workspace = set_active_workspace(workspace)
        config = {**load_merged_config(), "workspace": self.workspace}
        if self._provider_factory is not None:
            provider = self._provider_factory(config)
        else:
            from model.factory import get_model_provider
            provider = get_model_provider(config=config)
        bus = EventBus()
        bus.subscribe_all(self._forward_event)
        self.session = RunSession(
            provider=provider,
            registry=create_authoritative_registry(),
            storage=StorageManager(),
            config=config,
            ask_approval=self._ask_approval,
            on_delta=lambda text: self.notify("run/delta", {"text": text}),
            event_bus=bus,
        )
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {"name": "buzzard-code"},
            "workspace": self.workspace,
            "model": str(getattr(provider, "model_name", "unknown")),
            "capabilities": {"planMode": True, "memory": True, "undo": True, "subagents": True},
        }

    def _run_start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        goal = params.get("goal")
        if not isinstance(goal, str) or not goal.strip():
            raise RpcError(INVALID_PARAMS, "goal must be a non-empty string.")
        if self._run_thread is not None and self._run_thread.is_alive():
            raise RpcError(BUSY, "A task is already running; cancel it or wait for run/finished.")
        if "planMode" in params:
            self._set_plan_mode({"enabled": params["planMode"]})
        import uuid

        run_id = f"task-{uuid.uuid4().hex[:8]}"
        self._run_thread = threading.Thread(target=self._run_task, args=(goal.strip(), run_id), daemon=True)
        self._run_thread.start()
        return {"runId": run_id}

    def _run_task(self, goal: str, run_id: str) -> None:
        assert self.session is not None
        outcome = self.session.run(goal, target="localhost", scope=["localhost", "127.0.0.1"], session_id=run_id)
        self._deny_pending()
        if outcome.evidence_report:
            self.notify("run/evidence", {"runId": run_id, "report": outcome.evidence_report})
        self.notify("run/finished", {
            "runId": run_id,
            "status": outcome.status,
            "finalAnswer": outcome.final_answer,
            "error": outcome.error,
        })

    def _run_cancel(self, params: Dict[str, Any]) -> Dict[str, Any]:
        assert self.session is not None
        running = self._run_thread is not None and self._run_thread.is_alive()
        self.session.cancel()
        self._deny_pending()
        return {"cancelled": running}

    def _set_plan_mode(self, params: Dict[str, Any]) -> Dict[str, Any]:
        assert self.session is not None
        enabled = params.get("enabled")
        if not isinstance(enabled, bool):
            raise RpcError(INVALID_PARAMS, "enabled must be true or false.")
        self.session.plan_mode = enabled
        return {"planMode": enabled}

    # -- approvals -----------------------------------------------------------------------
    def _ask_approval(self, request: ApprovalRequest) -> str:
        """Runs on the task thread: asks the client and blocks until it answers or the run ends."""
        pending = _PendingApproval(request)
        with self._pending_lock:
            self._pending[request.request_id] = pending
        self.notify("approval/requested", {
            "requestId": request.request_id,
            "tool": request.tool_name,
            "arguments": request.arguments,
            "riskClass": request.risk_class,
            "canAllowForSession": request.session_rule is not None,
        })
        assert self.session is not None
        while not pending.answered.wait(APPROVAL_POLL_SECONDS):
            if self._closed.is_set() or self.session.stop_event.is_set():
                break
        with self._pending_lock:
            self._pending.pop(request.request_id, None)
        return pending.decision if pending.decision in DECISIONS else DENY

    def _approval_respond(self, params: Dict[str, Any]) -> Dict[str, Any]:
        request_id = params.get("requestId")
        decision = params.get("decision")
        if decision not in DECISIONS:
            raise RpcError(INVALID_PARAMS, f"decision must be one of {', '.join(DECISIONS)}.")
        with self._pending_lock:
            pending = self._pending.get(request_id) if isinstance(request_id, str) else None
            if pending is None or pending.answered.is_set():
                raise RpcError(INVALID_PARAMS, "No approval is waiting with that requestId.")
            if decision == ALLOW_SESSION and pending.request.session_rule is None:
                decision = ALLOW  # this action can only ever be approved once
            pending.decision = decision
            pending.answered.set()
        return {"accepted": True}

    def _deny_pending(self) -> None:
        with self._pending_lock:
            for pending in self._pending.values():
                if not pending.answered.is_set():
                    pending.decision = DENY
                    pending.answered.set()

    # -- events --------------------------------------------------------------------------
    def _forward_event(self, event: Any) -> None:
        method = FORWARDED_EVENTS.get(getattr(getattr(event, "type", None), "value", ""))
        if not method:
            return
        payload = getattr(event, "payload", {}) or {}
        params: Dict[str, Any] = {"tool": payload.get("tool"), "runId": getattr(event, "assessment_id", None)}
        if method == "tool/started":
            params["arguments"] = payload.get("args", {})
        else:
            params.update(durationMs=payload.get("duration_ms"), exitCode=payload.get("exit_code"),
                          preview=str(payload.get("result_preview", ""))[:500])
        self.notify(method, params)

    # -- memory and undo -----------------------------------------------------------------
    def _memory_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from agent.project_memory import is_enabled, load_notes
        return {"enabled": is_enabled(), "notes": [{"text": n["text"], "source": n["source"]} for n in load_notes()]}

    def _memory_forget(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from agent.project_memory import ProjectMemoryError, forget_note
        number = params.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            raise RpcError(INVALID_PARAMS, "number must be an integer from memory/list (1-based).")
        try:
            return {"message": forget_note(number)}
        except ProjectMemoryError as error:
            raise RpcError(INVALID_PARAMS, str(error)) from None

    def _memory_clear(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from agent.project_memory import clear_notes
        return {"message": clear_notes()}

    def _memory_set_enabled(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from agent.project_memory import set_enabled
        enabled = params.get("enabled")
        if not isinstance(enabled, bool):
            raise RpcError(INVALID_PARAMS, "enabled must be true or false.")
        return {"message": set_enabled(enabled)}

    def _edit_undo(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from tools.filesystem import undo_last_edit
        if self._run_thread is not None and self._run_thread.is_alive():
            raise RpcError(BUSY, "Undo is not available while a task is running.")
        return {"message": undo_last_edit()}

    def _shutdown(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self._closed.set()
        return {"ok": True}

    def _close(self) -> None:
        self._closed.set()
        if self.session is not None:
            self.session.cancel()
        self._deny_pending()
        if self._run_thread is not None:
            self._run_thread.join(timeout=10)


def _claim_protocol_streams() -> "tuple[IO[str], IO[str]]":
    """
    Moves the protocol onto private copies of stdin and stdout, then points the process's own
    stdin at the null device and its stdout at stderr. Child processes (git, test runners)
    inherit those, so they can neither block on nor write into the protocol stream.
    """
    sys.stdout.flush()
    # newline="\n" keeps one protocol message per line on Windows too (no \r\n translation)
    reader = os.fdopen(os.dup(0), "r", encoding="utf-8", newline="\n")
    writer = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n")
    null_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(null_fd, 0)
    os.dup2(2, 1)
    os.close(null_fd)
    sys.stdin = open(os.devnull, "r", encoding="utf-8")
    sys.stdout = sys.stderr
    return reader, writer


def serve_stdio(provider_factory: Optional[Callable[[Dict[str, Any]], Any]] = None) -> None:
    """Entry point for `buzzard serve --stdio`: protocol on stdout, everything else on stderr."""
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    reader, writer = _claim_protocol_streams()
    StdioRuntimeServer(reader, writer, provider_factory=provider_factory).serve()
