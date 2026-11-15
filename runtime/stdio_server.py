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
import time
from pathlib import Path
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
        self._run_started_at: Optional[float] = None
        self._run_metrics: Dict[str, Any] = {}
        self._run_metrics_lock = threading.Lock()
        self.session: Optional[RunSession] = None
        self.workspace: Optional[str] = None
        self._engineer = None

    @property
    def engineer(self):
        if self._engineer is None:
            from agent.autonomous_engineer import AutonomousEngineer
            self._engineer = AutonomousEngineer(Path(self.workspace))
        return self._engineer

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
            "run/resume": self._run_resume,
            "task/list": self._task_list,
            "approval/respond": self._approval_respond,
            "session/setPlanMode": self._set_plan_mode,
            "memory/list": self._memory_list,
            "memory/forget": self._memory_forget,
            "memory/clear": self._memory_clear,
            "memory/setEnabled": self._memory_set_enabled,
            "edit/undo": self._edit_undo,
            "engineering/impact": self._engineering_impact,
            "engineering/testSelection": self._engineering_test_selection,
            "engineering/plan": self._engineering_plan,
            "engineering/outline": self._engineering_outline,
            "engineering/unfold": self._engineering_unfold,
            "engineering/repl": self._engineering_repl,
            "engineering/probe": self._engineering_probe,
            "engineering/causal": self._engineering_causal,
            "engineering/synthesizePoc": self._engineering_synthesize_poc,
            "engineering/executePoc": self._engineering_execute_poc,
            "engineering/cpgQuery": self._engineering_cpg_query,
            "engineering/bountyRace": self._engineering_bounty_race,
            "checkpoint/create": self._checkpoint_create,
            "checkpoint/rewind": self._checkpoint_rewind,
            "checkpoint/list": self._checkpoint_list,
            "context/distill": self._context_distill,
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
        runtime_config = config.get("runtime") if isinstance(config.get("runtime"), dict) else {}
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
            "provider": type(provider).__name__,
            "settings": {
                "maxIterations": runtime_config.get("max_iterations"),
                "timeoutSeconds": runtime_config.get("timeout_seconds"),
                "sandbox": runtime_config.get("sandbox"),
                "confirmation": runtime_config.get("confirmation"),
            },
            "capabilities": {
                "planMode": True,
                "memory": True,
                "undo": True,
                "subagents": True,
                "resume": True,
                "engineeringIntelligence": True,
            },
        }

    def _run_start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        goal = params.get("goal")
        if not isinstance(goal, str) or not goal.strip():
            raise RpcError(INVALID_PARAMS, "goal must be a non-empty string.")
        if self._run_thread is not None and self._run_thread.is_alive():
            raise RpcError(BUSY, "A task is already running; cancel it or wait for run/finished.")
        if "planMode" in params:
            self._set_plan_mode({"enabled": params["planMode"]})
        attempts = params.get("attempts", 1)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 5:
            raise RpcError(INVALID_PARAMS, "attempts must be a whole number from 1 to 5.")
        import uuid

        run_id = f"task-{uuid.uuid4().hex[:8]}"
        goal = goal.strip()
        return self._begin_run(run_id, lambda: self.session.run(
            goal, target="localhost", scope=["localhost", "127.0.0.1"], session_id=run_id, attempts=attempts))

    def _run_resume(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Continues an unfinished task saved by an earlier run (durable_tasks.py), under the same id."""
        from agent.durable_tasks import JournalError, load_journal

        task_id = params.get("taskId")
        if not isinstance(task_id, str) or not task_id:
            raise RpcError(INVALID_PARAMS, "taskId must be a non-empty string.")
        if self._run_thread is not None and self._run_thread.is_alive():
            raise RpcError(BUSY, "A task is already running; cancel it or wait for run/finished.")
        try:
            journal = load_journal(task_id)
        except JournalError as error:
            raise RpcError(INVALID_PARAMS, str(error)) from None
        if journal.workspace != str(Path(self.workspace).resolve()):
            raise RpcError(INVALID_PARAMS, f"Task {task_id} belongs to another workspace.")
        if not journal.unfinished:
            raise RpcError(INVALID_PARAMS, f"Task {task_id} already finished ({journal.status}).")
        return self._begin_run(task_id, lambda: self.session.resume(task_id))

    def _task_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from agent.durable_tasks import list_journals

        saved = list_journals(Path(self.workspace), unfinished_only=True)
        return {"tasks": [{"taskId": item.session_id, "status": item.status, "turn": item.turn,
                           "goal": item.goal, "updatedAt": item.updated_at} for item in saved]}

    def _begin_run(self, run_id: str, work: Callable[[], Any]) -> Dict[str, Any]:
        with self._run_metrics_lock:
            self._run_started_at = time.monotonic()
            self._run_metrics = {
                "modelCalls": 0,
                "inputCount": 0,
                "outputCount": 0,
                "countsEstimated": False,
                "turns": 0,
            }
        self._run_thread = threading.Thread(target=self._run_task, args=(run_id, work), daemon=True)
        self._run_thread.start()
        return {"runId": run_id}

    def _run_task(self, run_id: str, work: Callable[[], Any]) -> None:
        assert self.session is not None
        outcome = work()
        self._deny_pending()
        if outcome.evidence_report:
            self.notify("run/evidence", {"runId": run_id, "report": outcome.evidence_report})
        with self._run_metrics_lock:
            metrics = dict(self._run_metrics)
            if self._run_started_at is not None:
                metrics["elapsedSeconds"] = round(time.monotonic() - self._run_started_at, 3)
            metrics["costUsd"] = None
        self.notify("run/finished", {
            "runId": run_id,
            "status": outcome.status,
            "finalAnswer": outcome.final_answer,
            "error": outcome.error,
            "metrics": metrics,
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
        payload = getattr(event, "payload", {}) or {}
        event_type = getattr(getattr(event, "type", None), "value", "")
        if event_type == "model.completed":
            with self._run_metrics_lock:
                self._run_metrics["modelCalls"] += 1
                self._run_metrics["inputCount"] += int(payload.get("prompt_tokens") or 0)
                self._run_metrics["outputCount"] += int(payload.get("output_tokens") or 0)
                self._run_metrics["countsEstimated"] = (
                    self._run_metrics["countsEstimated"] or bool(payload.get("tokens_estimated"))
                )
            return
        if event_type in ("assessment.completed", "assessment.stopped"):
            with self._run_metrics_lock:
                self._run_metrics["turns"] = int(payload.get("iterations") or 0)
            return
        method = FORWARDED_EVENTS.get(event_type)
        if not method:
            return
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

    def _engineering_impact(self, params: Dict[str, Any]) -> Dict[str, Any]:
        files = params.get("files", [])
        if not isinstance(files, list):
            raise RpcError(INVALID_PARAMS, "files must be a list of file paths.")
        prediction = self.engineer.impact_simulator.simulate(files)
        return prediction.to_dict()

    def _engineering_test_selection(self, params: Dict[str, Any]) -> Dict[str, Any]:
        files = params.get("files", [])
        if not isinstance(files, list):
            raise RpcError(INVALID_PARAMS, "files must be a list of file paths.")
        selected = self.engineer.test_selector.select_tests_for_files(files)
        return selected.to_dict()

    def _engineering_plan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        goal = params.get("goal", "")
        targets = params.get("files")
        plan = self.engineer.plan(goal, targets)
        return {
            "task": plan.task,
            "targetFiles": plan.target_files,
            "impact": plan.impact.to_dict(),
            "selectedTests": plan.selected_tests.to_dict(),
            "modelRecommended": plan.model_recommended,
            "steps": plan.steps,
        }

    def _engineering_outline(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file", "")
        outline = self.engineer.outline_file(file_path)
        return {
            "filePath": outline.file_path,
            "totalLines": outline.total_lines,
            "savingsPercent": outline.savings_percent,
            "symbols": [s.to_dict() for s in outline.symbols],
            "rendered": outline.render_skeleton(),
        }

    def _engineering_unfold(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file", "")
        symbol = params.get("symbol", "")
        return self.engineer.unfold_symbol(file_path, symbol)

    def _engineering_repl(self, params: Dict[str, Any]) -> Dict[str, Any]:
        code = params.get("code", "")
        res = self.engineer.eval_repl(code)
        return {
            "success": res.success,
            "output": res.output,
            "result": res.result,
            "error": res.error,
            "executionTimeMs": res.execution_time_ms,
        }

    def _engineering_probe(self, params: Dict[str, Any]) -> Dict[str, Any]:
        code = params.get("code", "")
        res = self.engineer.probe_code(code)
        return {
            "success": res.success,
            "returnValue": res.return_value,
            "exceptionType": res.exception_type,
            "exceptionMessage": res.exception_message,
            "report": res.format_diagnostic_report(),
        }

    def _engineering_causal(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file", "")
        lines = params.get("lines", [1])
        report = self.engineer.causal_history(file_path, lines)
        return {
            "filePath": report.file_path,
            "hasWorkarounds": report.has_historical_workarounds,
            "warnings": report.warnings,
            "summary": report.format_summary(),
        }

    def _engineering_synthesize_poc(self, params: Dict[str, Any]) -> Dict[str, Any]:
        issue = params.get("issue", "")
        target = params.get("targetFile") or params.get("target_file")
        art = self.engineer.synthesize_poc(issue, target)
        d = art.to_dict()
        d["artifactId"] = d.get("artifact_id")
        return d

    def _engineering_execute_poc(self, params: Dict[str, Any]) -> Dict[str, Any]:
        artifact_id = params.get("artifactId") or params.get("artifact_id", "")
        exec_res = self.engineer.execute_poc(artifact_id)
        return {
            "artifactId": exec_res.artifact_id,
            "exitCode": exec_res.exit_code,
            "isFailingExpectedly": exec_res.is_failing_expectedly,
            "isResolved": exec_res.is_resolved,
            "durationMs": exec_res.duration_ms,
            "diagnosticMessage": exec_res.diagnostic_message,
        }

    def _engineering_cpg_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        symbol = params.get("symbol", "")
        direction = params.get("direction", "callees")
        depth = params.get("depth", 3)
        res = self.engineer.query_cpg(symbol, direction, depth)
        return {"symbol": symbol, "direction": direction, "results": res}

    def _engineering_bounty_race(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("targetFile") or params.get("target_file", "")
        funcs = params.get("functions")
        max_rounds = params.get("maxRounds") or params.get("max_rounds", 1)
        report = self.engineer.run_bounty_challenge(target, funcs, max_rounds=max_rounds)
        return report.to_dict()

    def _checkpoint_create(self, params: Dict[str, Any]) -> Dict[str, Any]:
        step = params.get("stepId", 1)
        desc = params.get("description", "Checkpoint")
        files = params.get("files")
        node = self.engineer.create_checkpoint(step, desc, files)
        return node.to_dict()

    def _checkpoint_rewind(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", 1)
        ok, msg = self.engineer.rewind_checkpoint(target)
        return {"success": ok, "message": msg}

    def _checkpoint_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        timeline = self.engineer.checkpoints.list_timeline()
        return {"checkpoints": timeline}

    def _context_distill(self, params: Dict[str, Any]) -> Dict[str, Any]:
        turns = params.get("turns", [])
        files = params.get("files", [])
        distilled = self.engineer.distill_context(turns, files)
        return {
            "savingsPercent": distilled.savings_percent,
            "originalTokens": distilled.original_estimated_tokens,
            "distilledTokens": distilled.distilled_estimated_tokens,
            "prompt": distilled.format_as_prompt(),
        }

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


if __name__ == "__main__":
    serve_stdio()
