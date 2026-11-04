"""
Tool Execution Component for Buzzard Code.

Responsible for:
1. Validating tool availability and checking quarantine status
2. Validating arguments, schemas, and target scope via canonical AssessmentState
3. Checking tool action eligibility and preventing repeat failures
4. Managing state-scoped tool result caching
5. Executing tools in the sandbox runtime via the authoritative ToolRegistry
6. Classifying errors and quarantining dependency-missing tools
7. Producing structured ToolResult objects
8. Tracking execution timing and metric telemetry
"""

from __future__ import annotations

import re
import json
import time
import sys
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple, List, Set

from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    CandidateActionValidator,
    TargetValidator,
    HTTPState,
    ServiceState,
    VerificationStatus,
    FailureClassification,
    classify_failure,
)
from sandbox.container import ToolResult as ContainerToolResult, ToolErrorType
from events.bus import EventBus
from events.types import EventType, EventSeverity
from events.agent_event import AgentEvent, AgentEventType
from cli.renderer import console


@dataclass
class ToolExecutionResult:
    """
    Standardized execution result produced by the ToolExecutor.
    """
    success: bool
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    target: str = ""
    exit_code: int = 0
    error_type: str = "none"
    stdout: str = ""
    stderr: str = ""
    raw_output: str = ""
    duration: float = 0.0
    evidence_id: Optional[str] = None
    cache_hit: bool = False
    quarantined: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "target": self.target,
            "exit_code": self.exit_code,
            "error_type": self.error_type,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "raw_output": self.raw_output,
            "duration": self.duration,
            "evidence_id": self.evidence_id,
            "cache_hit": self.cache_hit,
            "quarantined": self.quarantined,
        }

    def __str__(self) -> str:
        return self.raw_output or self.stdout or (self.stderr if not self.success else "")


# Results depend on workspace state that edits and commands change, so a repeated call must
# run again. Re-running also means each repeated command gets its own operator approval.
WORKSPACE_STATE_TOOLS = frozenset({
    "terminal.execute", "file_read", "file.read", "file_view", "file.view", "file_search", "file.search",
    "directory_list", "todo_write", "git_status", "git.status", "git_diff", "git.diff", "git_log", "git.log",
})


class ToolExecutor:
    """
    Authoritative tool execution subsystem.
    Executes tools through ToolRegistry while enforcing scope, validation,
    caching, quarantine, and error classification.
    """

    def __init__(
        self,
        registry: Any,
        config: Optional[Dict[str, Any]] = None,
        event_bus: Optional[EventBus] = None,
        storage: Optional[Any] = None,
        assessment_logger: Optional[Any] = None,
    ):
        self.registry = registry
        self.config = config or {}
        self.event_bus = event_bus
        self.storage = storage
        self.assessment_logger = assessment_logger

        # Execution tracking & cache
        self.tool_cache: Dict[str, Dict[str, Any]] = {}
        self.tool_call_counts: Dict[str, int] = {}
        self.tool_latencies: List[float] = []
        self.tools_successful: int = 0
        self.tools_failed: int = 0
        self.duplicate_calls_blocked: int = 0
        self.cache_hits: int = 0

        self.max_same_tool: int = int(self.config.get("max_same_tool", 1))
        self.max_retries: int = int(self.config.get("max_retries", 2))
        self.max_actions: int = int(self.config.get("max_actions", 20))

    def _emit(
        self, 
        event_type: EventType, 
        data: Dict[str, Any], 
        severity: EventSeverity = EventSeverity.INFO, 
        assessment_id: Optional[str] = None
    ) -> None:
        """Helper to emit events if event_bus is present."""
        if self.event_bus:
            self.event_bus.emit(event_type, data, severity=severity, assessment_id=assessment_id)

    def is_tool_quarantined(self, tool_name: str) -> bool:
        """Checks if a tool is quarantined due to missing host/runtime dependencies."""
        if hasattr(self.registry, "quarantine"):
            return tool_name in self.registry.quarantine
        return False

    def is_tool_available(self, tool_name: str) -> bool:
        """Checks if a tool exists in the active ToolRegistry."""
        if hasattr(self.registry, "tools"):
            return tool_name in self.registry.tools
        return False

    def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        target: str = "",
        session_id: str = "",
        state: Optional[AssessmentState] = None,
        policy_engine: Optional[Any] = None,
        sandbox: Optional[Any] = None,
        knowledge: Optional[Any] = None,
        selector: Optional[Any] = None,
        ui_active: bool = False,
    ) -> ToolExecutionResult:
        """
        Executes a tool with complete pre-execution validation, quarantine checking,
        state-scoped caching, sandboxed dispatch, and error classification.
        """
        tool_start_time = time.time()
        self.tool_call_counts[tool_name] = self.tool_call_counts.get(tool_name, 0) + 1

        # 1. Quarantine & Availability Check
        if self.is_tool_quarantined(tool_name):
            tool_elapsed = time.time() - tool_start_time
            self.tools_failed += 1
            err_msg = f"TOOL QUARANTINED: Tool '{tool_name}' has been disabled because its runtime dependencies are missing in the sandbox."
            return ToolExecutionResult(
                success=False,
                tool_name=tool_name,
                arguments=arguments,
                target=target,
                exit_code=127,
                error_type="dependency_missing",
                stderr=err_msg,
                raw_output=err_msg,
                duration=tool_elapsed,
                quarantined=True
            )

        if not self.is_tool_available(tool_name):
            tool_elapsed = time.time() - tool_start_time
            self.tools_failed += 1
            err_msg = f"TOOL UNAVAILABLE: Tool '{tool_name}' is not registered in the toolchain schema."
            return ToolExecutionResult(
                success=False,
                tool_name=tool_name,
                arguments=arguments,
                target=target,
                exit_code=2,
                error_type="unavailable",
                stderr=err_msg,
                raw_output=err_msg,
                duration=tool_elapsed
            )

        # 2. Candidate Action Validation (Target bounds, schemas, unverified evidence)
        tool_args = dict(arguments or {})
        if state is not None:
            is_valid, val_reason, norm_args = CandidateActionValidator.validate_candidate(
                tool_name=tool_name,
                args=tool_args,
                state=state
            )
            if not is_valid:
                tool_elapsed = time.time() - tool_start_time
                self.tools_failed += 1
                err_type = "invalid_argument" if "ACTION REJECTED" in val_reason else "target_not_supported"

                # Record in state
                state.record_action_attempt(
                    tool_name=tool_name,
                    args=tool_args,
                    target=target,
                    success=False,
                    failure_type=FailureClassification.INVALID_ARGUMENT if err_type == "invalid_argument" else FailureClassification.TARGET_NOT_SUPPORTED,
                    output_snippet=val_reason,
                    reason="Candidate validation failed",
                    duration=tool_elapsed
                )

                return ToolExecutionResult(
                    success=False,
                    tool_name=tool_name,
                    arguments=tool_args,
                    target=target,
                    exit_code=2,
                    error_type=err_type,
                    stderr=val_reason,
                    raw_output=val_reason,
                    duration=tool_elapsed
                )
            tool_args = norm_args

        # 3. State-Scoped Caching & Duplicate Prevention
        clean_args = {k: v for k, v in tool_args.items() if v is not None and v != ""}
        cache_key = f"{tool_name}:{target}:{json.dumps(clean_args, sort_keys=True)}"

        cacheable = tool_name not in WORKSPACE_STATE_TOOLS
        if cacheable and cache_key in self.tool_cache:
            cached_entry = self.tool_cache[cache_key]
            age = time.time() - cached_entry["timestamp"]
            self.duplicate_calls_blocked += 1
            self.cache_hits += 1
            tool_elapsed = 0.001

            if not cached_entry.get("success", True):
                msg = f"[BLOCKED REPEAT FAILURE from {age:.1f}s ago]\n{cached_entry['output']}\nGuidance: Do not repeat failed tool calls. Move to the next target or conclude."
                return ToolExecutionResult(
                    success=False,
                    tool_name=tool_name,
                    arguments=tool_args,
                    target=target,
                    exit_code=cached_entry.get("exit_code", 1),
                    error_type=cached_entry.get("error_type", "repeated_failure"),
                    raw_output=msg,
                    duration=tool_elapsed,
                    cache_hit=True
                )
            else:
                msg = f"[CACHED RESULT from {age:.1f}s ago]\n{cached_entry['output']}"
                return ToolExecutionResult(
                    success=True,
                    tool_name=tool_name,
                    arguments=tool_args,
                    target=target,
                    exit_code=cached_entry.get("exit_code", 0),
                    error_type="none",
                    raw_output=msg,
                    stdout=msg,
                    duration=tool_elapsed,
                    cache_hit=True
                )

        # 4. Scope and Policy Evaluation
        if policy_engine is not None:
            is_permitted, reason = policy_engine.evaluate_tool_call(tool_name, tool_args)
            if not is_permitted:
                allow_override = False
                if self.config.get("allow_all_targets", False) or self.config.get("override_policy", False):
                    allow_override = True
                elif sys.stdin.isatty() and self.config.get("interactive", False):
                    console.print(f"\n[bold yellow]⚠ Policy Alert:[/] Target '[bold red]{tool_args.get('url') or tool_args.get('host') or reason}[/]' is outside authorized testing scope: {policy_engine.scope}")
                    try:
                        ans = input(f"Do you want to override policy and permit '{tool_name}' on '{tool_args.get('url') or tool_args.get('host')}'? (y/N): ").strip().lower()
                        if ans in ("y", "yes"):
                            allow_override = True
                            raw_target = tool_args.get('url') or tool_args.get('host')
                            if raw_target:
                                hostname = raw_target.split("://")[-1].split("/")[0].split(":")[0]
                                if hostname not in policy_engine.scope:
                                    policy_engine.scope.append(hostname)
                            console.print(f"[bold green]✓ Policy overridden by user. Target added to scope.[/bold green]\n")
                    except Exception:
                        allow_override = False

                if not allow_override:
                    tool_elapsed = time.time() - tool_start_time
                    denied_msg = f"POLICY DENIED: {reason}"
                    self.tools_failed += 1
                    self._emit(
                        EventType.POLICY_DENIED,
                        {"tool": tool_name, "reason": reason, "args": {k: str(v)[:100] for k, v in tool_args.items()}},
                        severity=EventSeverity.WARN,
                        assessment_id=session_id
                    )
                    return ToolExecutionResult(
                        success=False,
                        tool_name=tool_name,
                        arguments=tool_args,
                        target=target,
                        exit_code=126,
                        error_type="policy_denied",
                        stderr=denied_msg,
                        raw_output=denied_msg,
                        duration=tool_elapsed
                    )

        # 4.5. Stateful Request Context Resolution (Session & Auth Injection)
        if state is not None and tool_name in ("http.request", "web_fetch", "curl_probe", "whatweb_scan", "evaluate_security_headers", "check_cors", "check_csrf"):
            req_url = str(tool_args.get("url") or tool_args.get("target") or "")
            if req_url:
                auth_ctx = state.get_request_auth_context(req_url)
                if auth_ctx.get("headers"):
                    current_headers = tool_args.get("headers")
                    if current_headers is None:
                        tool_args["headers"] = dict(auth_ctx["headers"])
                    elif isinstance(current_headers, dict):
                        for hk, hv in auth_ctx["headers"].items():
                            # Only inject if model didn't explicitly override it
                            if not any(hk.lower() == k.lower() for k in current_headers):
                                current_headers[hk] = hv

        # 5. Sandbox Dispatch via Registry
        context = {
            "session_id": session_id,
            "storage_manager": self.storage,
            "sandbox": sandbox,
            "knowledge": knowledge,
            "selector": selector,
            "state": state,
        }

        exit_code = 0
        try:
            raw_result = self.registry.execute(tool_name, tool_args, context=context)
        except Exception as e:
            raw_result = f"Tool error: Error executing tool {tool_name}: {e}"
            exit_code = 1
            self._emit(
                EventType.TOOL_FAILED,
                {"tool": tool_name, "error": str(e)},
                severity=EventSeverity.ERROR,
                assessment_id=session_id
            )

        tool_elapsed = time.time() - tool_start_time
        self.tool_latencies.append(tool_elapsed)
        raw_res_str = str(raw_result)

        # 6. Structured Exit Code & Error Classification via ContainerToolResult
        container_res = ContainerToolResult.from_raw_output(raw_res_str, exit_code=exit_code, tool_name=tool_name)
        is_success = container_res.success
        exit_code = container_res.exit_code
        error_type = container_res.error_type.value

        # Auto-quarantine if dependency_missing
        if error_type == "dependency_missing" or exit_code == 127:
            if hasattr(self.registry, "quarantine"):
                self.registry.quarantine.add(tool_name)
                quarantined = True
            else:
                quarantined = False
        else:
            quarantined = False

        if is_success:
            self.tools_successful += 1
        else:
            self.tools_failed += 1

        # Synchronize with state & Ingest HTTP responses into session store
        if state is not None:
            # HTTP probes state tracking and session continuity
            if tool_name in ("http.request", "browser.open", "browser.goto", "whatweb_scan", "web_fetch", "curl_probe"):
                target_url = str(tool_args.get("url") or f"http://{target}/")
                if error_type == "connection_refused":
                    state.record_http_probe(target_url, HTTPState.REFUSED)
                elif is_success:
                    # Parse status, headers, and body from raw_res_str
                    status_code = 200
                    parsed_headers: Dict[str, str] = {}
                    body_str = ""

                    if "STATUS:" in raw_res_str:
                        sm = re.search(r"STATUS:\s*(\d+)", raw_res_str)
                        if sm:
                            status_code = int(sm.group(1))

                        hm = re.search(r"HEADERS:\s*\n(.*?)(?=\n\nBODY:|\n\nDURATION:|\Z)", raw_res_str, re.DOTALL)
                        if hm:
                            for line in hm.group(1).splitlines():
                                if ":" in line:
                                    hk, hv = line.split(":", 1)
                                    parsed_headers[hk.strip()] = hv.strip()

                        bm = re.search(r"BODY:\s*\n(.*?)(?=\n\nDURATION:|\Z)", raw_res_str, re.DOTALL)
                        if bm:
                            body_str = bm.group(1)
                    else:
                        body_str = raw_res_str

                    state.record_http_probe(target_url, HTTPState.RESPONDS, status_code=status_code)
                    state.ingest_session_http_response(
                        target_url=target_url,
                        status_code=status_code,
                        headers=parsed_headers,
                        body=body_str,
                        evidence_id=None
                    )

            # Record action attempt in canonical state
            state.record_action_attempt(
                tool_name=tool_name,
                args=tool_args,
                target=target,
                success=is_success,
                failure_type=classify_failure(raw_res_str, exit_code),
                output_snippet=raw_res_str,
                reason="Tool execution completed",
                duration=tool_elapsed
            )

        # 7. Populate Tool Cache
        if cacheable:
            self.tool_cache[cache_key] = {
                "output": raw_res_str,
                "timestamp": time.time(),
                "success": is_success,
                "exit_code": exit_code,
                "error_type": error_type
            }

        return ToolExecutionResult(
            success=is_success,
            tool_name=tool_name,
            arguments=tool_args,
            target=target,
            exit_code=exit_code,
            error_type=error_type,
            stdout=raw_res_str if is_success else "",
            stderr=raw_res_str if not is_success else "",
            raw_output=raw_res_str,
            duration=tool_elapsed,
            cache_hit=False,
            quarantined=quarantined
        )
