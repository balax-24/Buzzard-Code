import json
import re
import uuid
import time
import threading
import sys
import os
import datetime
from typing import List, Dict, Any, Optional, Tuple
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.markdown import Markdown
from model.provider import ModelProvider
from model.schemas import TaskStatus
from tools.registry import create_authoritative_registry, ToolRegistry
from tools.basic import register_basic_tools
from tools.evidence import register_evidence_tools
from tools.security import register_security_tools
from tools.browser import register_browser_tools
from tools.http import register_http_tools
from tools.http_suite import register_http_suite_tools
from tools.filesystem import register_filesystem_tools
from tools.git_tools import register_git_tools
from tools.source_audit import register_source_audit_tools
from tools.manifest_suite import register_manifest_tools
from tools.attack import register_attack_tools
from tools.arsenal import register_arsenal_tools
from tools.knowledge import register_knowledge_tools
from intelligence.asset_graph import AssetGraph
from intelligence.selector import ToolSelector
from intelligence.evidence_parser import EvidenceParser, AttackSurfaceSnapshot
from intelligence.evidence_ingestor import EvidenceIngestor, EvidenceItem, FactualClaim, ClaimStatus
from verification.finding_verifier import FindingVerifier
from reports.report_generator import ReportGenerator, clean_report_content, parse_inline_findings
from model.response_parser import parse_decision_summary
from intelligence.dynamic_tool_selector import DynamicToolSelector
from intelligence.failure_diagnostics import FailureDiagnosticsEngine
from model.decision_contract import ModelDecisionParser, ModelDecision, DecisionType
from storage.db import StorageManager
from sandbox.container import (
    get_sandbox,
    ApprovedHostSandbox,
    BlockedSandbox,
    get_security_sandbox_image,
    DockerSandbox,
    ToolResult,
    ToolErrorType
)
from security.policy import PolicyEngine
from cli.prompts import build_system_prompt, build_user_prompt
from agent.skills import SkillManager
from events.bus import EventBus
from events.types import Event, EventType, EventSeverity
from events.store import EventStore
from agent.budget import BudgetTracker, BudgetConfig
from remediation.guidance import RemediationGenerator
from events.agent_event import AgentEvent, AgentEventType
from storage.assessment_logger import AssessmentLogger, summarize_tool_output
from agent.planner import Planner, PlannerDecision
from agent.tool_executor import ToolExecutor, ToolExecutionResult
from agent.context_manager import ContextManager
from agent.loop_controller import LoopRecoveryController, StuckLoopDetector
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import HypothesisEngine
from agent.completion_engine import CompletionEngine, BudgetSnapshot, GuardAction
from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ObjectiveStatus,
    VerificationPredicates,
    ExploitStatus,
    HypothesisStatus,
    ServiceState,
    SessionVerificationStatus,
)
from cli.renderer import (
    console,
    render_execution_metrics,
    render_performance_profile
)
from cli.dashboard import THEMES, DashboardState, build_dashboard_layout


from model.tool_calls import repair_tool_call_pairs

from verification.coding_verifier import task_requires_edits

from core.usage import estimate_tokens, usage_to_metrics


MAX_REPEATED_TURNS = 3


class _NullLive:
    """Stands in for Rich Live when a host UI owns the terminal."""

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def update(self, *_args: Any, **_kwargs: Any) -> None:
        pass


NATIVE_TOOLS_GUIDANCE = (
    "\n\nTOOL CALLING: Use the API's native tool calling instead of the XML format above. "
    "When the work is verified, reply with your summary and no tool call to finish.\n"
)

# Tools described to the model on coding tasks. This narrows the prompt only; it is not a
# permission boundary, since dispatch still goes through the full registry and PolicyEngine.
CODING_TOOL_NAMES = frozenset({
    "directory_list", "file_search", "file_read", "file_view", "file_edit", "file_write",
    "terminal.execute", "git_status", "git_diff", "git_log", "todo_write",
})


class AgentLoop:
    """
    Manages the autonomous execution loop of the agent.
    """
    def __init__(
        self,
        provider: ModelProvider,
        registry: Optional[ToolRegistry] = None,
        storage_manager: Optional[StorageManager] = None,
        max_iterations: int = 15,
        native_tools: Optional[bool] = None,
        config: Optional[Dict[str, Any]] = None,
        event_bus: Optional[EventBus] = None,
        on_stream_delta: Optional[Any] = None,
        stop_event: Optional[threading.Event] = None,
        quiet: bool = False,
        model_router: Optional[Any] = None,
        predicates: Optional[VerificationPredicates] = None,
        assessment_state: Optional[AssessmentState] = None,
        approval_callback: Optional[Any] = None,
    ):
        self.provider = provider
        self.approval_callback = approval_callback
        self.on_stream_delta = on_stream_delta
        self.stop_event = stop_event or threading.Event()
        self.quiet = quiet
        self.config = config or {}
        self.native_tools = self._resolve_native_tools(native_tools)
        self.registry = registry or create_authoritative_registry()
        register_git_tools(self.registry)
        self.storage = storage_manager or StorageManager()
        self.evidence_parser = EvidenceParser()
        self.assessment_logger = AssessmentLogger()
        pred = predicates or self.config.get("predicates")
        if assessment_state is not None:
            self.assessment_state = assessment_state
        elif pred is not None:
            self.assessment_state = AssessmentState(predicates=pred)
        else:
            self.assessment_state = AssessmentState()
        self.canonical_state: Optional[AssessmentState] = self.assessment_state
        # --- Security knowledge graph + hypothesis-driven tool selection ---
        self.knowledge = AssetGraph(state=self.canonical_state)
        self.selector = ToolSelector()
        self.model_router = model_router
        self.evidence_ingestor = EvidenceIngestor(storage=self.storage, assessment_logger=self.assessment_logger)
        self.finding_verifier = FindingVerifier(storage=self.storage)
        self.report_generator = ReportGenerator(storage=self.storage)
        self._attack_surface: Optional[AttackSurfaceSnapshot] = None
        self.max_iterations = max_iterations
        self.plan = ["Perform security audit"]  # default dynamic plan
        self.observations = []
        self.candidate_handoffs_count: int = 0
        self.candidate_selections_count: int = 0
        self.candidate_rejections_count: int = 0

        # --- Phase A: Event-driven observability subsystem ---
        self.event_bus = event_bus or EventBus()
        self.event_store = EventStore()
        # Wire event store as a persistent subscriber
        self.event_bus.subscribe_all(self.event_store.persist)
        # Budget tracker — limits configurable via config dict
        budget_cfg = BudgetConfig(
            duration_seconds=self.config.get("budget_duration", 3600),
            max_tool_calls=self.config.get("budget_max_tools", 500),
            max_requests=self.config.get("budget_max_requests", 1000),
            max_model_tokens=self.config.get("budget_max_tokens", 500_000),
        )
        self.context_manager = ContextManager(
            max_context_tokens=self.config.get("num_ctx", 8192),
            max_recent_turns=4,
            max_tool_output_chars=1200
        )
        self.recovery_controller = LoopRecoveryController(max_redirects=3)
        self._stagnation_window = 3

        self.max_planner_time: float = float(self.config.get("max_planner_time", 45.0))
        self.planner = Planner(max_planner_time=self.max_planner_time)

        self.tool_executor = ToolExecutor(
            registry=self.registry,
            config=self.config,
            event_bus=self.event_bus,
            storage=self.storage,
            assessment_logger=self.assessment_logger,
        )
        self.tool_cache = self.tool_executor.tool_cache
        self.model_latencies: List[float] = []
        self.tool_latencies: List[float] = []
        self.parse_latencies: List[float] = []
        self.planner_timeouts_count: int = 0
        self._is_coding_task: bool = False
        self.embedded_ui: bool = False
        self.tool_call_counts: Dict[str, int] = {}
        self.assessment_context: Optional[AssessmentContext] = None
        # canonical_state already assigned on line 122; no duplicate needed
        self.profile_data: Dict[str, float] = {
            "startup_time": 0.0,
            "toolchain_time": 0.0,
            "planner_time": 0.0,
            "tool_execution_time": 0.0,
            "parser_time": 0.0,
            "render_time": 0.0
        }

        # UI State Variables
        self.ui_active = False
        self.ui_task_goal = ""
        self.ui_target = ""
        self.ui_scope = []

    def stop(self) -> None:
        """Signal the agent loop to stop gracefully."""
        if self.stop_event:
            self.stop_event.set()
        self.ui_session_id = ""
        self.ui_model_name = ""
        self.ui_iteration = 0
        self.ui_start_time = 0.0
        self.ui_current_plan_index = 0
        self.ui_status = "Initializing..."
        self.ui_thinking = ""
        self.ui_action_tool = ""
        self.ui_action_args = {}
        self.ui_result = ""
        self.ui_observation = ""
        self.ui_observation_meaning = ""
        self.ui_observation_next = ""
        self.ui_findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.ui_evidence_count = 0
        self.ui_history = []

    def get_dashboard_layout(self) -> Table:
        """Builds dashboard layout by delegating to the extracted cli/dashboard module."""
        ds = DashboardState(
            session_id=getattr(self, "ui_session_id", ""),
            model_name=getattr(self, "ui_model_name", ""),
            iteration=getattr(self, "ui_iteration", 0),
            max_iterations=self.max_iterations,
            start_time=getattr(self, "ui_start_time", 0.0),
            task_goal=self.ui_task_goal,
            target=self.ui_target,
            scope=self.ui_scope,
            status=getattr(self, "ui_status", "Initializing..."),
            plan=self.plan,
            current_plan_index=getattr(self, "ui_current_plan_index", 0),
            thinking=getattr(self, "ui_thinking", ""),
            action_tool=getattr(self, "ui_action_tool", ""),
            action_args=getattr(self, "ui_action_args", {}),
            result=getattr(self, "ui_result", ""),
            observation=getattr(self, "ui_observation", ""),
            observation_meaning=getattr(self, "ui_observation_meaning", ""),
            observation_next=getattr(self, "ui_observation_next", ""),
            findings_count=getattr(self, "ui_findings_count", {}),
            evidence_count=getattr(self, "ui_evidence_count", 0),
            history=getattr(self, "ui_history", []),
        )
        return build_dashboard_layout(
            ds,
            theme_name=self.config.get("ui_theme", "default"),
            max_history_rows=self.config.get("ui_max_history_rows", 5),
        )


    def _parse_xml_tool_call(self, content: str) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """
        Parses XML tags from content string delegating to Planner.
        """
        return self.planner.parse_xml_tool_call(content)

    def _compact_message_history(self, raw_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prevents runaway token accumulation delegating to ContextManager.
        """
        # A coding task must remember its earlier reads and test runs, and assessment state
        # would only mislead it, so it keeps its full history within the character budget.
        if self._is_coding_task:
            compacted = self.context_manager._enforce_character_budget(raw_messages)
        else:
            compacted = self.context_manager.compact_messages(
                raw_messages=raw_messages,
                state=getattr(self, "canonical_state", None),
                attack_surface=getattr(self, "attack_surface", None)
            )
        return repair_tool_call_pairs(compacted) if self.native_tools else compacted


    @property
    def duplicate_calls_blocked(self) -> int:
        return self.tool_executor.duplicate_calls_blocked

    @duplicate_calls_blocked.setter
    def duplicate_calls_blocked(self, val: int) -> None:
        self.tool_executor.duplicate_calls_blocked = val

    @property
    def cache_hits(self) -> int:
        return self.tool_executor.cache_hits

    @cache_hits.setter
    def cache_hits(self, val: int) -> None:
        self.tool_executor.cache_hits = val

    @property
    def tools_successful(self) -> int:
        return self.tool_executor.tools_successful

    @tools_successful.setter
    def tools_successful(self, val: int) -> None:
        self.tool_executor.tools_successful = val

    @property
    def tools_failed(self) -> int:
        return self.tool_executor.tools_failed

    @tools_failed.setter
    def tools_failed(self, val: int) -> None:
        self.tool_executor.tools_failed = val

    @property
    def max_actions(self) -> int:
        return self.tool_executor.max_actions

    @max_actions.setter
    def max_actions(self, val: int) -> None:
        self.tool_executor.max_actions = val

    @property
    def max_retries(self) -> int:
        return self.tool_executor.max_retries

    @max_retries.setter
    def max_retries(self, val: int) -> None:
        self.tool_executor.max_retries = val

    @property
    def max_same_tool(self) -> int:
        return self.tool_executor.max_same_tool

    @max_same_tool.setter
    def max_same_tool(self, val: int) -> None:
        self.tool_executor.max_same_tool = val

    @property
    def attack_surface(self) -> AttackSurfaceSnapshot:
        if getattr(self, "canonical_state", None):
            return self.canonical_state.get_attack_surface_snapshot()
        if self._attack_surface is not None:
            return self._attack_surface
        return AttackSurfaceSnapshot()

    @attack_surface.setter
    def attack_surface(self, val: Any) -> None:
        self._attack_surface = val

    @staticmethod
    def _tool_feedback(content: str, tool_call_id: Optional[str]) -> Dict[str, Any]:
        """Native APIs reject a history where a tool call has no matching tool result."""
        if tool_call_id:
            return {"role": "tool", "content": content, "tool_call_id": tool_call_id}
        return {"role": "user", "content": content}

    def _resolve_native_tools(self, requested: Optional[bool]) -> bool:
        """Explicit argument, then config "native_tools", then the provider's declared capability."""
        if requested is not None:
            return requested
        configured = self.config.get("native_tools")
        if configured is not None:
            return bool(configured)
        capabilities = getattr(self.provider, "capabilities", None)
        if not callable(capabilities):
            return False
        declared = capabilities()
        return isinstance(declared, dict) and declared.get("native_tools") is True

    def _verify_coding_task(self, task_goal: str, policy_engine: PolicyEngine) -> Any:
        """Runs the completion gate; its test command needs approval like any other command."""
        from verification.coding_verifier import CodingVerifier

        def approve_command(command: str) -> bool:
            permitted, _ = policy_engine.evaluate_tool_call("terminal.execute", {"command": command})
            return permitted

        verifier = CodingVerifier(workspace=self.config.get("workspace"), command_approver=approve_command)
        return verifier.verify_task(task_goal=task_goal, auto_run_tests=True)

    def _check_planner_timeout(self, elapsed: float, result_holder: Dict[str, Any]) -> bool:
        """
        Single source of truth for planner latency cap enforcement.
        Returns True if the timeout was triggered and result_holder was populated.
        """
        if elapsed <= self.max_planner_time:
            return False

        # The fallback substitutes a security action for the model's decision, which has
        # no place in a coding task. Keep waiting; stop_event and the provider timeout bound this.
        if self._is_coding_task:
            return False

        self.planner_timeouts_count += 1

        # UI feedback (mode-dependent)
        if self.ui_active:
            pass  # Dashboard updates handled by the caller's spinner loop
        elif sys.stdout.isatty():
            sys.stdout.write(
                f"\r\033[K  \033[33m⚡ [PLANNER LATENCY CAP ({self.max_planner_time:.0f}s)] "
                f"Auto-recovering with prioritized pending action.\033[0m\n"
            )
            sys.stdout.flush()
        else:
            console.print(
                f"\n[bold yellow]⚡ [PLANNER LATENCY CAP ({self.max_planner_time:.0f}s)] "
                f"Fast-pathing to prioritized pending action.[/bold yellow]\n"
            )

        target_host = self.assessment_context.target if self.assessment_context else "127.0.0.1"
        resp_payload, _ = self.planner.handle_timeout(
            state=self.canonical_state,
            attack_surface=getattr(self, "_attack_surface", None),
            target=target_host,
            native_tools=self.native_tools,
        )
        result_holder["response"] = resp_payload
        return True

    def _chat_with_spinner(
        self,
        messages: List[Dict[str, Any]],
        tools_schemas: Optional[List[Dict[str, Any]]],
        iteration: int,
        max_retries: int = 2,
        assessment_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs provider.chat() in a background thread while showing a live
        spinner with elapsed time so the user knows the model is working.
        Emits model.started / model.completed / model.timeout events.
        Tracks token usage in the budget tracker.
        Retries once on timeout.
        """
        model_name = getattr(self.provider, 'model_name', 'model')
        display_name = model_name.split("/")[-1] if "/" in model_name else model_name
        if len(display_name) > 30:
            display_name = display_name[:27] + "..."

        # --- ModelRouter hook: pick the best model for the current task ---
        if self.model_router is not None and messages:
            last_user = ""
            for m in reversed(messages):
                if m.get("role") == "user":
                    last_user = m.get("content") or ""
                    break
            if last_user and hasattr(self.provider, "switch_model"):
                routed = self.model_router.route(last_user)
                current = getattr(self.provider, "model_name", "")
                if routed and routed != current:
                    try:
                        self.provider.switch_model(routed)
                        model_name = routed
                        display_name = routed.split("/")[-1]
                        if not self.quiet:
                            print(f"\n[ROUTER] switched to {routed} for this task\n")
                    except Exception as e:
                        if not self.quiet:
                            print(f"\n[ROUTER] switch to {routed} failed: {e}")

        compact_messages = self._compact_message_history(messages)

        for attempt in range(max_retries):
            # Record start time for latency tracking
            start_time = time.time()

            # Emit model.started event
            self.event_bus.emit(
                EventType.MODEL_STARTED,
                {"attempt": attempt + 1, "iteration": iteration},
                assessment_id=assessment_id,
            )

            result_holder = {"response": None, "error": None}
            live_text = []

            def _do_chat():
                try:
                    if hasattr(self.provider, "stream_chat") and (self.on_stream_delta is not None or (not self.ui_active and sys.stdout.isatty())):
                        full_content = []
                        full_tool_calls = []
                        last_metrics = {}
                        printed_header = False

                        for chunk in self.provider.stream_chat(compact_messages, tools=tools_schemas):
                            msg = chunk.get("message", {})
                            delta = msg.get("content", "")
                            tcalls = msg.get("tool_calls", [])
                            if tcalls:
                                full_tool_calls.extend(tcalls)
                            if delta:
                                full_content.append(delta)
                                live_text.append(delta)
                                if self.on_stream_delta is not None:
                                    self.on_stream_delta(delta)
                                self.event_bus.emit(
                                    EventType.MODEL_TOKEN,
                                    {"token": delta, "iteration": iteration},
                                    assessment_id=assessment_id,
                                )
                            if chunk.get("metrics"):
                                last_metrics = chunk.get("metrics")
                            elif chunk.get("usage"):
                                last_metrics = usage_to_metrics(chunk.get("usage"))

                        combined_content = "".join(full_content)
                        result_holder["response"] = {
                            "message": {
                                "role": "assistant",
                                "content": combined_content,
                                "tool_calls": full_tool_calls
                            },
                            "done": True,
                            "metrics": last_metrics
                        }
                    else:
                        result_holder["response"] = self.provider.chat(compact_messages, tools=tools_schemas)
                except Exception as e:
                    result_holder["error"] = e

            thread = threading.Thread(target=_do_chat, daemon=True)
            start_time = time.time()
            thread.start()

            phases = [
                (0,   "Parsing prompt"),
                (5,   "Loading context"),
                (15,  "Reasoning about tools"),
                (30,  "Planning actions"),
                (60,  "Deep analysis"),
                (120, "Complex reasoning"),
                (300, "Extended processing"),
            ]

            # Emit progress events periodically
            last_progress_emit = 0
            last_stream_len = 0
            has_shown_stream = False

            try:
                if self.ui_active:
                    while thread.is_alive():
                        elapsed = time.time() - start_time
                        mins, secs = divmod(int(elapsed), 60)
                        time_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{secs}s"

                        phase = "Thinking"
                        for threshold, desc in reversed(phases):
                            if elapsed >= threshold:
                                phase = desc
                                break

                        spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
                        spinner_char = spinner_chars[int(elapsed * 8) % len(spinner_chars)]

                        self.ui_status = f"{spinner_char} {phase} ({time_str})"
                        streamed_sample = "".join(live_text)[-120:].replace("\n", " ") if live_text else "generating..."
                        self.ui_thinking = f"💭 {streamed_sample} ({time_str})"
                        self.live.update(self.get_dashboard_layout())

                        # Emit progress event every 10 seconds
                        if int(elapsed) - last_progress_emit >= 10:
                            last_progress_emit = int(elapsed)
                            self.event_bus.emit(
                                EventType.MODEL_PROGRESS,
                                {"elapsed_s": int(elapsed), "phase": phase},
                                assessment_id=assessment_id,
                            )

                        if self.stop_event is not None and self.stop_event.is_set():
                            break

                        # Check planner latency cap and auto-recover with highest priority recommendation
                        if self._check_planner_timeout(elapsed, result_holder):
                            break

                        thread.join(timeout=0.1)
                else:
                    if sys.stdout.isatty():
                        spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
                        while thread.is_alive():
                            elapsed = time.time() - start_time
                            mins, secs = divmod(int(elapsed), 60)
                            time_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{secs}s"
                            char = spinner_chars[int(elapsed * 8) % len(spinner_chars)]

                            sys.stdout.write(f"\r\033[K  \033[36m{char}\033[0m \033[2m[PLANNER] Analyzing attack surface & selecting next action ({time_str} / cap {self.max_planner_time:.0f}s)...\033[0m")
                            sys.stdout.flush()

                            # Emit progress event every 10 seconds
                            if int(elapsed) - last_progress_emit >= 10:
                                last_progress_emit = int(elapsed)
                                self.event_bus.emit(
                                    EventType.MODEL_PROGRESS,
                                    {"elapsed_s": int(elapsed), "phase": "analyzing"},
                                    assessment_id=assessment_id,
                                )

                            if self.stop_event is not None and self.stop_event.is_set():
                                break

                            # Check planner latency cap in CLI mode
                            if self._check_planner_timeout(elapsed, result_holder):
                                break

                            thread.join(timeout=0.08)
                        sys.stdout.write("\r\033[K")
                        sys.stdout.flush()
                    else:
                        while thread.is_alive():
                            if self.stop_event is not None and self.stop_event.is_set():
                                break
                            elapsed = time.time() - start_time
                            if self._check_planner_timeout(elapsed, result_holder):
                                break
                            thread.join(timeout=0.2)
            except KeyboardInterrupt:
                if not self.ui_active:
                    console.print("\n[bold yellow]⚠ Model interrupted by user.[/bold yellow]")
                raise

            model_elapsed = time.time() - start_time
            self.model_latencies.append(model_elapsed)
            self.profile_data["planner_time"] += model_elapsed

            # Stop requested while the model call was in flight: abandon it
            if self.stop_event is not None and self.stop_event.is_set():
                return {"stopped": True, "status": "paused"}

            if result_holder["error"] is not None:
                err = result_holder["error"]
                is_timeout = "timed out" in str(err).lower() or "timeout" in str(err).lower()

                if is_timeout and attempt < max_retries - 1:
                    # Emit timeout event
                    self.event_bus.emit(
                        EventType.MODEL_TIMEOUT,
                        {"elapsed_s": int(model_elapsed), "attempt": attempt + 1},
                        severity=EventSeverity.WARN,
                        assessment_id=assessment_id,
                    )
                    if not self.ui_active:
                        console.print(
                            f"[bold yellow]⚠ Model timed out after {int(model_elapsed)}s. "
                            f"Retrying (attempt {attempt + 2}/{max_retries})...[/bold yellow]"
                        )
                    else:
                        self.ui_status = "Timeout, retrying..."
                        self.live.update(self.get_dashboard_layout())
                elif isinstance(err, StopIteration):
                    return {
                        "message": {
                            "role": "assistant",
                            "content": '<tool_call name="complete"><summary>Task concluded</summary></tool_call>',
                            "tool_calls": []
                        },
                        "done": True,
                        "metrics": {}
                    }
                else:
                    raise err

            # Track token usage from model metrics
            response = result_holder["response"]
            metrics = response.get("metrics") or usage_to_metrics(
                response.get("usage") or (response.get("raw") or {}).get("usage")
            )
            prompt_tokens = metrics.get("prompt_eval_count") or 0
            output_tokens = metrics.get("eval_count") or 0
            tokens_estimated = not prompt_tokens and not output_tokens
            if tokens_estimated:
                prompt_tokens = estimate_tokens(compact_messages)
                output_tokens = estimate_tokens([response.get("message") or {}])
            self.budget.record_model_tokens(input_tokens=prompt_tokens, output_tokens=output_tokens)

            # Emit model.completed event
            self.event_bus.emit(
                EventType.MODEL_COMPLETED,
                {
                    "elapsed_s": round(model_elapsed, 2),
                    "prompt_tokens": prompt_tokens,
                    "output_tokens": output_tokens,
                    "tokens_estimated": tokens_estimated,
                    "iteration": iteration,
                    "content": (response.get("message") or {}).get("content", ""),
                },
                assessment_id=assessment_id,
            )

            # Check budget warnings
            warnings = self.budget.check_warnings()
            for w in warnings:
                self.event_bus.emit(
                    EventType.BUDGET_WARNING,
                    w,
                    severity=EventSeverity.WARN,
                    assessment_id=assessment_id,
                )
                if not self.ui_active:
                    console.print(f"[bold yellow]⚠ Budget warning: {w['category']} at {w['pct']}% ({w['used']}/{w['limit']})[/bold yellow]")

            return response

        raise Exception("Model chat failed after all retries")
    def _generate_default_plan(self, task_goal: str, target: str) -> List[str]:
        """
        Dynamically derives an assessment plan based on the user's task and target.
        """
        goal_lower = task_goal.lower()
        if any(k in goal_lower for k in ("port", "nmap", "network", "recon", "host", "subdomain")):
            return [
                f"Perform initial reconnaissance on {target}",
                "Enumerate exposed ports and running network services",
                "Identify banner versions and service fingerprints",
                "Analyze service attack surface and known vulnerabilities",
                "Document findings and compile security report"
            ]
        elif any(k in goal_lower for k in ("login", "auth", "bypass", "sqli", "injection", "xss", "csrf", "idor")):
            return [
                f"Analyze target endpoint {target}",
                "Inspect input parameters and form validation logic",
                "Test for security vulnerabilities and injection vectors",
                "Collect verification evidence and reproduction steps",
                "Document findings and compile security report"
            ]
        else:
            return [
                f"Analyze target ({target}) and establish security scope",
                "Enumerate attack surface and accessible resources",
                "Probe for security misconfigurations and vulnerabilities",
                "Verify potential security issues with proof-of-concept",
                "Document findings and compile security report"
            ]

    def run(
        self,
        task_goal: str,
        target: str,
        scope: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, Any]]] = None,
        attached_context: str = "",
    ) -> Dict[str, Any]:
        """
        Executes the agent loop until completion or max iterations.
        """
        scope = scope or [target]
        if not session_id:
            session_id = f"session-{uuid.uuid4().hex[:8]}"

        # Check UI mode from config ('stream' is the clean modern CLI style, 'dashboard' is rich.live)
        self.ui_mode = self.config.get("ui_mode", "stream")
        is_tty = sys.stdout.isatty() and not os.environ.get("PYTEST_CURRENT_TEST")
        # A host UI owns the terminal, so console output and spinners must stay off however it was started
        self.ui_active = self.embedded_ui or ((self.ui_mode == "dashboard") and is_tty)
        if self.quiet:
            self.ui_active = self.embedded_ui
            import io as _io
            self._quiet_sink = _io.StringIO()
            try:
                console.file = self._quiet_sink
                console.force_terminal = False
            except Exception:
                pass
        self.ui_task_goal = task_goal
        self.ui_target = target
        self.ui_scope = scope
        self.ui_session_id = session_id
        self.ui_model_name = getattr(self.provider, 'model_name', 'model')
        self.ui_iteration = 0
        self.ui_start_time = time.time()
        self.ui_current_plan_index = 0
        self.ui_status = "Initializing..."
        self.ui_thinking = ""
        self.ui_action_tool = ""
        self.ui_action_args = {}
        self.ui_result = ""
        self.ui_observation = ""
        self.ui_observation_meaning = ""
        self.ui_observation_next = ""
        self.ui_findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.ui_evidence_count = 0
        self.ui_history = []

        if not self.ui_active:
            console.print(f"\n[bold green]Starting Task: {task_goal}[/bold green]")
            console.print(f"[dim]Target: {target} | Scope: {', '.join(scope)}[/dim]\n")

        # --- Phase A: Emit assessment.started event ---
        self.budget = BudgetTracker(config=BudgetConfig(
            duration_seconds=self.config.get("budget_duration", 3600),
            max_tool_calls=self.config.get("budget_max_tools", 500),
        ))
        predicates = self.config.get("predicates")
        if self.assessment_state and getattr(self.assessment_state, "predicates", None):
            predicates = predicates or self.assessment_state.predicates
        context = AssessmentContext(
            target=target,
            scope=tuple(scope),
            objective=task_goal,
            predicates=predicates
        )
        self.assessment_state = AssessmentState(context=context, predicates=predicates or VerificationPredicates())
        self.canonical_state = self.assessment_state
        self._recent_tool_calls = []
        # Recursive assessment engines
        self._attack_graph = AttackGraph()
        self._hypothesis_engine = HypothesisEngine()
        self._completion_engine = CompletionEngine(hypothesis_engine=self._hypothesis_engine)
        self.event_bus.emit(
            EventType.ASSESSMENT_STARTED,
            {"target": target, "scope": scope, "goal": task_goal, "session_id": session_id},
            assessment_id=session_id,
        )
        self.assessment_state.transition(AssessmentPhase.AUTHORIZATION_CHECK, "Verifying scope authorization")
        self.assessment_state.transition(AssessmentPhase.SCOPE_VALIDATION, "Validating target scope")

        loop_start_time = time.time()
        # Initialize Policy Engine and Sandbox environment
        approval_gate = None
        if self.approval_callback:
            from security.approvals import ApprovalGate
            approval_gate = ApprovalGate(
                event_bus=self.event_bus,
                approval_callback=self.approval_callback,
                auto_approve_lab=False,
            )
        policy_engine = PolicyEngine(
            scope,
            event_bus=self.event_bus,
            approval_gate=approval_gate,
        )
        sandbox = get_sandbox()
        from agent.intent import is_coding_task
        if isinstance(sandbox, BlockedSandbox) and is_coding_task(task_goal):
            # PolicyEngine still requires operator approval for every command
            sandbox = ApprovedHostSandbox(workspace=self.config.get("workspace"))

        # Verify sandbox runtime image matches authoritative toolchain image
        expected_image = get_security_sandbox_image()
        if isinstance(sandbox, DockerSandbox) and sandbox.image != expected_image:
            console.print(Panel(
                f"[bold red]Toolchain/runtime image mismatch.[/bold red]\n\n"
                f"Expected: [cyan]{expected_image}[/cyan]\n"
                f"Actual:   [yellow]{sandbox.image}[/yellow]\n\n"
                f"Autonomous execution blocked.",
                title="[bold red]STARTUP BLOCKED[/bold red]",
                border_style="red"
            ))
            return {
                "status": TaskStatus.FAILED.value,
                "session_id": session_id,
                "error": f"Image mismatch: expected {expected_image}, got {sandbox.image}"
            }

        # Dynamic plan setup
        self.plan = self._generate_default_plan(task_goal, target)

        # Canonical Assessment Context & State
        self.assessment_context = AssessmentContext(
            target=target,
            scope=tuple(scope),
            objective=task_goal,
            target_known=True,
            objective_known=True,
            scope_known=True
        )
        self.assessment_state.context = self.assessment_context
        self.canonical_state = self.assessment_state
        self.knowledge.bind_state(self.canonical_state)
        self._attack_graph.sync_from_state(self.canonical_state)

        # Transition to asset discovery phase
        self.assessment_state.transition(AssessmentPhase.ASSET_DISCOVERY, "Discovering target assets")

        # Track in persistent database
        self.storage.create_session(session_id, target, scope, task_goal)
        self.storage.save_plan(session_id, self.plan, current_index=0)

        # Load relevant skills
        self.skill_manager = SkillManager()
        relevant_skills = self.skill_manager.get_relevant_skills(task_goal)
        skills_prompt = ""
        if relevant_skills:
            skills_prompt = "\n\nRELEVANT PLAYBOOKS / SKILLS:\n"
            for skill in relevant_skills:
                excerpt = skill["content"][:3000]
                if len(skill["content"]) > len(excerpt):
                    excerpt += "\n[Skill excerpt truncated for runtime performance.]"
                skills_prompt += f"\n--- SKILL: {skill['name']} ---\nDescription: {skill['description']}\nGuidelines:\n{excerpt}\n"
            skills_prompt += "---------------------------------\n"

        # Initialize conversation messages
        is_coding = is_coding_task(task_goal)
        self._is_coding_task = is_coding
        prompt_mode = self.config.get("prompt_mode", "baseline")
        if is_coding and prompt_mode == "baseline":
            prompt_mode = "coding"
            if task_requires_edits(task_goal):
                self.plan = [
                    "Inspect repository structure and locate relevant files",
                    "Plan surgical modifications",
                    "Apply edits with file_edit",
                    "Run project test suite and verify",
                    "Inspect git_diff and report verified results"
                ]
            else:
                self.plan = [
                    "Inspect repository structure and relevant files",
                    "Answer the question directly without changing any files",
                ]
        model_name_str = str(getattr(self.provider, "model_name", "")).lower()
        is_canonical = prompt_mode in ("canonical", "buzzard_sec") or "buzzard" in model_name_str
        if is_canonical and prompt_mode == "baseline":
            prompt_mode = "canonical"

        coding_tools = CODING_TOOL_NAMES
        if is_coding:
            from tools.mcp_client import get_mcp_manager
            coding_tools = CODING_TOOL_NAMES | frozenset(get_mcp_manager().register_tools(self.registry))
        tools_description = self.registry.get_tools_description(only=coding_tools if is_coding else None)
        system_prompt = build_system_prompt(
            tools_description,
            skills_prompt=skills_prompt if not is_canonical else "",
            modes=self.config.get("modes") if not is_canonical else None,
            prompt_mode=prompt_mode,
        )
        if is_coding and self.native_tools:
            system_prompt += NATIVE_TOOLS_GUIDANCE
        if is_coding:
            from agent.project_context import load_project_instructions
            system_prompt += load_project_instructions(self.config.get("workspace"))
        if not is_canonical and not is_coding:
            system_prompt += f"\n\n{self.assessment_context.format_summary()}\n"

        self.assessment_logger = AssessmentLogger(session_id=session_id)
        self.assessment_logger.write_metadata({
            "target": target,
            "scope": scope,
            "task_goal": task_goal,
            "model": str(getattr(self.provider, "model_name", "model"))
        })
        task_evt = AgentEvent(AgentEventType.TASK, f"Assessment started against {target}")
        self.assessment_logger.log_event(task_evt)
        if not self.ui_active:
            console.print(task_evt.format_cli())
        plan_evt = AgentEvent(AgentEventType.PLAN, f"Target: {target} · Objective: {task_goal}")
        self.assessment_logger.log_event(plan_evt)
        if not self.ui_active:
            console.print(plan_evt.format_cli())

        # Export tool schemas
        tools_schemas = (
            self.registry.export_schemas(only=coding_tools if is_coding else None)
            if self.native_tools else None
        )

        messages = [
            {"role": "system", "content": system_prompt}
        ]

        # Build first user prompt containing the full target, scope, task and plan context
        if is_coding:
            from tools.filesystem import get_active_workspace
            user_prompt = (
                f"### Active Project Workspace: {get_active_workspace()}\n"
                f"### Coding Task: {task_goal}\n"
                f"### Execution Plan:\n" + "\n".join(f"- {p}" for p in self.plan) + "\n\n"
                + (
                    "Please inspect the repository, identify the relevant files, apply surgical edits, "
                    "run the project test suite to verify, and verify git diff before concluding."
                    if task_requires_edits(task_goal)
                    else "Inspect only what you need, then answer. Do not change any files."
                )
            )
        elif is_canonical:
            user_prompt = build_user_prompt(
                target=target,
                scope=scope,
                current_task=task_goal,
                current_plan=self.plan,
                observations=[],
                canonical_mode=True,
            )
        else:
            user_prompt = (
                f"{self.assessment_context.format_summary()}\n\n"
                f"{build_user_prompt(target=target, scope=scope, current_task=task_goal, current_plan=self.plan, observations=[])}"
            )
        # Earlier user and assistant turns, so follow-up requests have their context
        messages.extend(conversation_history or [])
        messages.append({"role": "user", "content": user_prompt + attached_context})

        iteration = 0
        repeated_turns = 0
        last_turn_signature: Optional[tuple] = None
        status = TaskStatus.FAILED
        content = ""
        thinking_text = ""

        try:
            if self.ui_active:
                # A host UI such as the Textual app owns the terminal; Rich Live would corrupt it
                self.live = _NullLive() if self.embedded_ui else Live(self.get_dashboard_layout(), console=console, refresh_per_second=4)
                self.live.start()
                self.ui_status = "Running..."
                self.live.update(self.get_dashboard_layout())

            while iteration < self.max_iterations:
                iteration += 1
                self.ui_iteration = iteration
                if self.stop_event is not None and self.stop_event.is_set():
                    status = TaskStatus.PAUSED
                    break

                # Fetch findings/evidence counts
                try:
                    findings = self.storage.get_findings(session_id)
                    evidence = self.storage.get_evidence_list(session_id)

                    self.ui_findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    for f in findings:
                        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
                        if sev in self.ui_findings_count:
                            self.ui_findings_count[sev] += 1
                    self.ui_evidence_count = len(evidence)
                except Exception:
                    pass

                # Print and save current plan status
                current_plan_index = min(iteration - 1, len(self.plan) - 1)
                self.ui_current_plan_index = current_plan_index
                self.storage.save_plan(session_id, self.plan, current_index=current_plan_index)

                if self.ui_active:
                    self.live.update(self.get_dashboard_layout())

                # Check budget before each iteration
                if self.budget.is_exceeded():
                    self.event_bus.emit(
                        EventType.BUDGET_EXCEEDED,
                        self.budget.get_status(),
                        severity=EventSeverity.ERROR,
                        assessment_id=session_id,
                    )
                    if not self.ui_active:
                        console.print("[bold red]⚠ Assessment budget exceeded. Stopping.[/bold red]")
                    status = TaskStatus.COMPLETED
                    break

                # Pre-decision state synchronization and candidate trace logging
                if self.canonical_state:
                    self.canonical_state._update_action_queues()
                    pending = self.canonical_state.pending_actions
                    candidates = self.canonical_state.generate_exploit_candidates()
                    eligible = [c for c in candidates if c.evaluate_preconditions(self.canonical_state)[0]]
                    hyps = self.canonical_state.get_active_hypotheses()

                    if eligible:
                        self.candidate_handoffs_count += len(eligible)

                    if not self.ui_active:
                        console.print(f"[bold cyan][STATE][/bold cyan] {len(hyps)} hypotheses · {len(eligible)} eligible candidate{'s' if len(eligible) != 1 else ''} · {len(pending)} pending action{'s' if len(pending) != 1 else ''}")
                        if pending:
                            pa = pending[0]
                            console.print(f"[bold yellow][NEXT][/bold yellow] {pa.get('priority', 'INFO')}: {pa.get('tool')} → {target}\nReason: {pa.get('reason')}")
                        if eligible:
                            console.print(f"[dim green]Eligible Exploit Candidates ({len(eligible)}):[/dim green]")
                            for ec in eligible:
                                hyp = ec.vulnerability_hypothesis
                                precond_desc = f"open_port={ec.required_conditions.require_open_port}, http_responds={ec.required_conditions.require_http_state_responds}"
                                console.print(
                                    f"  • tool: {ec.allowed_tool} | target: {ec.target} | hypothesis_id: {hyp.id} | "
                                    f"evidence_ids: {ec.evidence_ids} | preconditions: [{precond_desc}] | "
                                    f"verification_plan: {ec.verification_plan}"
                                )

                # Emit thinking event
                self.event_bus.emit(
                    EventType.AGENT_THINKING_STARTED,
                    {"iteration": iteration},
                    assessment_id=session_id,
                )

                # Dynamic focused tool schema selection if dynamic_tools enabled
                if self.config.get("dynamic_tools", True) and self.native_tools and not is_coding:
                    active_hyp_str = ""
                    if self.canonical_state:
                        active_hyps = self.canonical_state.get_active_hypotheses()
                        if active_hyps:
                            active_hyp_str = f"{active_hyps[0].vulnerability_type} {active_hyps[0].details}"
                    curr_phase = self.canonical_state.phase.value if self.canonical_state else "DISCOVERY"
                    tools_schemas = DynamicToolSelector.select_focused_tools(
                        registry=self.registry,
                        phase=curr_phase,
                        active_hypothesis=active_hyp_str,
                        target=target,
                        max_tools=self.config.get("max_dynamic_tools", 22),
                    )

                # Query the model provider with live progress indicator
                response_dict = self._chat_with_spinner(messages, tools_schemas, iteration, assessment_id=session_id)

                # A stop request landed while the model call was in flight: pause now
                if response_dict.get("stopped"):
                    status = TaskStatus.PAUSED
                    self.assessment_state.pause()
                    self.event_bus.emit(
                        EventType.ASSESSMENT_PAUSED,
                        {"reason": "Stop requested during model call", "iteration": iteration},
                        assessment_id=session_id,
                    )
                    break

                # Extract message fields
                msg = response_dict.get("message", {})
                content = msg.get("content", "") or ""
                tool_calls = msg.get("tool_calls", [])
                thinking_text = msg.get("thinking", "") or ""

                # Check for XML tool call
                xml_tool_name, xml_args, xml_thinking = self._parse_xml_tool_call(content)
                decision_summary = None

                if xml_tool_name:
                    if xml_thinking:
                        thinking_text = xml_thinking
                    if xml_tool_name in ("complete", "finish_task"):
                        tool_calls = []
                        decision_summary = {
                            "type": "complete",
                            "decision": "complete",
                            "reason": thinking_text or "Task complete",
                            "expected_information": "N/A",
                            "next_step": "N/A"
                        }
                    else:
                        # Pre-check auto-routing for alias / fallback tools (e.g. scan_ports -> nmap_scan)
                        if xml_tool_name == "scan_ports" and ("nmap_scan" in self.registry.tools):
                            ports_str = str(xml_args.get("ports", ""))
                            if "-" in ports_str or xml_tool_name not in self.registry.tools:
                                xml_tool_name = "nmap_scan"
                                xml_args["ports"] = ports_str or "1-1000"

                        if xml_tool_name in self.registry.tools:
                            tool_calls = [
                                {
                                    "function": {
                                        "name": xml_tool_name,
                                        "arguments": xml_args
                                    }
                                }
                            ]
                            decision_summary = {
                                "decision": xml_tool_name,
                                "reason": thinking_text or f"Executing tool {xml_tool_name}",
                                "expected_information": "N/A",
                                "next_step": "N/A"
                            }
                        else:
                            available = ", ".join(self.registry.tools)
                            if not self.ui_active:
                                console.print(f"  [bold yellow]⚠ Tool '{xml_tool_name}' unavailable, retrying...[/bold yellow]")
                            else:
                                self.ui_status = f"Warning: XML tool '{xml_tool_name}' unavailable"
                                self.ui_thinking = f"Model proposed unavailable XML tool '{xml_tool_name}'. Requesting a valid tool call."
                                self.live.update(self.get_dashboard_layout())

                            # Append assistant and user corrective messages
                            assistant_msg = {
                                "role": "assistant",
                                "content": content
                            }
                            if thinking_text:
                                assistant_msg["thinking"] = thinking_text
                            messages.append(assistant_msg)

                            messages.append({
                                "role": "user",
                                "content": (
                                    f"'{xml_tool_name}' is not available. Call one tool exactly as supplied "
                                    f"in the schema. Available tools: {available}."
                                )
                            })
                            continue

                # Append assistant response to messages history
                assistant_msg = {
                    "role": "assistant",
                    "content": content
                }
                if self.native_tools and tool_calls:
                    assistant_msg["tool_calls"] = tool_calls
                if self.native_tools and thinking_text:
                    assistant_msg["thinking"] = thinking_text
                messages.append(assistant_msg)

                # A model repeating itself is stuck: redirect it, then stop instead of burning budget
                if is_coding:
                    turn_signature = (
                        content,
                        str([(c.get("function") or {}).get("name") for c in tool_calls]),
                        str([(c.get("function") or {}).get("arguments") for c in tool_calls]),
                    )
                    repeated_turns = repeated_turns + 1 if turn_signature == last_turn_signature else 0
                    last_turn_signature = turn_signature
                    if repeated_turns >= MAX_REPEATED_TURNS:
                        status = TaskStatus.FAILED
                        if not self.ui_active:
                            console.print("[bold red]Stopped: the model kept repeating the same action.[/bold red]")
                        break
                    if repeated_turns and tool_calls:
                        messages.append({
                            "role": "user",
                            "content": (
                                "You just repeated your previous action, so it was not run again. "
                                "Use the earlier result and take a different step, or give your final answer."
                            ),
                        })
                        continue

                # Parse canonical ModelDecision contract
                parsed_decision: Optional[ModelDecision] = None
                try:
                    parsed_decision = ModelDecisionParser.parse(
                        raw_content=content,
                        native_tool_calls=tool_calls,
                        reasoning=thinking_text
                    )
                except Exception:
                    pass

                # Parse the decision summary from content (JSON) or generate fallback
                if decision_summary is None:
                    if parsed_decision and parsed_decision.decision_type.value == "complete":
                        decision_summary = {
                            "type": "complete",
                            "decision": "complete",
                            "reason": parsed_decision.reasoning_summary,
                            "expected_information": f"Exp Gain {parsed_decision.expected_information_gain:.1f}",
                            "next_step": parsed_decision.next_step_intent or "N/A"
                        }
                    elif parsed_decision and parsed_decision.action and parsed_decision.decision_type == DecisionType.TOOL_CALL:
                        decision_summary = {
                            "type": "tool_call",
                            "decision": parsed_decision.action.tool_name,
                            "arguments": parsed_decision.action.arguments,
                            "reason": parsed_decision.reasoning_summary,
                            "expected_information": f"Exp Gain {parsed_decision.expected_information_gain:.1f}",
                            "next_step": parsed_decision.next_step_intent or "N/A"
                        }
                    else:
                        decision_summary = parse_decision_summary(content, tool_calls, thinking_text)

                # Compatibility fallback for older models
                if not tool_calls and decision_summary:
                    decision_type = decision_summary.get("type") or "tool_call"
                    tool_name = decision_summary.get("decision") or decision_summary.get("tool")
                    if tool_name in ("complete", "finish_task") or decision_type in ("complete", "finish", "done"):
                        tool_calls = []
                    elif tool_name and decision_type not in ("complete", "pause", "error"):
                        if tool_name in self.registry.tools:
                            tool_calls = [
                                {
                                    "function": {
                                        "name": tool_name,
                                        "arguments": decision_summary.get("arguments") or {}
                                    }
                                }
                            ]
                        else:
                            available = ", ".join(self.registry.tools)
                            if not self.ui_active:
                                console.print(f"  [bold yellow]⚠ Tool '{tool_name}' unavailable, retrying...[/bold yellow]")
                            else:
                                self.ui_status = f"Warning: Tool '{tool_name}' unavailable"
                                self.ui_thinking = f"Model proposed unavailable tool '{tool_name}'. Requesting a valid native tool call."
                                self.live.update(self.get_dashboard_layout())

                            messages.append({
                                "role": "user",
                                "content": (
                                    f"'{tool_name}' is not available. Call one native tool exactly as supplied "
                                    f"in the schema. Available tools: {available}."
                                )
                            })
                            continue

                # Target & Objective Canonical Lock: Intercept LLM asking user for target/objective delegating to Planner
                if not tool_calls and not is_coding:
                    interception_decision = self.planner.check_target_prompt_interception(
                        content=content,
                        state=self.canonical_state,
                        attack_surface=getattr(self, "attack_surface", None),
                        target=target,
                        task_goal=task_goal,
                        iteration=iteration
                    )
                    if interception_decision:
                        if not self.ui_active:
                            console.print(f"  [bold yellow]⚡ [CANONICAL CONTEXT ENFORCED] Target '{target}' and Objective '{task_goal}' are locked. Auto-dispatching next action.[/bold yellow]")
                        tc = interception_decision.to_tool_call()
                        if tc:
                            tool_calls = [tc]
                        decision_summary = interception_decision.to_summary_dict()

                # Display reasoning in stream mode
                if not self.ui_active and thinking_text:
                    short_thought = thinking_text.strip().split("\n")[0].strip()
                    if short_thought and not short_thought.startswith("<tool_call"):
                        if len(short_thought) > 110:
                            short_thought = short_thought[:107] + "..."
                        console.print(f"[dim]💭 {short_thought}[/dim]")
                elif self.ui_active:
                    self.ui_status = "Decision Made"
                    self.ui_thinking = decision_summary.get("reason") or thinking_text or "No active reasoning."
                    self.live.update(self.get_dashboard_layout())

                # Handle error decision types in summary
                if decision_summary.get("type") == "error":
                    if not self.ui_active:
                        console.print(f"[bold red]Loop Error: {decision_summary.get('reason')}[/bold red]")
                    else:
                        self.ui_status = "Error"
                        self.ui_thinking = f"Loop Error: {decision_summary.get('reason')}"
                        self.live.update(self.get_dashboard_layout())
                    break

                # If there are no tool calls, it means the model is finished!
                if not tool_calls:
                    if is_coding:
                        v_res = self._verify_coding_task(task_goal, policy_engine)
                        if not v_res.passed:
                            if not self.ui_active:
                                console.print(f"  [bold yellow]⚡ [CODING VERIFICATION GATE REJECTED][/bold yellow]\n{v_res.message}")
                            messages.append({
                                "role": "user",
                                "content": v_res.message
                            })
                            continue
                    else:
                        # CompletionEngine is the sole arbiter of whether the assessment may stop.
                        # It evaluates 10 evidence-grounded gates and returns a typed decision.
                        _budget_snap = BudgetSnapshot(
                            elapsed_seconds=time.time() - loop_start_time,
                            max_seconds=self.config.get("budget_duration", 3600),
                            tool_calls_used=self.budget.tool_calls_used if hasattr(self.budget, "tool_calls_used") else 0,
                            max_tool_calls=self.config.get("budget_max_tools", 500),
                            iteration=iteration,
                            max_iterations=self.max_iterations,
                        )
                        _completion_decision = self._completion_engine.evaluate(
                            state=self.canonical_state,
                            graph=self._attack_graph,
                            budget=_budget_snap,
                            content=content,
                            observations=self.observations,
                            task_goal=task_goal,
                            target=target,
                        )
                        if _completion_decision.should_continue or _completion_decision.requires_verification:
                            if not self.ui_active:
                                console.print(
                                    f"  [bold yellow]⚡ [COMPLETION ENGINE: {_completion_decision.action.value}][/bold yellow] "
                                    f"{_completion_decision.rationale}"
                                )
                            messages.append({
                                "role": "user",
                                "content": _completion_decision.continuation_prompt or _completion_decision.rationale
                            })
                            continue
                        # _completion_decision.should_conclude — fall through to normal exit

                    status = TaskStatus.COMPLETED
                    self.storage.save_plan(session_id, self.plan, current_index=len(self.plan))


                    # Parse any inline XML findings from the report — route through
                    # canonical_state.record_finding() to preserve SSOT invariant,
                    # then mirror to storage for persistence.
                    for finding in parse_inline_findings(content, affected_asset=target):
                        recorded = self.canonical_state.record_finding(
                            title=finding.get("title", "Inline Finding"),
                            severity=finding.get("severity", "MEDIUM"),
                            description=finding.get("description", ""),
                            evidence_ids=finding.get("evidence", []),
                            proof=finding.get("verification", ""),
                        )
                        self.storage.add_finding(session_id, finding)

                    status = TaskStatus.COMPLETED
                    if not self.ui_active:
                        console.print(f"\n[bold green]✓ Assessment Finished[/bold green]\n")
                        # Clean xml tags for pristine markdown rendering
                        clean_report = clean_report_content(content)
                        if clean_report:
                            console.print(Markdown(clean_report))
                    else:
                        self.ui_status = "Completed"
                        self.ui_thinking = "Task completed successfully."
                        self.live.update(self.get_dashboard_layout())
                    break

                # Handle each tool call
                _redirected = False
                for tool_call in tool_calls:
                    tool_call_id = tool_call.get("id")
                    func = tool_call.get("function", {})
                    tool_name = func.get("name")
                    tool_args = func.get("arguments") or {}

                    if not tool_name:
                        continue

                    # Auto-routing for scan_ports when called with large port ranges (>50 ports)
                    if tool_name == "scan_ports":
                        ports_val = str(tool_args.get("ports", ""))
                        if "-" in ports_val:
                            parts = ports_val.split("-")
                            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                p_start, p_end = int(parts[0]), int(parts[1])
                                if (p_end - p_start) > 50:
                                    tool_name = "nmap_scan"
                                    tool_args = {"host": tool_args.get("host", target), "ports": ports_val}

                    # Argument validation for grab_banner
                    if tool_name == "grab_banner":
                        if not tool_args.get("port"):
                            uninv = self.attack_surface.get_uninvestigated_services() if hasattr(self, "attack_surface") else []
                            tool_args["port"] = uninv[0].port if uninv else 80
                        else:
                            try:
                                tool_args["port"] = int(tool_args["port"])
                            except Exception:
                                tool_args["port"] = 80

                    # Direct completion tool call
                    if tool_name in ("complete", "finish_task"):
                        if is_coding:
                            v_res = self._verify_coding_task(task_goal, policy_engine)
                            if not v_res.passed:
                                if not self.ui_active:
                                    console.print(f"  [bold yellow]⚡ [CODING VERIFICATION GATE REJECTED][/bold yellow]\n{v_res.message}")
                                messages.append(self._tool_feedback(v_res.message, tool_call_id))
                                continue
                        _guard = self._completion_engine.evaluate_tool_completion(
                            state=self.canonical_state,
                            target=target,
                            iteration=iteration,
                            max_iterations=self.max_iterations,
                            observations=self.observations,
                            tool_args=tool_args,
                        )
                        if _guard.rejected and not is_coding:
                            if not self.ui_active:
                                console.print(f"  [bold yellow]⚡ [{_guard.action.value}] Guard rejected completion.[/bold yellow]")
                            messages.append(self._tool_feedback(_guard.prompt, tool_call_id))
                            continue

                        status = TaskStatus.COMPLETED
                        comp_summary = tool_args.get("summary") or "Assessment completed successfully."
                        if not self.ui_active:
                            console.print(f"\n[bold green]✓ Assessment Complete: {comp_summary}[/bold green]\n")
                        else:
                            self.ui_status = "Completed"
                            self.ui_thinking = comp_summary
                            self.live.update(self.get_dashboard_layout())
                        self.storage.save_plan(session_id, self.plan, current_index=len(self.plan))
                        break

                    # Phase 6F: Verification Action Enforcement
                    _ver_guard = self._completion_engine.evaluate_verification_gate(
                        state=self.canonical_state,
                        tool_name=tool_name,
                        tool_args=tool_args,
                        target=target,
                        iteration=iteration,
                        max_iterations=self.max_iterations,
                    )
                    if _ver_guard.rejected and not is_coding:
                        if not self.ui_active:
                            console.print(f"  [bold yellow]⚡ [{_ver_guard.action.value}] Action '{tool_name}' rejected. Guiding to independent verification.[/bold yellow]")
                        messages.append(self._tool_feedback(_ver_guard.prompt, tool_call_id))
                        continue

                    # Emit tool.started event
                    self.event_bus.emit(
                        EventType.TOOL_STARTED,
                        {"tool": tool_name, "args": {k: str(v)[:100] for k, v in tool_args.items()}},
                        assessment_id=session_id,
                    )
                    tool_start_time = time.time()

                    # Budget: record tool call
                    self.budget.record_tool_call()

                    # Stagnation & loop detection via LoopRecoveryController
                    self.recovery_controller.record_action(
                        tool_name=tool_name,
                        arguments=tool_args,
                        success=True
                    )
                    is_loop, loop_tool = self.recovery_controller.check_stuck_loop()
                    if is_loop and loop_tool:
                        self.event_bus.emit(
                            EventType.LOOP_DETECTED,
                            {"tool": loop_tool, "repeated": self._stagnation_window},
                            severity=EventSeverity.WARN,
                            assessment_id=session_id,
                        )
                        next_phase, redirect_prompt, _ = self.recovery_controller.handle_stuck_state(
                            state=self.canonical_state,
                            target=target,
                            last_tool=loop_tool
                        )
                        if not self.ui_active:
                            console.print(f"[bold yellow]⚠ Loop detected on {loop_tool}. Reassessing state -> Transitioning to {next_phase.value}.[/bold yellow]")
                        messages.append({
                            "role": "user",
                            "content": redirect_prompt
                        })
                        if self.recovery_controller.max_redirects_exceeded():
                            # A stuck coding task has not passed its completion gate
                            status = TaskStatus.FAILED if is_coding else TaskStatus.COMPLETED
                            break
                        _redirected = True
                        break


                    # Clean operational event stream
                    tool_evt = AgentEvent(
                        AgentEventType.TOOL_START,
                        tool=tool_name,
                        summary=f"Selected: {tool_name}"
                    )
                    self.assessment_logger.log_event(tool_evt)
                    self.event_bus.emit(
                        EventType.AGENT_ACTION_PROPOSED,
                        {
                            "tool": tool_name,
                            "arguments": tool_args,
                            "target": target,
                            "tool_call_id": tool_call_id,
                        },
                        assessment_id=session_id,
                    )
                    self.event_bus.emit(
                        EventType.TOOL_STARTED,
                        {
                            "tool": tool_name,
                            "arguments": tool_args,
                            "target": target,
                            "tool_call_id": tool_call_id,
                        },
                        assessment_id=session_id,
                    )
                    if not self.ui_active:
                        console.print(tool_evt.format_cli())
                    else:
                        self.ui_status = f"Executing Tool: {tool_name}"
                        self.ui_action_tool = tool_name
                        self.ui_action_args = tool_args
                        self.live.update(self.get_dashboard_layout())

                    # Authoritative tool execution via ToolExecutor
                    exec_res = self.tool_executor.execute(
                        tool_name=tool_name,
                        arguments=tool_args,
                        target=target,
                        session_id=session_id,
                        state=self.canonical_state,
                        policy_engine=policy_engine,
                        sandbox=sandbox,
                        knowledge=self.knowledge,
                        selector=self.selector,
                        ui_active=self.ui_active,
                    )

                    tool_args = exec_res.arguments
                    tool_elapsed = exec_res.duration
                    raw_res_str = exec_res.raw_output
                    tool_result = exec_res.raw_output
                    is_failed = not exec_res.success
                    exit_code = exec_res.exit_code
                    error_type = exec_res.error_type

                    # If candidate validation blocked pre-execution
                    if error_type in ("invalid_argument", "target_not_supported") and exit_code == 2 and not exec_res.cache_hit:
                        if not self.ui_active:
                            console.print(f"  [bold red]⛔ {raw_res_str}[/bold red]")
                        obs_msg = f"POLICY DENIED / ACTION BLOCKED: {raw_res_str}"
                        self.observations.append(obs_msg)
                        self.ui_observation = obs_msg
                        tool_response_content = (
                            f"{raw_res_str}\n\n"
                            f"Guidance: Select an action supported by the current verified attack surface."
                        )
                        messages.append({"role": "tool", "content": tool_response_content, "tool_call_id": tool_call_id})
                        continue

                    if is_failed:
                        summary_text = f"{tool_name} FAILED (exit {exit_code}, error: {error_type})"
                    else:
                        summary_text = self.assessment_logger.log_tool_call(
                            tool=tool_name,
                            arguments=tool_args,
                            raw_output=raw_res_str,
                            duration_s=tool_elapsed,
                            exit_code=exit_code
                        )

                    # Stream mode result display via AgentEvent
                    res_evt = AgentEvent(
                        AgentEventType.TOOL_RESULT,
                        tool=tool_name,
                        duration_s=tool_elapsed,
                        summary=summary_text,
                        result_summary=summary_text
                    )
                    self.assessment_logger.log_event(res_evt)
                    if not self.ui_active:
                        console.print(res_evt.format_cli())
                        if tool_name == "log_finding":
                            is_acc, v_find, v_reason = self.finding_verifier.verify_candidate_finding(
                                candidate=tool_args,
                                state=self.canonical_state,
                                session_id=session_id
                            )
                            if is_acc:
                                find_evt = AgentEvent(
                                    AgentEventType.FINDING,
                                    summary=v_find.title,
                                    severity=v_find.severity.value
                                )
                                self.assessment_logger.log_event(find_evt)
                                console.print(find_evt.format_cli())
                            else:
                                console.print(f"  [bold red]⚠ {v_reason}[/bold red]")
                    else:
                        self.ui_result = str(tool_result)
                        res_summary = str(tool_result).replace("\n", " ")
                        if len(res_summary) > 60:
                            res_summary = res_summary[:57] + "..."
                        self.ui_history.append({
                            "time": datetime.datetime.now().strftime("%H:%M:%S"),
                            "tool": tool_name,
                            "args": tool_args,
                            "result_summary": res_summary
                        })
                        self.live.update(self.get_dashboard_layout())

                    # Emit tool.completed or tool.failed event
                    tool_result_str = str(tool_result)
                    evt_type = EventType.TOOL_FAILED if is_failed else EventType.TOOL_COMPLETED
                    self.event_bus.emit(
                        evt_type,
                        {
                            "tool": tool_name,
                            "arguments": tool_args,
                            "target": target,
                            "duration_ms": int(tool_elapsed * 1000),
                            "duration_seconds": tool_elapsed,
                            "result_length": len(tool_result_str),
                            "result_preview": tool_result_str[:500],
                            "raw_output": raw_res_str,
                            "stdout": getattr(exec_res, "stdout", raw_res_str),
                            "stderr": getattr(exec_res, "stderr", ""),
                            "success": not is_failed,
                            "exit_code": exit_code,
                            "error_type": error_type,
                            "tool_call_id": tool_call_id,
                        },
                        assessment_id=session_id,
                    )

                    # Authoritative evidence ingestion into canonical AssessmentState and storage
                    p_start = time.time()
                    self.evidence_ingestor.ingest(
                        tool_result=exec_res,
                        state=self.canonical_state,
                        session_id=session_id,
                        target=target
                    )
                    if self.canonical_state:
                        try:
                            self.canonical_state.derive_hypotheses_from_evidence()
                        except Exception:
                            pass
                        # Sync canonical state into AttackGraph for recursive work tracking
                        try:
                            self._attack_graph.sync_from_state(self.canonical_state)
                        except Exception:
                            pass
                        # Sync canonical state into derived AssetGraph
                        try:
                            self.knowledge.sync_from_state(self.canonical_state)
                        except Exception:
                            pass
                    self.profile_data["parser_time"] += (time.time() - p_start)
                    self.profile_data["tool_execution_time"] += tool_elapsed

                    if self.canonical_state:
                        predicates = getattr(self.canonical_state, "predicates", None) or VerificationPredicates()

                        # Record validation attempt & tool status
                        is_validation_tool = predicates.matches_validation_tool(tool_name, tool_args)
                        if is_validation_tool:
                            self.canonical_state.validation_attempted = True
                            if not is_failed:
                                self.canonical_state.validation_tool_success = True
                                self.canonical_state.last_validation_output = raw_res_str
                                req_url = str(tool_args.get("url") or f"http://{target}/")
                                token = predicates.extract_session_token(raw_res_str)
                                if token:
                                    self.canonical_state.session_credentials["Cookie"] = token
                                elif any(kw in str(tool_args) for kw in predicates.validation_arg_keywords):
                                    self.canonical_state.session_credentials["Cookie"] = predicates.default_session_cookie

                                self.canonical_state.get_session_store().update_from_http_response(
                                    target_url=req_url,
                                    status_code=200,
                                    headers={},
                                    body=raw_res_str
                                )

                                if self.canonical_state.time_to_validation is None:
                                    self.canonical_state.time_to_validation = round(time.time() - loop_start_time, 2)
                                if self.canonical_state.objective_status in (ObjectiveStatus.OBJECTIVE_UNREACHED, ObjectiveStatus.OBJECTIVE_FAILED):
                                    adv_ok = self.canonical_state.advance_objective(
                                        ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED,
                                        reason="Validation tool succeeded against target",
                                        elapsed_seconds=time.time() - loop_start_time,
                                        iteration=iteration,
                                    )
                                    if adv_ok:
                                        self.canonical_state.transition(AssessmentPhase.VERIFICATION, "Validation succeeded. Transitioning to independent verification.")
                                        self.canonical_state.generate_verification_candidates()
                                        self.canonical_state._update_action_queues()

                        # Check for proof of compromise markers in tool result
                        matched_marker = predicates.matches_proof(raw_res_str)
                        if matched_marker and not is_failed:
                            req_url = str(tool_args.get("url") or f"http://{target}/")
                            active_sess = self.canonical_state.get_session_store().get_active_session_for_request(req_url)
                            if active_sess:
                                active_sess.verification_status = SessionVerificationStatus.VERIFIED

                            # Ensure forward transition through unverified if still unreached
                            if self.canonical_state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED:
                                self.canonical_state.advance_objective(
                                    ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED,
                                    reason=f"Proof marker '{matched_marker}' detected in response",
                                    elapsed_seconds=time.time() - loop_start_time,
                                    iteration=iteration,
                                )

                            self.canonical_state.advance_objective(
                                ObjectiveStatus.OBJECTIVE_VERIFIED,
                                reason="Verification proof captured. Ready for final report.",
                                elapsed_seconds=time.time() - loop_start_time,
                                iteration=iteration,
                                proof=matched_marker,
                            )
                            self.canonical_state.transition(AssessmentPhase.REPORT, "Verification proof captured. Ready for final report.")

                            for hyp in self.canonical_state.get_active_hypotheses():
                                if str(hyp.port) in str(tool_args) or hyp.vulnerability_type in tool_name or "http" in tool_name or "request" in tool_name or "web" in tool_name or "sqlmap" in tool_name:
                                    hyp.verified = True
                                    hyp.status = HypothesisStatus.VERIFIED
                                    self.canonical_state.record_exploit_attempt(
                                        hypothesis_id=hyp.id,
                                        tool_name=tool_name,
                                        target=hyp.target,
                                        port=hyp.port,
                                        arguments=tool_args,
                                        status=ExploitStatus.SUCCESS,
                                        verified=True
                                    )
                                    self.canonical_state.record_finding(
                                        title=f"Verified Vulnerability: {hyp.vulnerability_type} on port {hyp.port}",
                                        severity="HIGH",
                                        description=f"Automated validation confirmed {hyp.vulnerability_type} with proof marker in response.",
                                        evidence_ids=list(hyp.evidence_ids),
                                        proof=raw_res_str[:300]
                                    )
                                    break

                            if not self.canonical_state.findings:
                                active_hyps = self.canonical_state.get_active_hypotheses()
                                target_hyp = active_hyps[0] if active_hyps else None
                                eids = list(target_hyp.evidence_ids) if target_hyp else list(self.canonical_state.get_all_evidence_ids())
                                self.canonical_state.record_finding(
                                    title=predicates.fallback_finding_title,
                                    severity="HIGH",
                                    description=predicates.fallback_finding_description,
                                    evidence_ids=eids,
                                    proof=raw_res_str[:300]
                                )

                    # Update observations list
                    if is_failed:
                        observation_msg = f"Executed {tool_name} with {tool_args}. Status: FAILED (exit {exit_code}, error: {error_type}). Result: {tool_result}"
                    else:
                        observation_msg = f"Executed {tool_name} with {tool_args}. Status: SUCCESS (exit {exit_code}). Result: {tool_result}"
                    self.observations.append(observation_msg)

                    if self.ui_active:
                        self.ui_observation = f"Obtained tool result from {tool_name}."
                        self.ui_observation_meaning = f"The environment returned: {tool_result}"
                        self.ui_observation_next = decision_summary.get("next_step") or "Evaluate result in next decision iteration"
                        self.live.update(self.get_dashboard_layout())

                    # Context minimization: compress huge tool outputs before appending to LLM conversation history
                    compact_tool_output = self.context_manager.compress_tool_output(
                        tool_name=tool_name,
                        raw_output=raw_res_str,
                        state=self.canonical_state,
                        max_chars=1200
                    )


                    # Prepare structured tool response message for LLM
                    if is_failed:
                        hyp_str = ""
                        if self.canonical_state:
                            hyps = self.canonical_state.get_active_hypotheses()
                            if hyps:
                                hyp_str = f"{hyps[0].vulnerability_type} on {hyps[0].port}"
                        diag = FailureDiagnosticsEngine.diagnose_failure(
                            tool_name=tool_name,
                            arguments=tool_args,
                            raw_output=compact_tool_output,
                            exit_code=exit_code,
                            error_type=error_type,
                            active_hypothesis=hyp_str,
                        )
                        tool_response_content = (
                            f"Tool '{tool_name}' returned status FAILED (exit code {exit_code}, error: {error_type}).\n"
                            f"Output:\n{compact_tool_output}\n\n"
                            f"{'' if is_coding else diag.format_feedback_block()}"
                        )
                    else:
                        tool_response_content = compact_tool_output
                        if self.canonical_state and not is_coding:
                            self.canonical_state._update_action_queues()
                            planner_status = self.canonical_state.format_planner_status()
                            # Augment context with HypothesisEngine proposals and AttackGraph summary
                            try:
                                _proposals = self._hypothesis_engine.propose_next_actions(
                                    self.canonical_state, self._attack_graph, max_proposals=3
                                )
                                self._hypothesis_engine.ensure_hypotheses_in_state(
                                    self.canonical_state, _proposals
                                )
                                _hyp_block = self._hypothesis_engine.format_context_block(_proposals)
                                _graph_block = self._attack_graph.to_summary()
                                tool_response_content += (
                                    f"\n\n{planner_status}"
                                    f"\n\n{_graph_block}"
                                    f"\n\n{_hyp_block}"
                                )
                            except Exception:
                                tool_response_content += f"\n\n{planner_status}"
                        elif self.attack_surface.services and not is_coding:
                            tool_response_content += (
                                f"\n\n[VERIFIED ATTACK SURFACE DISCOVERIES - GROUND TRUTH]\n"
                                f"{self.attack_surface.format_evidence_summary()}"
                            )

                    # Append tool response message to messages history
                    if self.native_tools:
                        tool_msg = {
                            "role": "tool",
                            "content": tool_response_content
                        }
                        if tool_call_id:
                            tool_msg["tool_call_id"] = tool_call_id
                    else:
                        tool_msg = {
                            "role": "user",
                            "content": f"Tool '{tool_name}' execution result:\n{tool_response_content}"
                        }
                    messages.append(tool_msg)

                    # Check action budget limit
                    if len(self.observations) >= self.max_actions:
                        if not self.ui_active:
                            console.print(f"\n[bold yellow]⚡ Action budget limit reached ({self.max_actions} actions). Concluding assessment.[/bold yellow]\n")
                        # A coding task that ran out of actions has not passed its completion gate
                        status = TaskStatus.FAILED if is_coding else TaskStatus.COMPLETED
                        break


                if status == TaskStatus.COMPLETED:
                    break

                # If the loop detector redirected the model to exploitation, skip sleep and re-query
                if _redirected:
                    _redirected = False
                    continue

                # Brief sleep between iterations
                time.sleep(0.5)

        except KeyboardInterrupt:
            if not self.ui_active:
                console.print("\n[bold yellow]Execution interrupted by user. Pausing task.[/bold yellow]")
            else:
                self.ui_status = "Paused"
                self.live.update(self.get_dashboard_layout())
            status = TaskStatus.PAUSED
            self.assessment_state.pause()
            self.event_bus.emit(
                EventType.ASSESSMENT_PAUSED,
                {"reason": "User interrupted", "iteration": iteration},
                assessment_id=session_id,
            )
        except Exception as e:
            if not self.ui_active:
                console.print(f"[bold red]Loop Exception: {e}[/bold red]")
            else:
                self.ui_status = f"Error: {e}"
                self.live.update(self.get_dashboard_layout())
            import traceback
            traceback.print_exc()
            status = TaskStatus.FAILED
            self.assessment_state.transition(AssessmentPhase.FAILED)
        finally:
            if self.ui_active:
                self.live.stop()

        self.storage.update_session_status(session_id, status)

        # Emit assessment lifecycle completion event
        completion_event_type = {
            TaskStatus.COMPLETED: EventType.ASSESSMENT_COMPLETED,
            TaskStatus.FAILED: EventType.ASSESSMENT_STOPPED,
            TaskStatus.PAUSED: EventType.ASSESSMENT_PAUSED,
        }.get(status, EventType.ASSESSMENT_STOPPED)

        if status != TaskStatus.PAUSED:  # pause event already emitted above
            self.event_bus.emit(
                completion_event_type,
                {
                    "status": status.value,
                    "iterations": iteration,
                    "budget": self.budget.get_status(),
                    "state": self.assessment_state.to_dict(),
                },
                assessment_id=session_id,
            )

        # After stopping the live dashboard, print final CLI output if active
        if self.ui_active:
            console.print(f"\n[bold green]Task {session_id} finished with status: {status.value}[/bold green]")
            if status == TaskStatus.COMPLETED:
                console.print(f"\n[bold green]Final Response:[/bold green]\n{content or thinking_text or 'No response content'}")

        # Render Evidence-Grounded Security Audit Summary via ReportGenerator
        if status == TaskStatus.COMPLETED:
            report_data = self.report_generator.generate_and_render(
                state=self.canonical_state,
                session_id=session_id,
                target=target,
                scope=scope,
                goal=task_goal,
                observations=self.observations,
                iteration=iteration,
                elapsed_seconds=time.time() - (self.ui_start_time if getattr(self, "ui_start_time", None) else time.time()),
                budget_status=self.budget.get_status() if hasattr(self.budget, "get_status") else {},
                ui_active=self.ui_active
            )

        # Print execution metrics summary in stream mode
        if not self.ui_active:
            elapsed = time.time() - (self.ui_start_time if getattr(self, "ui_start_time", None) else time.time())
            tools_count = len(self.observations)
            failed_count = sum(1 for obs in self.observations if "FAILED" in obs or "Exit code: 1" in obs or "Exit code: 12" in obs or "error:" in obs.lower())
            successful_count = max(0, tools_count - failed_count)
            retries_count = getattr(self.assessment_state, "retry_tracker", None).total_retries if hasattr(self.assessment_state, "retry_tracker") else 0
            b_status = self.budget.get_status() if hasattr(self.budget, "get_status") else {}
            tokens_val = b_status.get("tokens", {}).get("used", 0) or (iteration * 1450)
            b_pct = b_status.get("pct_used", min(100.0, (iteration / self.max_iterations) * 100))
            avg_lat = (sum(self.model_latencies) / len(self.model_latencies)) if self.model_latencies else None
            render_execution_metrics(
                elapsed_seconds=elapsed,
                tools_count=tools_count,
                successful_count=successful_count,
                failed_count=failed_count,
                retries_count=retries_count,
                tokens=tokens_val,
                budget_pct=b_pct,
                duplicate_calls_blocked=self.duplicate_calls_blocked,
                cache_hits=self.cache_hits,
                avg_model_latency=avg_lat
            )

            if self.config.get("profile", False):
                render_performance_profile(self.profile_data)

        return {
            "status": status.value,
            "session_id": session_id,
            "iterations": iteration,
            "observations": self.observations,
            "messages": messages,
            "budget": self.budget.to_dict(),
            "assessment_state": self.assessment_state.to_dict(),
        }
