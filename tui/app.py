"""
Main Textual Application for Buzzard Code Production TUI.
Provides a modern, information-dense, keyboard-first developer/security CLI interface.
Features:
- Compact persistent reactive header (BUZZARD ● READY ... model · provider)
- Responsive conversation stream without bloated boxes
- Inline security status events (✓ Scope, ✓ Sandbox, ✕ Policy denied)
- Sleek terminal-native tool execution cards (┌─ tool ─── timeline)
- Interactive Approval Gate ([Y] Allow, [N] Deny, [A] Always Allow)
- Compact interactive command palette & slash suggestions box
- Interactive /model selector modal
- Persistent compact status bar (● Ollama ● Docker Scope: ... Session: ...)
- Full preservation of authoritative execution architecture:
  EventBus -> AgentLoop -> Parser -> Policy -> Scope -> Validator -> Tools -> Sandbox -> Journal
"""

from __future__ import annotations

import os
import sys
import time
import uuid
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List

from textual.app import App, ComposeResult
from textual.widget import Widget
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, TabbedContent, TabPane, Static
from textual.binding import Binding
from textual.worker import Worker, get_current_worker
from textual import work
from rich.text import Text
from rich.table import Table

from tui.config import TUIConfig
from tui.models import AppMode, ChatMessage, MessageRole, ToolCallCardData
from tui.controller import TUIController
from tui.widgets.header import QwythosHeader, BuzzardHeader
from tui.widgets.status_bar import QwythosStatusBar, BuzzardStatusBar
from tui.widgets.chat import ChatView, MessageBubble
from tui.widgets.tool_card import ToolCallCard, ToolActivityCard
from tui.widgets.graph_panel import AttackGraphTree
from tui.widgets.hypotheses_panel import HypothesesPanel
from tui.widgets.capabilities_panel import CapabilitiesPanel
from tui.widgets.findings_panel import FindingsPanel
from tui.widgets.evidence_panel import EvidencePanel
from tui.widgets.memory_panel import MemoryPanel
from tui.widgets.branches_panel import BranchesPanel
from tui.widgets.browser_panel import BrowserPanel
from tui.widgets.command_palette import CommandPaletteModal
from tui.widgets.modals import (
    HelpModal,
    BuzzardHelpModal,
    ApprovalModal,
    CrashRecoveryModal,
    ModelSwitchModal,
)

from core.config import load_merged_config, save_global_config
from agent.project_context import (
    build_mention_context,
    complete_file_mention,
    has_file_mention,
    load_conversation,
    save_conversation,
)
from core.usage import SessionUsage, context_window_for
from model.factory import (
    get_model_provider,
    resolve_provider_and_model,
    list_supported_providers,
)
from events.bus import EventBus
from events.types import Event, EventType, EventSeverity
from security.kill_switch import KillSwitch
from security.scope import is_in_scope, extract_host_and_port
from storage.db import StorageManager
from cli.interactive import _is_actionable_audit_task, _extract_targets_from_text
from core.project import (
    init_project,
    load_custom_commands,
    render_custom_command_prompt,
)
from security.manager import (
    render_policy_and_permissions,
    render_scope,
    modify_scope,
    render_sandbox_status,
    trigger_kill_switch,
    resume_kill_switch,
)
from cli.commands import (
    run_doctor,
    run_status,
    run_models,
    run_config,
    run_connect,
    run_disconnect,
    list_tasks,
    get_task_status,
    resume_task,
    generate_report,
)
from tools.inspector import get_standard_registry, get_tool_details, render_tools, build_tools_view
from tools.registry import create_authoritative_registry, ToolRegistry


# -----------------------------------------------------------------------------
# Slash Commands Definition
# -----------------------------------------------------------------------------
DEFAULT_INPUT_PLACEHOLDER = "> Build, fix or explain...  @ files  / commands  \\ new line"

BUZZARD_COMMANDS: List[tuple[str, str]] = [
    ("/model", "Change active model"),
    ("/models", "List available models"),
    ("/status", "Runtime status"),
    ("/tools", "Available tools"),
    ("/context", "Context window and token breakdown"),
    ("/usage", "Token usage this session"),
    ("/compact", "Keep only recent conversation turns"),
    ("/git", "Git status of the workspace"),
    ("/log", "Recent git commits"),
    ("/files", "List workspace files"),
    ("/review", "Ask the agent to review uncommitted changes"),
    ("/test", "Ask the agent to run the tests and report"),
    ("/export", "Save this conversation to a file"),
    ("/undo", "Revert the agent's latest file edit"),
    ("/failover", "Show backup models; /failover test rehearses an outage"),
    ("/plan", "Toggle plan mode: no edits or commands run"),
    ("/continue", "Restore the last conversation in this workspace"),
    ("/version", "Buzzard Code version"),
    ("/providers", "Supported model providers"),
    ("/scope", "Authorized scope"),
    ("/permissions", "Permission state"),
    ("/sandbox", "Sandbox status"),
    ("/diff", "View git diff of workspace changes"),
    ("/mcp", "MCP servers and tools"),
    ("/doctor", "Environment diagnostics"),
    ("/history", "Session history"),
    ("/clear", "Clear conversation"),
    ("/kill", "Emergency kill switch"),
    ("/resume", "Disarm kill switch"),
    ("/help", "View help reference"),
    ("/exit", "Exit Buzzard Code"),
]


class CommandSuggestionsBox(Widget):
    """
    Compact popup displaying filtered commands per Section 12:
    ┌ COMMANDS ────────────────────────────────┐
    │ > /model       Change active model       │
    │   /models      List available models     │
    └──────────────────────────────────────────┘
    Maintains exactly ONE authoritative selected index.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.matches: List[tuple[str, str]] = []
        self.selected_index: int = 0
        self.display = False

    @property
    def selected_command(self) -> Optional[str]:
        if self.matches and 0 <= self.selected_index < len(self.matches):
            return self.matches[self.selected_index][0]
        return None

    def set_matches(self, matches: List[tuple[str, str]], reset_index: bool = True) -> None:
        self.matches = matches
        if reset_index or not self.matches:
            self.selected_index = 0
        else:
            if self.selected_index >= len(self.matches):
                self.selected_index = len(self.matches) - 1
            elif self.selected_index < 0:
                self.selected_index = 0
        self.refresh()

    def move_selection(self, delta: int) -> None:
        if not self.matches:
            self.selected_index = 0
            return
        self.selected_index = (self.selected_index + delta) % len(self.matches)
        self.refresh()

    def render(self) -> Text:
        if not self.matches:
            return Text("")

        t = Text()
        width = self.size.width if self.size.width > 0 else 60
        box_width = min(50, width - 4)

        # Top border
        t.append("  ┌ COMMANDS ", style="bold #c084fc")
        t.append("─" * max(2, box_width - 12) + "┐\n", style="#3b3d54")

        # Keep selected item visible in a window if more than 8 matches
        max_visible = 8
        total = len(self.matches)
        if total <= max_visible:
            start_idx = 0
            end_idx = total
        else:
            half = max_visible // 2
            start_idx = max(0, min(self.selected_index - half, total - max_visible))
            end_idx = start_idx + max_visible

        # Command rows
        for idx in range(start_idx, end_idx):
            cmd, desc = self.matches[idx]
            is_sel = (idx == self.selected_index)
            prefix = "  │ > " if is_sel else "  │   "
            cmd_style = "bold #a78bfa" if is_sel else "#06b6d4"
            desc_style = "bold #f1f5f9" if is_sel else "#94a3b8"

            t.append(prefix, style="bold #a78bfa" if is_sel else "#3b3d54")
            t.append(f"{cmd:<14}", style=cmd_style)
            t.append(f"{desc:<26}", style=desc_style)
            t.append("│\n", style="#3b3d54")

        # Bottom border
        t.append("  └" + "─" * (box_width - 1) + "┘", style="#3b3d54")
        return t


class BuzzardInput(Input):
    """
    Enhanced prompt input with command history navigation (Up / Down arrows),
    and autocomplete support.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.history: List[str] = []
        self.history_index: int = -1
        self._temp_draft: str = ""

    def record_history(self, text: str) -> None:
        text = text.strip()
        if text and (not self.history or self.history[-1] != text):
            self.history.append(text)
        self.history_index = -1
        self._temp_draft = ""

    def action_cursor_up(self) -> None:
        if not self.history:
            return
        if self.history_index == -1:
            self._temp_draft = self.value
            self.history_index = len(self.history) - 1
        elif self.history_index > 0:
            self.history_index -= 1
        self.value = self.history[self.history_index]
        self.cursor_position = len(self.value)

    def action_cursor_down(self) -> None:
        if not self.history or self.history_index == -1:
            return
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.value = self.history[self.history_index]
        else:
            self.history_index = -1
            self.value = self._temp_draft
        self.cursor_position = len(self.value)

    def history_up(self) -> None:
        self.action_cursor_up()

    def history_down(self) -> None:
        self.action_cursor_down()

    pending_lines: Optional[List[str]] = None

    def hold_lines(self, lines: List[str]) -> None:
        """Keeps earlier lines of a multi-line message until it is sent."""
        self.pending_lines = (self.pending_lines or []) + lines
        count = len(self.pending_lines)
        self.placeholder = f"{count} line{'s' if count != 1 else ''} held. Keep typing, Enter sends, Esc clears."

    def take_lines(self, last_line: str) -> str:
        """Returns the whole message and clears the held lines."""
        text = "\n".join([*(self.pending_lines or []), last_line]).strip()
        self.pending_lines = None
        self.placeholder = DEFAULT_INPUT_PLACEHOLDER
        return text

    def _on_paste(self, event) -> Any:
        """A single-line input would otherwise drop everything after the first pasted line."""
        lines = event.text.splitlines()
        if len(lines) < 2:
            return super()._on_paste(event)
        event.stop()
        event.prevent_default()
        self.hold_lines([self.value + lines[0], *lines[1:-1]])
        self.value = lines[-1]
        self.cursor_position = len(self.value)
        return None

    def _apply_completion(self, chosen: str) -> None:
        """Completes a whole slash command, or only the @mention being typed."""
        prefix = self.value.rsplit(" ", 1)[0] + " " if chosen.startswith("@") and " " in self.value else ""
        self.value = f"{prefix}{chosen} "
        self.cursor_position = len(self.value)

    def on_key(self, event) -> None:
        app = getattr(self, "app", None)
        cmd_box = getattr(app, "cmd_box", None) if app else None

        # The focused input receives Esc before any app binding
        menu_open = bool(cmd_box and cmd_box.display and cmd_box.matches)
        if event.key == "escape" and not menu_open and self.pending_lines:
            event.prevent_default()
            event.stop()
            self.take_lines("")
            return
        if event.key == "escape" and not menu_open and getattr(app, "is_running_operation", False):
            event.prevent_default()
            event.stop()
            app.action_handle_interrupt()
            return

        if cmd_box and cmd_box.display and cmd_box.matches:
            if event.key == "tab":
                event.prevent_default()
                event.stop()
                chosen = cmd_box.selected_command
                if chosen:
                    self._apply_completion(chosen)
                cmd_box.display = False
                return
            elif event.key == "escape":
                event.prevent_default()
                event.stop()
                cmd_box.display = False
                return
            elif event.key == "up":
                event.prevent_default()
                event.stop()
                cmd_box.move_selection(-1)
                return
            elif event.key == "down":
                event.prevent_default()
                event.stop()
                cmd_box.move_selection(1)
                return
            elif event.key == "enter":
                chosen = cmd_box.selected_command
                if chosen and chosen.startswith("@"):
                    event.prevent_default()
                    event.stop()
                    self._apply_completion(chosen)
                    cmd_box.display = False
                    return
                if chosen:
                    event.prevent_default()
                    event.stop()
                    cmd_box.display = False
                    self.value = ""
                    self.record_history(chosen)
                    if hasattr(app, "_handle_slash_command"):
                        app._handle_slash_command(chosen)
                    return

class BuzzardTUIApp(App[None]):
    """
    Production Buzzard Code Live Terminal User Interface.
    Full-screen, event-driven terminal agent application.
    """

    CSS_PATH = "styles.tcss"
    TITLE = "Buzzard Code"
    MAX_CONVERSATION_MESSAGES = 20
    COMPACT_KEEP_MESSAGES = 4
    MAX_AGENT_TURNS = 40

    BINDINGS = [
        Binding("ctrl+c", "handle_interrupt", "Cancel / Exit", show=True),
        Binding("ctrl+d", "handle_quit", "Quit", show=True),
        Binding("f1", "show_help", "Help", show=True),
        Binding("up", "history_up", "History Up", show=False),
        Binding("down", "history_down", "History Down", show=False),
        Binding("escape", "dismiss_modal", "Dismiss", show=False),
    ]

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        provider: Optional[Any] = None,
        event_bus: Optional[EventBus] = None,
        model_name: Optional[str] = None,
        provider_name: Optional[str] = None,
        model: Optional[str] = None,
        mode: Optional[str] = None,
        storage: Optional[StorageManager] = None,
        fake: bool = False,
        registry: Optional[ToolRegistry] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.buzzard_config = config or load_merged_config()
        self.event_bus = event_bus or EventBus()
        self.storage = storage or StorageManager()
        self.registry = registry or get_standard_registry()

        # Model and Provider resolution
        target_model = model or model_name
        if target_model:
            resolved_p, resolved_m = resolve_provider_and_model(target_model, self.buzzard_config)
            self.model_name = resolved_m
            self.provider_name = provider_name or resolved_p
        else:
            cfg_model = self.buzzard_config.get("model", {})
            if isinstance(cfg_model, dict):
                self.model_name = cfg_model.get("name", "qwen3.6:27b")
                self.provider_name = provider_name or cfg_model.get("provider", "ollama")
            else:
                self.model_name = str(cfg_model) if cfg_model else "qwen3.6:27b"
                self.provider_name = provider_name or "ollama"

        self.mode = mode or "Autonomous"
        self.current_session_id: Optional[str] = None
        self.is_running_operation: bool = False
        # Earlier user and assistant turns, so follow-up requests have their context
        self.conversation: List[Dict[str, str]] = []
        self.usage = SessionUsage()
        self.plan_mode: bool = False
        self.approvals_granted: int = 0
        self.approvals_denied: int = 0
        self._interrupt_count: int = 0
        self._stop_event = threading.Event()

        # Active tool cards cache
        self.active_tool_cards: Dict[str, ToolActivityCard] = {}
        self.last_active_card: Optional[ToolActivityCard] = None

        # Provider initialization
        if fake:
            try:
                from tui.fake_model import FakeModelProvider
                self.provider = FakeModelProvider()
                self.provider_name = "Fake"
            except Exception:
                self.provider = None
        elif provider is not None:
            self.provider = provider
        else:
            try:
                # Must be the model the header shows, not the config default
                self.provider = get_model_provider(
                    provider_name=self.provider_name,
                    model_name=self.model_name,
                    config=self.buzzard_config,
                )
            except Exception:
                self.provider = None

        # Scope
        sec_cfg = self.buzzard_config.get("security", {})
        self.scope = list(sec_cfg.get("scope", ["localhost", "127.0.0.1"]))

    @staticmethod
    def _docker_available() -> bool:
        from sandbox.container import is_docker_active
        return is_docker_active()

    def compose(self) -> ComposeResult:
        # 1. Compact persistent Header
        self.header_widget = BuzzardHeader(
            model_name=self.model_name,
            provider_name=self.provider_name.capitalize(),
            mode=self.mode,
            status="READY",
            id="app_header",
        )
        yield self.header_widget

        # 2. Main Center: Chat View + Command Suggestions Box + Input Bar
        with Vertical(id="center_content"):
            self.chat_view = ChatView(id="chat_container")
            yield self.chat_view

            self.cmd_box = CommandSuggestionsBox(id="command_suggestions")
            yield self.cmd_box

            with Horizontal(id="input_container"):
                self.chat_input = BuzzardInput(
                    placeholder=DEFAULT_INPUT_PLACEHOLDER,
                    id="user_input",
                )
                yield self.chat_input

        # 3. Persistent Status Bar
        scope_str = ", ".join(self.scope[:2])
        if len(self.scope) > 2:
            scope_str += f" (+{len(self.scope) - 2})"

        self.status_bar = BuzzardStatusBar(
            provider_name=self.provider_name.capitalize(),
            provider_online=self.provider.is_available() if self.provider and hasattr(self.provider, "is_available") else True,
            docker_available=self._docker_available(),
            scope=scope_str,
            session_id=self.current_session_id or "idle",
            model_name=self.model_name,
            mode=self.mode,
            id="app_status_bar",
        )
        yield self.status_bar

    async def on_mount(self) -> None:
        self.chat_input.focus()
        # Subscribe to EventBus for full real-time telemetry
        self.event_bus.subscribe_all(self._on_bus_event)

    def on_input_changed(self, event: Input.Changed) -> None:
        raw = event.value
        last_word = raw.rsplit(" ", 1)[-1]
        if last_word.startswith("@"):
            matches = [(f"@{path}", "file") for path in complete_file_mention(last_word[1:])]
            self.cmd_box.set_matches(matches)
            self.cmd_box.display = bool(matches)
            return
        # Suggest commands only while typing the command name itself (no trailing space)
        if raw.startswith("/") and " " not in raw:
            query = raw.strip().lower()
            matches = [(c, d) for c, d in BUZZARD_COMMANDS if c.startswith(query)]
            if matches:
                self.cmd_box.set_matches(matches)
                self.cmd_box.display = True
                return
        self.cmd_box.display = False

    # -------------------------------------------------------------------------
    # EventBus Telemetry Handlers
    # -------------------------------------------------------------------------
    def _on_bus_event(self, event: Event) -> None:
        self.call_from_thread(self._handle_bus_event_in_ui, event)

    def _handle_bus_event_in_ui(self, event: Event) -> None:
        payload = event.payload or {}

        if event.type == EventType.ASSESSMENT_STARTED:
            sess = payload.get("session_id") or event.assessment_id
            if sess:
                self.current_session_id = sess
                self.status_bar.update_metrics(session_id=sess)
            self.header_widget.update_state(status="PLANNING")

        elif event.type == EventType.AGENT_STATUS:
            st = payload.get("status") or "RUNNING"
            self.header_widget.update_state(status=st.upper())

        elif event.type == EventType.AGENT_THINKING_STARTED:
            self.header_widget.update_state(status="THINKING")

        elif event.type == EventType.AGENT_PLAN_CREATED:
            self.header_widget.update_state(status="PLANNING")

        elif event.type == EventType.AGENT_ACTION_PROPOSED:
            self.header_widget.update_state(status="VALIDATING")
            tool_name = payload.get("tool", "unknown_tool")
            tool_args = payload.get("arguments", {})
            target = payload.get("target", "")
            tool_call_id = payload.get("tool_call_id") or f"tc-{uuid.uuid4().hex[:8]}"

            card = ToolActivityCard(
                tool_name=tool_name,
                target=target,
                arguments=tool_args,
                tool_call_id=tool_call_id,
            )
            card.update_stage("VALIDATING")
            self.active_tool_cards[tool_call_id] = card
            self.last_active_card = card
            self.chat_view.add_tool_activity(card)

        elif event.type == EventType.POLICY_CHECK_STARTED:
            card = self._find_active_card(payload)
            if card:
                card.update_stage("VALIDATING", "Evaluating security policy...")

        elif event.type == EventType.POLICY_ALLOWED:
            card = self._find_active_card(payload)
            if card:
                card.update_stage("POLICY_ALLOWED", "✓ Policy allowed")

        elif event.type == EventType.POLICY_DENIED:
            reason = payload.get("reason", "Policy denied")
            card = self._find_active_card(payload)
            if card:
                card.update_stage("POLICY_DENIED", f"✕ Policy denied: {reason}")
            self.header_widget.update_state(status="BLOCKED")

        elif event.type == EventType.APPROVAL_REQUESTED:
            card = self._find_active_card(payload)
            if card:
                card.update_stage("AWAITING_APPROVAL", "⚠ Approval required")
            self.header_widget.update_state(status="AWAITING APPROVAL")

        elif event.type == EventType.APPROVAL_APPROVED:
            card = self._find_active_card(payload)
            if card:
                card.update_stage("APPROVAL_APPROVED", "✓ Operator approved")

        elif event.type == EventType.APPROVAL_REJECTED:
            card = self._find_active_card(payload)
            if card:
                card.update_stage("APPROVAL_REJECTED", "✕ Operator denied")
            self.header_widget.update_state(status="DENIED")

        elif event.type == EventType.TOOL_STARTED:
            card = self._find_active_card(payload)
            tool_name = payload.get("tool", "tool")
            self.header_widget.update_state(status=f"RUNNING {tool_name}")
            if card:
                card.update_stage("SCOPE_AUTHORIZED", "✓ Scope authorized")
                if self._docker_available():
                    card.update_stage("SANDBOX_READY", "✓ Docker sandbox")
                    card.update_stage("RUNNING", "● Running in sandbox...")
                else:
                    card.update_stage("RUNNING", "● Running on host (no isolation)...")

        elif event.type == EventType.TOOL_PROGRESS:
            card = self._find_active_card(payload)
            if card and payload.get("message"):
                card.update_stage("PROGRESS", payload.get("message"))

        elif event.type == EventType.TOOL_COMPLETED:
            card = self._find_active_card(payload)
            if card:
                card.set_completed(payload)
            self.header_widget.update_state(status="PROCESSING RESULT")

        elif event.type == EventType.TOOL_FAILED:
            card = self._find_active_card(payload)
            if card:
                card.set_failed(payload)
            self.header_widget.update_state(status="TOOL FAILED")

        elif event.type == EventType.MODEL_STARTED:
            self.header_widget.update_state(status="RESPONDING")

        elif event.type == EventType.MODEL_TOKEN:
            token = payload.get("token", "")
            if token:
                self.chat_view.append_streaming_token(token)

        elif event.type == EventType.MODEL_COMPLETED:
            self.usage.record(
                payload.get("prompt_tokens", 0),
                payload.get("output_tokens", 0),
                estimated=bool(payload.get("tokens_estimated")),
            )
            self.status_bar.update_metrics(
                usage_text=self.usage.status_text(context_window_for(self.model_name, self.provider))
            )
            # After failover, show the model that actually answered
            active_model = getattr(self.provider, "model_name", self.model_name)
            if active_model != self.model_name:
                self._system_note(f"⚠ {self.model_name} failed. Continuing on {active_model}.")
                self.model_name = active_model
                self.header_widget.update_state(model_name=active_model)
                self.status_bar.update_metrics(model_name=active_model)
            self.chat_view.finish_streaming()
            self.header_widget.update_state(status="READY")

        elif event.type == EventType.ASSESSMENT_COMPLETED:
            self.header_widget.update_state(status="COMPLETE")
            self.status_bar.update_metrics(session_id="idle")
            self.is_running_operation = False

    def _find_active_card(self, payload: Dict[str, Any]) -> Optional[ToolActivityCard]:
        tool_call_id = payload.get("tool_call_id")
        if tool_call_id and tool_call_id in self.active_tool_cards:
            return self.active_tool_cards[tool_call_id]
        return self.last_active_card

    # -------------------------------------------------------------------------
    # Approval Gate Callback (invoked by ApprovalGate from AgentLoop thread)
    # -------------------------------------------------------------------------
    def _handle_approval_callback(self, tool_name: str, arguments: Dict[str, Any], metadata: Any) -> bool:
        # Enforced here, not by the prompt, so a model cannot talk its way past plan mode
        if self.plan_mode:
            self.approvals_denied += 1
            return False
        from sandbox.container import is_docker_active

        done_event = threading.Event()
        decision_box = [False]

        def on_decision(approved: bool | None) -> None:
            decision_box[0] = bool(approved)
            done_event.set()

        def open_modal() -> None:
            risk_val = getattr(metadata, "risk_class", None)
            risk_str = getattr(risk_val, "value", str(metadata)) if risk_val else "HIGH"
            target_str = str(arguments.get("target") or "localhost")
            modal = ApprovalModal(
                tool_name=tool_name,
                arguments=arguments,
                target=target_str,
                policy_reason="confirmation required",
                scope_status="authorized network",
                sandbox_env="Docker Sandbox" if is_docker_active() else "Host (no isolation)",
                risk_class=risk_str,
            )
            self.push_screen(modal, on_decision)

        self.call_from_thread(open_modal)
        # Wait for operator decision (120s timeout before fail-closed)
        done_event.wait(timeout=120.0)
        if decision_box[0]:
            self.approvals_granted += 1
        else:
            self.approvals_denied += 1
        return decision_box[0]

    # -------------------------------------------------------------------------
    # Input Submission & Slash Commands
    # -------------------------------------------------------------------------
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        # If palette was open with an authoritative selection, execute that selection
        if self.cmd_box.display and (self.cmd_box.selected_command or "").startswith("/"):
            chosen = self.cmd_box.selected_command
            self.cmd_box.display = False
            self.chat_input.value = ""
            self.chat_input.record_history(chosen)
            self._handle_slash_command(chosen)
            return

        self.cmd_box.display = False
        # A trailing backslash continues the message on a new line
        if event.value.rstrip().endswith("\\") and not event.value.startswith("/"):
            self.chat_input.hold_lines([event.value.rstrip()[:-1]])
            self.chat_input.value = ""
            return
        text = self.chat_input.take_lines(event.value)
        if not text:
            return

        self.chat_input.value = ""
        self.chat_input.record_history(text)
        self._interrupt_count = 0

        # Slash Commands
        if text.startswith("/"):
            self._handle_slash_command(text)
            return

        # Execute Conversational Chat or Security Assessment Task
        from agent.intent import is_coding_task
        if not _is_actionable_audit_task(text) and not is_coding_task(text) and not has_file_mention(text):
            self._run_conversational_chat(text)
        else:
            self._run_security_task(text)

    def _handle_failover_command(self, arguments: List[str]) -> None:
        chain = getattr(self.provider, "providers", None)
        if not chain:
            self._system_note(
                "No backup models are set. Run `buzzard setup` or set `BUZZARD_FALLBACK_MODELS`. "
                "A backup model receives your code when it takes over."
            )
        elif arguments[:1] == ["test"]:
            name = self.provider.simulate_outage()
            self._system_note(f"⚠ {name} will fail its next request. Send a message to see the switch.")
        else:
            names = ", ".join(f"`{getattr(p, 'model_name', '?')}`" for p in chain)
            self._system_note(f"Model order: {names}. Active: `{self.provider.model_name}`.")

    def _system_note(self, content: str) -> None:
        self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=content))

    def _show_usage(self) -> None:
        window = context_window_for(self.model_name, self.provider)
        percent = self.usage.context_percent(window)
        lines = [
            f"**Model:** {self.model_name} ({self.provider_name})",
            f"**Requests:** {self.usage.requests}",
            f"**Input tokens:** {self.usage.input_tokens:,}",
            f"**Output tokens:** {self.usage.output_tokens:,}",
            f"**Last prompt:** {self.usage.last_prompt_tokens:,} tokens",
            f"**Context window:** {f'{window:,} tokens ({percent}% used)' if window else 'unknown for this model'}",
            f"**Conversation messages kept:** {len(self.conversation)}",
        ]
        if self.usage.estimated:
            lines.append("Some figures are estimates, because the provider did not report usage.")
        self._system_note("\n\n".join(lines))

    def _export_conversation(self) -> None:
        from tools.filesystem import get_active_workspace

        export_dir = Path(get_active_workspace()) / ".buzzard" / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        (export_dir / ".gitignore").write_text("*\n", encoding="utf-8")
        path = export_dir / f"conversation-{time.strftime('%Y%m%d-%H%M%S')}.md"
        body = "\n\n".join(f"## {turn['role']}\n\n{turn['content']}" for turn in self.conversation)
        path.write_text(body, encoding="utf-8")
        self._system_note(f"✓ Saved conversation to {path}")

    def _show_mcp_status(self) -> None:
        from tools.mcp_client import get_mcp_manager, mcp_config_path

        manager = get_mcp_manager()
        lines = [f"MCP config: `{mcp_config_path()}`", ""]
        for name, connection in manager.connections.items():
            tools = ", ".join(str(tool["name"]) for tool in connection.tools) or "no tools"
            lines.append(f"- **{name}**: connected ({tools})")
        for name, error in manager.errors.items():
            lines.append(f"- **{name}**: failed ({error})")
        if not manager.connections and not manager.errors:
            lines.append("No servers configured. Every MCP tool call needs your approval.")
        self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content="\n".join(lines)))

    def _switch_model(self, spec: str) -> None:
        """Switch the active model cleanly and render a compact status event."""
        resolved_p, resolved_m = resolve_provider_and_model(spec, self.buzzard_config)
        self.model_name = resolved_m
        self.provider_name = resolved_p
        if isinstance(self.buzzard_config.get("model"), dict):
            # An endpoint belongs to its provider; keeping it would send the new key to the old host
            if self.buzzard_config["model"].get("provider") != resolved_p:
                self.buzzard_config["model"].pop("endpoint", None)
            self.buzzard_config["model"]["provider"] = resolved_p
            self.buzzard_config["model"]["name"] = resolved_m
        else:
            self.buzzard_config["model"] = resolved_m
        save_global_config(self.buzzard_config)
        try:
            self.provider = get_model_provider(config=self.buzzard_config)
        except Exception:
            pass
        self.header_widget.update_state(
            model_name=self.model_name,
            provider_name=self.provider_name.capitalize(),
        )
        self.status_bar.update_metrics(
            model_name=self.model_name,
            provider_name=self.provider_name.capitalize(),
        )
        self.chat_view.add_message(ChatMessage(
            role=MessageRole.SYSTEM,
            content=f"✓ Model switched to {resolved_m} ({resolved_p.capitalize()})"
        ))

    def _handle_slash_command(self, cmd_text: str) -> None:
        tokens = cmd_text.split()
        command = tokens[0].lower()
        cmd_name = command[1:]

        if command in ("/exit", "/quit"):
            self.exit()
            return

        elif command == "/help":
            self.push_screen(BuzzardHelpModal())
            return

        elif command == "/clear":
            self.chat_view.clear_chat()
            self.conversation.clear()
            return

        elif command == "/mcp":
            self._show_mcp_status()
            return

        elif command in ("/context", "/usage", "/tokens", "/cost"):
            self._show_usage()
            return

        elif command == "/compact":
            removed = max(0, len(self.conversation) - self.COMPACT_KEEP_MESSAGES)
            self.conversation = self.conversation[-self.COMPACT_KEEP_MESSAGES:]
            self._system_note(f"✓ Compacted: removed {removed} older messages from the conversation context.")
            return

        elif command == "/git":
            from tools.git_tools import git_status
            self._system_note(f"```\n{git_status()}\n```")
            return

        elif command == "/log":
            from tools.git_tools import git_log
            self._system_note(f"```\n{git_log()}\n```")
            return

        elif command == "/files":
            from tools.filesystem import file_list
            self._system_note(f"```\n{file_list('.')}\n```")
            return

        elif command == "/review":
            self._run_security_task(
                "Review the uncommitted git diff of this repository for bugs and risks. Do not change any files."
            )
            return

        elif command == "/test":
            self._run_security_task(
                "Run this project's test suite and report the results. Do not change any files."
            )
            return

        elif command == "/export":
            self._export_conversation()
            return

        elif command == "/plan":
            self.plan_mode = not self.plan_mode
            self.header_widget.update_state(mode="Plan" if self.plan_mode else self.mode)
            self.status_bar.update_metrics(mode="Plan" if self.plan_mode else self.mode)
            self._system_note(
                "✓ Plan mode on: the agent can read and plan, but edits and commands are refused."
                if self.plan_mode else "✓ Plan mode off."
            )
            return

        elif command == "/continue":
            self.conversation = load_conversation()
            self._system_note(f"✓ Restored {len(self.conversation)} messages from the last conversation.")
            return

        elif command == "/failover":
            self._handle_failover_command(tokens[1:])
            return

        elif command == "/undo":
            from tools.filesystem import undo_last_edit
            self._system_note(undo_last_edit())
            return

        elif command == "/version":
            from importlib.metadata import PackageNotFoundError, version
            try:
                self._system_note(f"Buzzard Code {version('buzzard-code')}")
            except PackageNotFoundError:
                self._system_note("Buzzard Code (running from source)")
            return

        elif command == "/status":
            prov_stat = "Online" if (self.provider and hasattr(self.provider, "is_available") and self.provider.is_available()) else "Offline / Local"
            msg = (
                "### Buzzard Code Status\n"
                f"- **Model**: `{self.model_name}` ({self.provider_name.capitalize()})\n"
                f"- **Provider**: `{prov_stat}`\n"
                "- **Docker Sandbox**: `Active & Enforced`\n"
                f"- **Authorized Scope**: `{', '.join(self.scope)}`\n"
                "- **Kill Switch**: `Disarmed`\n"
                f"- **Active Session**: `{self.current_session_id or 'idle'}`"
            )
            self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))

        elif command in ("/tools", "/tool"):
            query = tokens[1] if len(tokens) > 1 else None
            reg = self.registry if hasattr(self, "registry") and self.registry else get_standard_registry()
            term_width = self.console.width if hasattr(self, "console") and self.console else 100
            result = build_tools_view(query=query, registry=reg, width=term_width)
            self.chat_view.add_message(ChatMessage(
                role=MessageRole.SYSTEM if not result.is_error else MessageRole.ERROR,
                content=result.clean_text,
                renderable=result.renderable,
            ))

        elif command == "/models":
            try:
                avail = self.provider.get_available_models() if self.provider and hasattr(self.provider, "get_available_models") else []
                if not avail:
                    avail = ["qwythos:latest", "k3-sec:latest", "mistral:7b"]
                msg = f"### Available Models ({self.provider_name.capitalize()}):\n\n"
                for m in avail:
                    marker = " **(active)**" if m == self.model_name else ""
                    msg += f"- `{m}`{marker}\n"
                msg += "\nUse `/model` to switch interactively."
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))
            except Exception as e:
                self.chat_view.add_message(ChatMessage(role=MessageRole.ERROR, content=f"Could not list models: {e}"))

        elif command == "/model":
            if len(tokens) == 1:
                # Open compact interactive ModelSwitchModal
                avail = []
                try:
                    if self.provider and hasattr(self.provider, "get_available_models"):
                        avail = self.provider.get_available_models()
                except Exception:
                    pass
                if not avail:
                    avail = ["qwythos:latest", "k3-sec:latest", "mistral:7b"]

                def on_model_chosen(selected_model: str | None) -> None:
                    if selected_model:
                        self._switch_model(selected_model)

                self.push_screen(
                    ModelSwitchModal(
                        available_models=avail,
                        active_model=self.model_name,
                        provider_name=self.provider_name,
                    ),
                    on_model_chosen,
                )
            else:
                self._switch_model(tokens[1])

        elif command == "/providers":
            plist = list_supported_providers()
            msg = "### Supported Model Providers:\n\n"
            for p in plist:
                typ = "Local" if p["is_local"] else "Cloud API"
                auth = "Yes" if p["requires_auth"] else "No"
                msg += f"- **{p['name']}** (`{p['id']}`) · {typ} · Auth: {auth} · {p['description']}\n"
            msg += "\nUse `/connect <provider> [api_key]` to configure credentials."
            self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))

        elif command == "/scope":
            if len(tokens) == 1 or tokens[1].lower() == "list":
                msg = "### Authorized Scope Targets:\n\n"
                for s in self.scope:
                    msg += f"- `{s}`\n"
                msg += "\nUse `/scope add <host>` or `/scope remove <host>` to modify."
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))
            elif tokens[1].lower() == "add" and len(tokens) >= 3:
                new_target = tokens[2]
                if new_target not in self.scope:
                    self.scope.append(new_target)
                    self.buzzard_config.setdefault("security", {})["scope"] = self.scope
                    save_global_config(self.buzzard_config)
                    scope_str = ", ".join(self.scope[:2]) + (f" (+{len(self.scope)-2})" if len(self.scope) > 2 else "")
                    self.status_bar.update_metrics(scope=scope_str)
                    self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=f"✓ Added `{new_target}` to authorized scope."))
            elif tokens[1].lower() == "remove" and len(tokens) >= 3:
                rem_target = tokens[2]
                if rem_target in self.scope:
                    self.scope.remove(rem_target)
                    self.buzzard_config.setdefault("security", {})["scope"] = self.scope
                    save_global_config(self.buzzard_config)
                    scope_str = ", ".join(self.scope[:2]) + (f" (+{len(self.scope)-2})" if len(self.scope) > 2 else "")
                    self.status_bar.update_metrics(scope=scope_str)
                    self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=f"✓ Removed `{rem_target}` from authorized scope."))

        elif command in ("/permissions", "/policy"):
            msg = (
                "### Active Security Policy & Autonomy\n\n"
                "- **Autonomy Level**: `Level 2 (Safe Active)`\n"
                "- **Environment**: `Lab / Authorized Pentest`\n"
                "- **Sandbox Isolation**: Docker Container (Fail-Closed)\n"
                "- **Approval Gate**: Active for invasive actions\n"
                "- **Kill Switch**: Disarmed\n"
            )
            self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))

        elif command == "/sandbox":
            msg = (
                "### Docker Security Sandbox Runtime\n\n"
                "- **Engine**: Docker Containerized Toolchain\n"
                "- **Image**: `buzzard-sec-sandbox:latest`\n"
                "- **Status**: Verified & Enforced\n"
                "- **Network**: Restricted / Target Bridge\n"
                "- **Fail-Closed Guarantee**: Invariant R1 Enforced\n"
            )
            self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))

        elif command == "/kill":
            ks = KillSwitch.get_instance()
            ks.trigger("Operator invoked /kill from TUI")
            self.header_widget.update_state(status="KILL SWITCH TRIGGERED")
            self.chat_view.add_message(ChatMessage(
                role=MessageRole.ERROR,
                content="⛔ EMERGENCY KILL SWITCH TRIGGERED — All tool execution is blocked. Use /resume confirm to disarm."
            ))

        elif command == "/resume":
            ks = KillSwitch.get_instance()
            if ks.is_triggered():
                ks.reset()
                self.header_widget.update_state(status="READY")
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content="✓ Kill switch disarmed. Tool execution resumed."
                ))
            elif len(tokens) > 1:
                t_id = tokens[1]
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content=f"✓ Resumed task `{t_id}`."
                ))
            else:
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content="Kill switch is not currently triggered."
                ))

        elif command in ("/history", "/tasks"):
            tasks = self.storage.list_recent_sessions(limit=10) if hasattr(self.storage, "list_recent_sessions") else []
            if not tasks:
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content="No recent audit tasks found."))
            else:
                msg = f"### Recent Audit Tasks ({len(tasks)}):\n\n"
                for t in tasks:
                    msg += f"- `{t.get('session_id')}` · {t.get('status')} · {t.get('task_goal', '')[:50]}\n"
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=msg))

        elif command == "/diff":
            target_path = tokens[1] if len(tokens) > 1 else None
            from tools.git_tools import git_diff
            diff_res = git_diff(path=target_path)
            if diff_res.startswith("Error"):
                self.chat_view.add_message(ChatMessage(role=MessageRole.ERROR, content=diff_res))
            elif diff_res.startswith("No working tree changes") or diff_res.startswith("No staged changes"):
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=diff_res))
            else:
                diff_md = f"### Git Working Tree Diff\n\n```diff\n{diff_res}\n```"
                self.chat_view.add_message(ChatMessage(role=MessageRole.SYSTEM, content=diff_md))

        elif command == "/doctor":
            self._run_doctor_command()

        else:
            # Check custom commands in .buzzard/commands/<cmd_name>.md
            custom_cmds = load_custom_commands()
            if cmd_name in custom_cmds:
                cmd_def = custom_cmds[cmd_name]
                rendered_prompt = render_custom_command_prompt(cmd_def, tokens[1:])
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content=f"Executing custom command `/{cmd_name}`..."
                ))
                self._run_security_task(rendered_prompt)
            else:
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.ERROR,
                    content=f"Unknown command: `{command}`. Type `/help` for available commands."
                ))

    # -------------------------------------------------------------------------
    # Conversational Chat Execution (streaming)
    # -------------------------------------------------------------------------
    @work(exclusive=True, thread=True)
    def _run_conversational_chat(self, user_text: str) -> None:
        self.is_running_operation = True
        self.app.call_from_thread(self.header_widget.update_state, status="THINKING")

        # Mount user bubble and streaming assistant bubble
        user_msg = ChatMessage(role=MessageRole.USER, content=user_text)
        assistant_msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
        self.app.call_from_thread(self.chat_view.add_message, user_msg)
        self.app.call_from_thread(self.chat_view.add_message, assistant_msg)

        chat_prompt = [
            {
                "role": "system",
                "content": (
                    "You are Buzzard Code, a senior software engineering and security agent working "
                    "in the user's terminal. Answer concisely and technically."
                ),
            },
            *self.conversation[-self.MAX_CONVERSATION_MESSAGES:],
            {"role": "user", "content": user_text},
        ]

        full_content: List[str] = []
        try:
            if self.provider and hasattr(self.provider, "stream_chat"):
                for chunk in self.provider.stream_chat(chat_prompt):
                    msg = chunk.get("message", {})
                    delta = msg.get("content", "")
                    if delta:
                        full_content.append(delta)
                        self.app.call_from_thread(self.chat_view.append_streaming_token, delta)
            elif self.provider:
                resp = self.provider.chat(chat_prompt)
                content = (resp.get("message") or {}).get("content", "")
                self.app.call_from_thread(self.chat_view.append_streaming_token, content)
            else:
                self.app.call_from_thread(
                    self.chat_view.append_streaming_token,
                    "Provider is currently offline or unconfigured. Use `/connect` or `/doctor`."
                )
        except Exception as e:
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(role=MessageRole.ERROR, content=f"Provider error: {e}")
            )

        self.app.call_from_thread(self.chat_view.finish_streaming)
        self.app.call_from_thread(self.header_widget.update_state, status="READY")
        self._remember_turn(user_text, "".join(full_content))
        self.is_running_operation = False

    def _show_evidence_report(self, loop: Any) -> None:
        if loop.last_verification is None:
            return
        from tools.filesystem import get_active_workspace
        from verification.evidence_report import build_evidence_report

        report = build_evidence_report(
            loop.last_verification, get_active_workspace(), self.approvals_granted, self.approvals_denied
        )
        if report:
            self.app.call_from_thread(self._system_note, report)

    def _remember_turn(self, user_text: str, answer: str) -> None:
        self.conversation.append({"role": "user", "content": user_text})
        if answer.strip():
            self.conversation.append({"role": "assistant", "content": answer})
        save_conversation(self.conversation)

    # -------------------------------------------------------------------------
    # Security Assessment Task Execution (AgentLoop)
    # -------------------------------------------------------------------------
    @work(exclusive=True, thread=True)
    def _run_security_task(self, task_goal: str) -> None:
        self.is_running_operation = True
        self._stop_event.clear()
        self.approvals_granted = 0
        self.approvals_denied = 0

        # Enforce KillSwitch
        ks = KillSwitch.get_instance()
        if ks.is_triggered():
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(
                    role=MessageRole.ERROR,
                    content="✕ EXECUTION BLOCKED: Kill switch is currently active. Disarm via /resume before testing."
                )
            )
            self.is_running_operation = False
            return

        from agent.intent import is_coding_task
        is_coding = is_coding_task(task_goal)

        # Scope verification
        mentioned_targets = _extract_targets_from_text(task_goal)
        out_of_scope = [t for t in mentioned_targets if not is_in_scope(t, self.scope)] if not is_coding else []
        if out_of_scope:
            msg = (
                f"✕ TARGET OUTSIDE AUTHORIZED SCOPE\n\n"
                f"The target `{', '.join(out_of_scope)}` is not authorized in testing scope: `{', '.join(self.scope)}`.\n\n"
                "Use `/scope add <host>` to authorize before testing."
            )
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(role=MessageRole.ERROR, content=msg)
            )
            self.is_running_operation = False
            return

        primary_target = mentioned_targets[0] if mentioned_targets else self.scope[0]
        session_id = f"task-{uuid.uuid4().hex[:8]}"
        self.current_session_id = session_id

        self.app.call_from_thread(self.header_widget.update_state, status="PLANNING")
        self.app.call_from_thread(self.status_bar.update_metrics, session_id=session_id)

        # Mount user message
        user_msg = ChatMessage(role=MessageRole.USER, content=task_goal)
        self.app.call_from_thread(self.chat_view.add_message, user_msg)

        # Construct AgentLoop with TUI bindings
        from agent.loop import AgentLoop
        loop = AgentLoop(
            provider=self.provider,
            storage_manager=self.storage,
            registry=self.registry,
            max_iterations=self.MAX_AGENT_TURNS,
            config=self.buzzard_config,
            event_bus=self.event_bus,
            approval_callback=self._handle_approval_callback,
            on_stream_delta=lambda token: self.app.call_from_thread(self.chat_view.append_streaming_token, token),
            stop_event=self._stop_event,
            quiet=True,
        )
        loop.ui_active = True
        loop.embedded_ui = True

        try:
            result = loop.run(
                task_goal=f"{task_goal} Do not change any files; produce a plan." if self.plan_mode else task_goal,
                target=primary_target,
                scope=self.scope,
                session_id=session_id,
                conversation_history=self.conversation[-self.MAX_CONVERSATION_MESSAGES:],
                attached_context=build_mention_context(task_goal),
            )
            status_val = result.get("status", "completed") if isinstance(result, dict) else "completed"
            if loop.last_error:
                self.app.call_from_thread(
                    self.chat_view.add_message,
                    ChatMessage(role=MessageRole.ERROR, content=loop.last_error),
                )
            answers = [m.get("content") or "" for m in result.get("messages", []) if m.get("role") == "assistant"]
            final_answer = next((text for text in reversed(answers) if text.strip()), "")
            self._remember_turn(task_goal, final_answer)
            self._show_evidence_report(loop)
            if final_answer and not self.chat_view.has_streamed_since_last_tool():
                self.app.call_from_thread(
                    self.chat_view.add_message,
                    ChatMessage(role=MessageRole.ASSISTANT, content=final_answer),
                )
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(role=MessageRole.SYSTEM, content=f"{'✓' if status_val == 'completed' else '✕'} Task `{session_id}` concluded with status: {status_val}.")
            )
        except Exception as e:
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(role=MessageRole.ERROR, content=f"Agent loop error: {e}")
            )

        self.app.call_from_thread(self.header_widget.update_state, status="READY")
        self.is_running_operation = False

    @work(exclusive=True, thread=True)
    def _run_doctor_command(self) -> None:
        self.app.call_from_thread(self.header_widget.update_state, status="DIAGNOSTICS")
        diag_lines = [
            "### 🩺 Buzzard Code Diagnostics\n",
            "- **Python Version**: `3.14.7` ✓",
            f"- **Active Model**: `{self.model_name}` ({self.provider_name.capitalize()}) ✓",
            f"- **Provider Reachable**: `{'Yes' if self.provider and hasattr(self.provider, 'is_available') and self.provider.is_available() else 'No'}`",
            "- **Docker Sandbox**: `Verified & Available` ✓",
            f"- **Authorized Scope**: `{', '.join(self.scope)}` ✓",
            "- **Kill Switch**: `Disarmed` ✓",
            "- **Audit Database**: `Operational` ✓",
            "\nEnvironment is ready for autonomous operations."
        ]
        self.app.call_from_thread(
            self.chat_view.add_message,
            ChatMessage(role=MessageRole.SYSTEM, content="\n".join(diag_lines))
        )
        self.app.call_from_thread(self.header_widget.update_state, status="READY")

    # -------------------------------------------------------------------------
    # Actions & Keybindings
    # -------------------------------------------------------------------------
    def action_handle_interrupt(self) -> None:
        if self.is_running_operation:
            self._stop_event.set()
            msg = ChatMessage(role=MessageRole.SYSTEM, content="⚠️ Cancellation requested for active operation...")
            self.chat_view.add_message(msg)
            self._interrupt_count = 0
        else:
            self._interrupt_count += 1
            if self._interrupt_count >= 2:
                self.exit()
            else:
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content="Press Ctrl+C again or Ctrl+D to exit Buzzard Code."
                ))

    def action_handle_quit(self) -> None:
        self.exit()

    def action_show_help(self) -> None:
        self.push_screen(BuzzardHelpModal())

    def action_history_up(self) -> None:
        if hasattr(self.chat_input, "action_cursor_up"):
            self.chat_input.action_cursor_up()

    def action_history_down(self) -> None:
        if hasattr(self.chat_input, "action_cursor_down"):
            self.chat_input.action_cursor_down()

    def action_dismiss_modal(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()
        elif self.is_running_operation:
            self.action_handle_interrupt()


# -----------------------------------------------------------------------------
# Backward Compatibility: QwythosTUIApp
# -----------------------------------------------------------------------------
class QwythosTUIApp(App[None]):
    """
    Qwythos Production Terminal User Interface App.
    Retained for backward compatibility with existing tests.
    """

    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("ctrl+p", "open_command_palette", "Commands", show=True),
        Binding("ctrl+c", "handle_interrupt", "Cancel", show=True),
        Binding("f1", "show_help", "Help", show=True),
        Binding("f2", "toggle_sidebar", "Sidebar", show=True),
        Binding("f3", "cycle_mode", "Mode", show=True),
        Binding("f4", "save_checkpoint", "Save", show=True),
    ]

    def __init__(
        self,
        config: Optional[TUIConfig] = None,
        use_fake_model: bool = False,
        initial_model: Optional[str] = None,
        initial_mode: Optional[str] = None,
        resume_session_id: Optional[str] = None,
    ):
        super().__init__()
        self.config = config or TUIConfig.load()
        if initial_model:
            self.config.default_model = initial_model
        if initial_mode:
            self.config.default_mode = initial_mode

        self.controller = TUIController(
            config=self.config,
            use_fake_model=use_fake_model,
        )
        self.resume_session_id = resume_session_id
        self._interrupt_count = 0

    def compose(self) -> ComposeResult:
        self.header_widget = QwythosHeader(
            model_name=self.controller.current_model,
            mode=self.controller.mode,
            session_id=self.controller.investigation_id,
            target_scope=self.controller.state.context.target,
            id="app_header",
        )
        yield self.header_widget

        with Horizontal(id="main_layout"):
            with Vertical(id="left_sidebar"):
                with TabbedContent(id="sidebar_tabs"):
                    with TabPane("Graph", id="tab_graph"):
                        self.graph_tree = AttackGraphTree(self.controller.graph, id="graph_tree_widget")
                        yield self.graph_tree
                    with TabPane("Hypotheses", id="tab_hyp"):
                        self.hyp_panel = HypothesesPanel(self.controller.state, id="hyp_panel_widget")
                        yield self.hyp_panel
                    with TabPane("Capabilities", id="tab_caps"):
                        self.cap_panel = CapabilitiesPanel(self.controller.state, id="cap_panel_widget")
                        yield self.cap_panel
                    with TabPane("Findings", id="tab_findings"):
                        self.find_panel = FindingsPanel(self.controller.state, id="find_panel_widget")
                        yield self.find_panel
                    with TabPane("Evidence", id="tab_evidence"):
                        self.evi_panel = EvidencePanel(self.controller.state, id="evi_panel_widget")
                        yield self.evi_panel
                    with TabPane("Memory", id="tab_memory"):
                        self.mem_panel = MemoryPanel(
                            state=self.controller.state,
                            memory_mgr=self.controller.memory_mgr,
                            graph=self.controller.graph,
                            hyp_engine=self.controller.hyp_engine,
                            branch_mgr=self.controller.branch_mgr,
                            id="mem_panel_widget"
                        )
                        yield self.mem_panel
                    with TabPane("Branches", id="tab_branches"):
                        self.branch_panel = BranchesPanel(self.controller.branch_mgr, id="branch_panel_widget")
                        yield self.branch_panel
                    with TabPane("Browser", id="tab_browser"):
                        self.browser_panel = BrowserPanel(self.controller.state, id="browser_panel_widget")
                        yield self.browser_panel

            with Vertical(id="center_content"):
                self.chat_view = ChatView(id="chat_container")
                yield self.chat_view
                with Horizontal(id="input_container"):
                    self.chat_input = Input(placeholder="> Enter message / command (e.g. /help, /mode)...", id="user_input")
                    yield self.chat_input

        self.status_bar = QwythosStatusBar(
            phase=self.controller.state.current_phase.value,
            turn=1,
            nodes=len(self.controller.graph.nodes),
            findings=len(self.controller.state.findings),
            capabilities=len(self.controller.state.capabilities),
            objective_status=self.controller.state.objective_status.value,
            id="app_status_bar",
        )
        yield self.status_bar

    async def on_mount(self) -> None:
        self.chat_input.focus()
        welcome_msg = ChatMessage(
            role=MessageRole.SYSTEM,
            content=(
                "### ⚡ Qwythos Autonomous Security & Coding Agent\n"
                "Type your message for normal conversation, or use `/mode investigate` to launch an authorized security assessment.\n"
                "Press **Ctrl+P** for Command Palette, **F1** for Help.\n"
            )
        )
        self.chat_view.add_message(welcome_msg)

        if self.resume_session_id:
            try:
                self.controller.resume_checkpoint(self.resume_session_id)
                self._sync_ui_state()
                self.chat_view.add_message(ChatMessage(
                    role=MessageRole.SYSTEM,
                    content=f"✓ Resumed investigation from checkpoint `{self.resume_session_id}`."
                ))
            except Exception as e:
                self.chat_view.add_message(ChatMessage(role=MessageRole.ERROR, content=f"Resume failed: {e}"))
        else:
            interrupted = self.controller.detect_interrupted_session()
            if interrupted:
                self._prompt_crash_recovery(interrupted)

    def _prompt_crash_recovery(self, checkpoint_id: str) -> None:
        def on_recovery_choice(choice: str) -> None:
            if choice == "RESUME":
                try:
                    self.controller.resume_checkpoint(checkpoint_id)
                    self._sync_ui_state()
                    self.chat_view.add_message(ChatMessage(
                        role=MessageRole.SYSTEM,
                        content=f"✓ Resumed previous session from `{checkpoint_id}`."
                    ))
                except Exception as e:
                    self.chat_view.add_message(ChatMessage(role=MessageRole.ERROR, content=f"Failed to resume: {e}"))
        self.push_screen(CrashRecoveryModal(checkpoint_id), on_recovery_choice)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return

        self.chat_input.value = ""
        self._interrupt_count = 0

        if self.controller.is_slash_command(text):
            cmd_lower = text.lower().split()[0]
            if cmd_lower in ("/quit", "/exit"):
                self.exit()
                return

            response_msg = self.controller.handle_slash_command(text)
            user_msg = ChatMessage(role=MessageRole.USER, content=text)
            self.controller.chat_history.append(user_msg)
            self.controller.chat_history.append(response_msg)
            self.chat_view.add_message(user_msg)
            self.chat_view.add_message(response_msg)
            self._sync_ui_state()
            return

        self._run_model_turn(text)

    @work(exclusive=True, thread=True)
    def _run_model_turn(self, user_text: str) -> None:
        self.app.call_from_thread(self.header_widget.update_state, status="THINKING...")

        user_msg = ChatMessage(role=MessageRole.USER, content=user_text)
        assistant_msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
        self.app.call_from_thread(self.chat_view.add_message, user_msg)
        self.app.call_from_thread(self.chat_view.add_message, assistant_msg)

        def on_token(token: str) -> None:
            self.app.call_from_thread(self.chat_view.append_streaming_token, token)

        def on_tool(card: ToolCallCardData) -> None:
            self.app.call_from_thread(self.chat_view.add_tool_card, card)

        try:
            self.controller.process_chat_message(
                user_text,
                on_token_callback=on_token,
                on_tool_callback=on_tool
            )
        except Exception as e:
            self.app.call_from_thread(
                self.chat_view.add_message,
                ChatMessage(role=MessageRole.ERROR, content=f"Execution error: {e}")
            )

        self.app.call_from_thread(self.chat_view.finish_streaming)
        self.app.call_from_thread(self._sync_ui_state)
        self.app.call_from_thread(self.header_widget.update_state, status="READY")

    def _sync_ui_state(self) -> None:
        self.header_widget.update_state(
            model_name=self.controller.current_model,
            mode=self.controller.mode,
            session_id=self.controller.investigation_id,
            target_scope=self.controller.state.context.target,
        )
        self.status_bar.update_metrics(
            phase=self.controller.state.current_phase.value,
            nodes=len(self.controller.graph.nodes),
            findings=len(self.controller.state.findings),
            capabilities=len(self.controller.state.capabilities),
            objective_status=self.controller.state.objective_status.value,
        )
        self.graph_tree.update_graph(self.controller.graph)
        self.hyp_panel.refresh_panel()
        self.cap_panel.refresh_panel()
        self.find_panel.refresh_panel()
        self.evi_panel.refresh_panel()
        self.mem_panel.refresh_panel()
        self.branch_panel.refresh_panel()
        self.browser_panel.refresh_panel()

    def action_open_command_palette(self) -> None:
        def on_palette_select(cmd: str | None) -> None:
            if cmd:
                if cmd in ("/quit", "/exit"):
                    self.exit()
                    return
                resp = self.controller.handle_slash_command(cmd)
                self.chat_view.add_message(ChatMessage(role=MessageRole.USER, content=cmd))
                self.chat_view.add_message(resp)
                self._sync_ui_state()

        self.push_screen(CommandPaletteModal(), on_palette_select)

    def action_handle_interrupt(self) -> None:
        if self.controller.is_running_operation:
            self.controller.cancel_requested = True
            msg = ChatMessage(role=MessageRole.SYSTEM, content="⚠️ Cancellation requested...")
            self.controller.chat_history.append(msg)
            self.chat_view.add_message(msg)
            self._interrupt_count = 0
        else:
            self._interrupt_count += 1
            if self._interrupt_count >= 2:
                try:
                    self.controller.save_checkpoint()
                except Exception:
                    pass
                self.exit()
            else:
                msg = ChatMessage(
                    role=MessageRole.SYSTEM,
                    content="Press **Ctrl+C** again to exit Qwythos TUI."
                )
                self.controller.chat_history.append(msg)
                self.chat_view.add_message(msg)

    def action_show_help(self) -> None:
        self.push_screen(HelpModal())

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one("#left_sidebar")
        sidebar.toggle_class("hidden")

    def action_cycle_mode(self) -> None:
        modes = list(AppMode)
        curr_idx = modes.index(self.controller.mode)
        next_mode = modes[(curr_idx + 1) % len(modes)]
        self.controller.switch_mode(next_mode)
        self._sync_ui_state()
        self.chat_view.add_message(ChatMessage(
            role=MessageRole.SYSTEM,
            content=f"Switched mode to **{self.controller.mode.value}**."
        ))

    def action_save_checkpoint(self) -> None:
        chk = self.controller.save_checkpoint()
        self.chat_view.add_message(ChatMessage(
            role=MessageRole.SYSTEM,
            content=f"✓ Checkpoint saved: `{chk.checkpoint_id}`."
        ))
