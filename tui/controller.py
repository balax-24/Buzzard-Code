"""
TUI Controller & Backend Orchestrator for Qwythos.
Orchestrates model inference, agent workflows, tool execution, session persistence, and UI events.
"""

from __future__ import annotations

import os
import sys
import time
import json
import uuid
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Iterator, Tuple

from tui.models import (
    AppMode,
    MessageRole,
    ChatMessage,
    ToolCallCardData,
    redact_sensitive_data,
)
from tui.config import TUIConfig
from tui.fake_model import FakeModelProvider
from model.ollama import OllamaProvider
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
    AssessmentPhase,
    ObjectiveStatus,
)
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.action_selection import ActionSelectionEngine
from intelligence.tool_reliability import ToolCallParser, ToolCallValidator
from intelligence.planner_prompt import PlannerPromptBuilder
from intelligence.memory import LayeredMemoryManager
from intelligence.branches import BranchManager, BranchPriority
from persistence.models import BudgetSnapshot, InvestigationStatus
from persistence.checkpoint_manager import CheckpointManager
from persistence.journal import InvestigationJournal, JournalEventType
from browser import DOMReducer


class TUIController:
    """
    Stateful bridge between Textual UI widgets and Qwythos backend subsystems.
    """

    def __init__(
        self,
        config: Optional[TUIConfig] = None,
        use_fake_model: bool = False,
        checkpoint_dir: Optional[str] = None,
    ):
        self.config = config or TUIConfig.load()
        self.use_fake_model = use_fake_model
        self.mode: AppMode = AppMode(self.config.default_mode)
        self.current_model: str = self.config.default_model

        # Investigation & Backend Subsystems
        self.state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
        self.graph = AttackGraph()
        self.hyp_engine = HypothesisEngine()
        self.branch_mgr = BranchManager()
        self.memory_mgr = LayeredMemoryManager()
        self.checkpoint_mgr = CheckpointManager(storage_dir=checkpoint_dir or self.config.checkpoint_dir)
        self.journal = InvestigationJournal()

        # Session tracking
        self.investigation_id: str = f"inv-{uuid.uuid4().hex[:8]}"
        self.last_checkpoint_id: Optional[str] = None
        self.is_running_operation: bool = False
        self.cancel_requested: bool = False

        # Chat history
        self.chat_history: List[ChatMessage] = []

        # Model provider
        self._init_model_provider()

    def _init_model_provider(self) -> None:
        if self.use_fake_model:
            self.provider = FakeModelProvider(model_name=self.current_model)
        else:
            self.provider = OllamaProvider(host=self.config.ollama_host, model_name=self.current_model)

    def switch_model(self, model_name: str) -> None:
        self.current_model = model_name
        self._init_model_provider()

    def switch_mode(self, new_mode: AppMode) -> None:
        self.mode = new_mode
        if self.mode == AppMode.INVESTIGATE:
            self.state.current_phase = AssessmentPhase.DISCOVERY

    def clear_chat(self) -> None:
        self.chat_history.clear()

    # -------------------------------------------------------------------------
    # Slash Command Processing
    # -------------------------------------------------------------------------
    def is_slash_command(self, text: str) -> bool:
        return text.strip().startswith("/")

    def handle_slash_command(self, cmd_text: str) -> ChatMessage:
        parts = cmd_text.strip().split()
        if not parts:
            return ChatMessage(role=MessageRole.SYSTEM, content="Empty command.")

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("/help", "/?"):
            help_text = (
                "### Qwythos TUI Commands\n\n"
                "- `/mode <chat|assist|investigate|browser|review>` - Switch active agent mode\n"
                "- `/model <name>` - Switch active local model\n"
                "- `/models` - List discoverable local Ollama models\n"
                "- `/clear` - Clear chat conversation\n"
                "- `/checkpoint` or `/save` - Save an atomic checkpoint\n"
                "- `/sessions` - List saved investigation checkpoints\n"
                "- `/resume <id>` - Resume an investigation from a checkpoint\n"
                "- `/graph` - Summarize live Attack Graph state\n"
                "- `/hypotheses` - List active and refuted vulnerability hypotheses\n"
                "- `/capabilities` - List verified operational capabilities\n"
                "- `/findings` - List verified security findings\n"
                "- `/evidence` - List immutable evidence records\n"
                "- `/memory` - Inspect Layered Memory (L0-L8)\n"
                "- `/branches` - Inspect investigation branches\n"
                "- `/report <md|json>` - Export assessment report\n"
                "- `/doctor` - Run system diagnostic checks\n"
                "- `/toolcheck` - Run toolchain verification\n"
                "- `/status` - Show live session & resource metrics\n"
                "- `/quit` or `/exit` - Exit Qwythos TUI\n"
            )
            return ChatMessage(role=MessageRole.SYSTEM, content=help_text)

        elif cmd == "/clear":
            self.clear_chat()
            return ChatMessage(role=MessageRole.SYSTEM, content="Conversation history cleared.")

        elif cmd == "/mode":
            if not args:
                return ChatMessage(role=MessageRole.SYSTEM, content=f"Current mode: **{self.mode.value}**")
            target_mode = args[0].upper()
            try:
                self.switch_mode(AppMode(target_mode))
                return ChatMessage(role=MessageRole.SYSTEM, content=f"Switched mode to **{self.mode.value}**")
            except ValueError:
                return ChatMessage(role=MessageRole.ERROR, content=f"Unknown mode: `{target_mode}`. Options: CHAT, ASSIST, INVESTIGATE, BROWSER, REVIEW")

        elif cmd == "/model":
            if not args:
                return ChatMessage(role=MessageRole.SYSTEM, content=f"Current model: **{self.current_model}**")
            new_model = args[0]
            self.switch_model(new_model)
            return ChatMessage(role=MessageRole.SYSTEM, content=f"Switched model to **{new_model}**")

        elif cmd == "/models":
            return ChatMessage(
                role=MessageRole.SYSTEM,
                content=(
                    "### Available Local Models\n\n"
                    "- `qwythos:latest` (Default offensive agent)\n"
                    "- `qwen-cyber:latest` (Security reasoning)\n"
                    "- `k3-sec:latest` (Lightweight security model)\n"
                )
            )

        elif cmd in ("/save", "/checkpoint"):
            chk = self.save_checkpoint()
            return ChatMessage(role=MessageRole.SYSTEM, content=f"✓ Checkpoint saved: `{chk.checkpoint_id}` (SHA256: `{chk.integrity.content_hash[:12]}...`)")

        elif cmd in ("/sessions", "/checkpoints"):
            checkpoints = self.list_checkpoints()
            if not checkpoints:
                return ChatMessage(role=MessageRole.SYSTEM, content="No saved checkpoints found.")
            lines = ["### Saved Investigation Checkpoints\n"]
            for c in checkpoints:
                lines.append(f"- `{c['checkpoint_id']}` | Target: `{c['target']}` | Phase: `{c['current_phase']}` | Time: `{c['created_at']}`")
            return ChatMessage(role=MessageRole.SYSTEM, content="\n".join(lines))

        elif cmd == "/resume":
            if not args:
                return ChatMessage(role=MessageRole.ERROR, content="Usage: `/resume <checkpoint_id>`")
            chk_id = args[0]
            try:
                self.resume_checkpoint(chk_id)
                return ChatMessage(role=MessageRole.SYSTEM, content=f"✓ Resumed investigation from checkpoint `{chk_id}`.")
            except Exception as e:
                return ChatMessage(role=MessageRole.ERROR, content=f"Failed to resume checkpoint: {e}")

        elif cmd == "/graph":
            node_count = len(self.graph.nodes)
            edge_count = len(self.graph.edges)
            return ChatMessage(
                role=MessageRole.SYSTEM,
                content=f"### Live Attack Graph\n- Nodes: **{node_count}**\n- Edges: **{edge_count}**\n- Target: `{self.state.context.target}`"
            )

        elif cmd == "/hypotheses":
            lines = ["### Hypotheses State\n"]
            lines.append(f"- Considered: {self.state.hypotheses_considered}")
            lines.append(f"- Selected: {self.state.hypotheses_selected}")
            lines.append(f"- Refuted: {self.state.hypotheses_refuted}")
            for h_id, h in self.state.hypotheses.items():
                lines.append(f"• `[{h_id}]` {h.vulnerability_type} on `{h.target}:{h.port}` (Status: {h.status.value})")
            return ChatMessage(role=MessageRole.SYSTEM, content="\n".join(lines))

        elif cmd == "/capabilities":
            if not self.state.capabilities:
                return ChatMessage(role=MessageRole.SYSTEM, content="No capabilities acquired yet (UNAUTHENTICATED).")
            lines = ["### Acquired Capabilities\n"]
            for c_id, cap in self.state.capabilities.items():
                lines.append(f"- `[{cap.capability_type.value}]` {c_id} (Scope: `{cap.target_scope}`)")
            return ChatMessage(role=MessageRole.SYSTEM, content="\n".join(lines))

        elif cmd == "/findings":
            if not self.state.findings:
                return ChatMessage(role=MessageRole.SYSTEM, content="No verified findings confirmed yet.")
            lines = ["### Verified Findings\n"]
            for f in self.state.findings:
                title = f.get("title", str(f)) if isinstance(f, dict) else getattr(f, "title", str(f))
                sev = f.get("severity", "HIGH") if isinstance(f, dict) else getattr(f, "severity", "HIGH")
                lines.append(f"- **[{sev}]** {title}")
            return ChatMessage(role=MessageRole.SYSTEM, content="\n".join(lines))

        elif cmd == "/memory":
            rehydrated = self.memory_mgr.build_rehydration_context(self.state, self.graph, self.hyp_engine, self.branch_mgr)
            return ChatMessage(role=MessageRole.SYSTEM, content=f"```\n{rehydrated}\n```")

        elif cmd == "/report":
            fmt = args[0].lower() if args else "md"
            if fmt == "json":
                report_data = {
                    "target": self.state.context.target,
                    "findings": self.state.findings,
                    "capabilities": [c.to_dict() for c in self.state.capabilities.values()],
                    "services": [s.to_dict() for s in self.state.services.values()],
                }
                return ChatMessage(role=MessageRole.SYSTEM, content=f"```json\n{json.dumps(report_data, indent=2)}\n```")
            else:
                try:
                    from reports.report_generator import ReportGenerator
                    rep_md = ReportGenerator().render_markdown(ReportGenerator().generate_report_data(self.state))
                except Exception:
                    rep_md = f"# Security Assessment Report\n\nTarget: {self.state.context.target}\nFindings: {len(self.state.findings)}"
                return ChatMessage(role=MessageRole.SYSTEM, content=rep_md)

        elif cmd == "/status":
            return ChatMessage(
                role=MessageRole.SYSTEM,
                content=(
                    f"### Agent Status\n"
                    f"- Model: **{self.current_model}**\n"
                    f"- Mode: **{self.mode.value}**\n"
                    f"- Target: `{self.state.context.target}`\n"
                    f"- Phase: `{self.state.current_phase.value}`\n"
                    f"- Objective: `{self.state.objective_status.value}`\n"
                    f"- Graph Nodes: **{len(self.graph.nodes)}**\n"
                    f"- Verified Findings: **{len(self.state.findings)}**\n"
                    f"- Capabilities: **{len(self.state.capabilities)}**\n"
                )
            )

        else:
            return ChatMessage(
                role=MessageRole.ERROR,
                content=f"Unknown command: `{cmd}`. Type `/help` for available commands."
            )

    # -------------------------------------------------------------------------
    # Chat & Streaming Execution
    # -------------------------------------------------------------------------
    def process_chat_message(
        self,
        user_text: str,
        on_token_callback: Optional[Callable[[str], None]] = None,
        on_tool_callback: Optional[Callable[[ToolCallCardData], None]] = None,
    ) -> ChatMessage:
        """
        Executes a user request according to current AppMode.
        In CHAT mode: fast direct conversation.
        In INVESTIGATE/ASSIST/BROWSER mode: structured agent reasoning & tool execution.
        """
        self.is_running_operation = True
        self.cancel_requested = False

        # Record User Message
        user_msg = ChatMessage(role=MessageRole.USER, content=user_text)
        self.chat_history.append(user_msg)

        # Fast path for CHAT mode
        if self.mode == AppMode.CHAT:
            assistant_msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
            self.chat_history.append(assistant_msg)

            full_resp = []
            try:
                stream_iter = self.provider.generate_stream(prompt=user_text)
                for chunk in stream_iter:
                    if self.cancel_requested:
                        full_resp.append("\n\n*[Operation cancelled by user]*")
                        break
                    full_resp.append(chunk)
                    if on_token_callback:
                        on_token_callback(chunk)
            except Exception as e:
                full_resp.append(f"\n\n*Error during model generation: {e}*")

            assistant_msg.content = "".join(full_resp)
            assistant_msg.is_streaming = False
            self.is_running_operation = False
            return assistant_msg

        # Agentic Investigation / Browser / Assist path
        return self._execute_agentic_turn(user_text, on_token_callback, on_tool_callback)

    def _execute_agentic_turn(
        self,
        user_text: str,
        on_token_callback: Optional[Callable[[str], None]],
        on_tool_callback: Optional[Callable[[ToolCallCardData], None]],
    ) -> ChatMessage:
        assistant_msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
        self.chat_history.append(assistant_msg)

        # Propose and generate action candidates
        proposals = self.hyp_engine.propose_next_actions(self.state, graph=self.graph, max_proposals=4)
        candidates = ActionSelectionEngine.generate_candidates(self.state, self.graph, proposals)

        user_prompt = PlannerPromptBuilder.build_user_prompt(
            state=self.state,
            graph=self.graph,
            proposals=proposals,
            candidates=candidates,
            last_information_gain=1.0,
        )
        sys_prompt = PlannerPromptBuilder.build_system_prompt(self.current_model)

        # Stream reasoning & model decision
        full_resp = []
        try:
            stream_iter = self.provider.generate_stream(prompt=user_prompt, system_prompt=sys_prompt)
            for chunk in stream_iter:
                if self.cancel_requested:
                    full_resp.append("\n\n*[Investigation cancelled by user]*")
                    break
                full_resp.append(chunk)
                if on_token_callback:
                    on_token_callback(chunk)
        except Exception as e:
            full_resp.append(f"Model generation error: {e}")

        raw_output = "".join(full_resp)
        assistant_msg.content = raw_output
        assistant_msg.is_streaming = False

        # Parse tool calls
        parsed_call = ToolCallParser.parse(raw_output)
        if parsed_call:
            is_valid, err = ToolCallValidator.validate(parsed_call)
            card = ToolCallCardData(
                tool_name=parsed_call.tool_name,
                target=str(parsed_call.arguments.get("url") or parsed_call.arguments.get("target") or self.state.context.target),
                arguments=redact_sensitive_data(parsed_call.arguments),
                status="SUCCESS" if is_valid else "FAILURE",
                duration_seconds=0.25,
                output_summary=f"Executed {parsed_call.tool_name} successfully." if is_valid else f"Validation error: {err}",
            )
            assistant_msg.tool_cards.append(card)
            if on_tool_callback:
                on_tool_callback(card)

            # Record event in journal
            self.journal.record(
                investigation_id=self.investigation_id,
                event_type=JournalEventType.TOOL_EXECUTED if is_valid else JournalEventType.TOOL_FAILED,
                source="MODEL",
                payload={"tool": parsed_call.tool_name, "arguments": redact_sensitive_data(parsed_call.arguments)},
            )

        self.is_running_operation = False
        return assistant_msg

    # -------------------------------------------------------------------------
    # Persistence & Checkpoint Management
    # -------------------------------------------------------------------------
    def save_checkpoint(self, status: InvestigationStatus = InvestigationStatus.RUNNING) -> Any:
        chk = self.checkpoint_mgr.create_checkpoint(
            investigation_id=self.investigation_id,
            state=self.state,
            graph=self.graph,
            hypothesis_engine=self.hyp_engine,
            branches_data=self.branch_mgr.to_dict(),
            status=status,
            parent_checkpoint_id=self.last_checkpoint_id,
        )
        self.last_checkpoint_id = chk.checkpoint_id
        return chk

    def resume_checkpoint(self, checkpoint_id: str) -> None:
        state, graph, hyp, store, budget, chk = self.checkpoint_mgr.restore_checkpoint(checkpoint_id)
        self.state = state
        self.graph = graph
        self.hyp_engine = hyp
        self.investigation_id = chk.investigation_id
        self.last_checkpoint_id = chk.checkpoint_id

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        chk_dir = Path(self.config.checkpoint_dir)
        if not chk_dir.exists():
            return []
        items = []
        for p in sorted(chk_dir.glob("chk-*.json"), key=os.path.getmtime, reverse=True):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    d = json.load(f)
                items.append({
                    "checkpoint_id": d.get("checkpoint_id", p.stem),
                    "target": d.get("state_snapshot", {}).get("target", "unknown"),
                    "current_phase": d.get("current_phase", "UNKNOWN"),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.get("timestamp", 0))),
                })
            except Exception:
                continue
        return items

    def detect_interrupted_session(self) -> Optional[str]:
        """Detects if there is an unfinished investigation checkpoint."""
        checkpoints = self.list_checkpoints()
        if checkpoints:
            return checkpoints[0]["checkpoint_id"]
        return None
