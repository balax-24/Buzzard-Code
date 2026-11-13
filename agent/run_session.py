"""
UI-independent run orchestration for Buzzard Code.

A RunSession owns everything a front end needs to run coding tasks, without any UI code:
approval rules (plan mode, MCP auto-approve, "allow for this session"), the AgentLoop setup,
cancellation, conversation memory and the Evidence Report. Front ends supply two callbacks:

- ask_approval(request) -> "allow" | "allow_session" | "deny", called on the loop's thread
  and allowed to block until the user answers;
- on_delta(text), for streamed reply text.

The terminal app and `buzzard serve --stdio` both run tasks through this class, so approval
behaviour cannot drift between them.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agent.project_context import build_mention_context, save_conversation
from security.approvals import session_rule_for

logger = logging.getLogger(__name__)

ALLOW = "allow"
ALLOW_SESSION = "allow_session"
DENY = "deny"
DECISIONS = (ALLOW, ALLOW_SESSION, DENY)
PLAN_MODE_SUFFIX = " Do not change any files; produce a plan."
MAX_CONVERSATION_MESSAGES = 20


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    tool_name: str
    arguments: Dict[str, Any]
    risk_class: str
    session_rule: Optional[str]


@dataclass
class RunOutcome:
    session_id: str
    status: str
    final_answer: str = ""
    error: Optional[str] = None
    evidence_report: Optional[str] = None
    evidence_bundle: Optional[str] = None
    messages: List[Dict[str, Any]] = field(default_factory=list)


AskApproval = Callable[[ApprovalRequest], str]


class RunSession:
    """One workspace's run state, shared by whichever front end drives it."""

    def __init__(
        self,
        provider: Any,
        registry: Any,
        storage: Any,
        config: Dict[str, Any],
        ask_approval: AskApproval,
        on_delta: Optional[Callable[[str], None]] = None,
        event_bus: Optional[Any] = None,
        max_iterations: int = 25,
    ):
        self.provider = provider
        self.registry = registry
        self.storage = storage
        self.config = config
        self.ask_approval = ask_approval
        self.on_delta = on_delta
        self.event_bus = event_bus
        self.max_iterations = max_iterations
        self.plan_mode = False
        self.session_rules: set = set()
        self.approvals_granted = 0
        self.approvals_denied = 0
        self.last_evidence_bundle: Optional[str] = None
        self.conversation: List[Dict[str, str]] = []
        self.stop_event = threading.Event()
        self.current_loop: Optional[Any] = None
        self._run_lock = threading.Lock()

    # -- approvals -----------------------------------------------------------------------
    def approve(self, tool_name: str, arguments: Dict[str, Any], metadata: Any) -> bool:
        """The approval callback given to AgentLoop. Plan mode is enforced here, in code."""
        if self.plan_mode:
            self.approvals_denied += 1
            return False
        from tools.mcp_client import is_mcp_auto_approved

        if is_mcp_auto_approved(tool_name):
            self.approvals_granted += 1
            return True
        rule = session_rule_for(tool_name, arguments)
        if rule and rule in self.session_rules:
            self.approvals_granted += 1
            return True
        if self.stop_event.is_set():
            self.approvals_denied += 1
            return False
        risk = getattr(getattr(metadata, "risk_class", None), "value", None) or "HIGH"
        request = ApprovalRequest(f"approval-{uuid.uuid4().hex[:10]}", tool_name, dict(arguments or {}), str(risk), rule)
        try:
            decision = self.ask_approval(request)
        except Exception:  # a broken front end must fail closed, never open
            logger.exception("Approval prompt failed; denying %s", tool_name)
            decision = DENY
        if decision in (ALLOW, ALLOW_SESSION):
            self.approvals_granted += 1
            if decision == ALLOW_SESSION and rule:
                self.session_rules.add(rule)
            return True
        self.approvals_denied += 1
        return False

    # -- runs ----------------------------------------------------------------------------
    def cancel(self) -> None:
        self.stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._run_lock.locked()

    def run(self, goal: str, target: str, scope: List[str], session_id: Optional[str] = None) -> RunOutcome:
        """Runs one task to completion on the calling thread. Only one task runs at a time."""
        session_id = session_id or f"task-{uuid.uuid4().hex[:8]}"
        if not self._run_lock.acquire(blocking=False):
            return RunOutcome(session_id, "rejected", error="A task is already running in this session.")
        try:
            return self._run(goal, target, scope, session_id)
        finally:
            self.current_loop = None
            self._run_lock.release()

    def _run(self, goal: str, target: str, scope: List[str], session_id: str) -> RunOutcome:
        from agent.loop import AgentLoop

        self.stop_event.clear()
        self.last_evidence_bundle = None
        self.approvals_granted = 0
        self.approvals_denied = 0
        try:
            # Built inside the try: a failure here must still end the run with an outcome
            loop = AgentLoop(
                provider=self.provider,
                storage_manager=self.storage,
                registry=self.registry,
                max_iterations=self.max_iterations,
                config={**self.config, "plan_mode": self.plan_mode},
                event_bus=self.event_bus,
                approval_callback=self.approve,
                on_stream_delta=self.on_delta,
                stop_event=self.stop_event,
                quiet=True,
            )
            loop.ui_active = True
            loop.embedded_ui = True
            self.current_loop = loop
            result = loop.run(
                task_goal=goal + PLAN_MODE_SUFFIX if self.plan_mode else goal,
                target=target,
                scope=scope,
                session_id=session_id,
                conversation_history=self.conversation[-MAX_CONVERSATION_MESSAGES:],
                attached_context=build_mention_context(goal),
            )
        except Exception as error:
            logger.exception("Agent loop failed")
            return RunOutcome(session_id, "failed", error=f"Agent loop error: {error}")
        result = result if isinstance(result, dict) else {}
        messages = result.get("messages", [])
        answers = [m.get("content") or "" for m in messages if m.get("role") == "assistant"]
        final_answer = next((text for text in reversed(answers) if text.strip()), "")
        self.remember_turn(goal, final_answer)
        status = "cancelled" if self.stop_event.is_set() else str(result.get("status", "completed"))
        evidence_report = self._evidence_report(loop, goal, session_id)
        return RunOutcome(
            session_id=session_id,
            status=status,
            final_answer=final_answer,
            error=loop.last_error or None,
            evidence_report=evidence_report,
            evidence_bundle=self.last_evidence_bundle,
            messages=messages,
        )

    def _evidence_report(self, loop: Any, goal: str = "", session_id: str = "task") -> Optional[str]:
        if getattr(loop, "last_verification", None) is None:
            return None
        from tools.filesystem import get_active_workspace
        from verification.evidence_bundle import create_evidence_bundle
        from verification.evidence_report import build_evidence_report

        workspace = get_active_workspace()
        report = build_evidence_report(
            loop.last_verification, workspace, self.approvals_granted, self.approvals_denied,
        )
        model = str(getattr(self.provider, "model_name", type(self.provider).__name__))
        try:
            bundle_path = create_evidence_bundle(
                workspace=workspace,
                session_id=session_id,
                task=goal,
                verification=loop.last_verification,
                approvals_granted=self.approvals_granted,
                approvals_denied=self.approvals_denied,
                model=model,
                evidence_report=report,
            )
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            logger.exception("Could not write Evidence Bundle for %s", session_id)
            return report
        self.last_evidence_bundle = str(bundle_path)
        if report is not None:
            relative_bundle = os.path.relpath(bundle_path, workspace)
            report += f"\n- Evidence Bundle: `{relative_bundle}`"
        return report

    def remember_turn(self, user_text: str, answer: str) -> None:
        self.conversation.append({"role": "user", "content": user_text})
        if answer.strip():
            self.conversation.append({"role": "assistant", "content": answer})
        save_conversation(self.conversation)
