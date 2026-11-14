"""
Specialized coding agent loop (roadmap H).

A focused, lean execution loop for software engineering tasks.
Binds to the lightweight coding tool registry and enforces the completion gate.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agent.loop import AgentLoop, CODING_TOOL_NAMES, CODING_SESSION_ONLY_TOOLS
from coding.interfaces import CodingOutcome
from coding.registry import create_coding_registry
from events.bus import EventBus
from model.provider import ModelProvider
from storage.db import StorageManager
from tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class CodingLoop(AgentLoop):
    """
    Focused autonomous coding loop.
    Defaults to the lightweight coding registry instead of the full pentest registry.
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
        approval_callback: Optional[Any] = None,
    ):
        coding_reg = registry or create_coding_registry()
        super().__init__(
            provider=provider,
            registry=coding_reg,
            storage_manager=storage_manager,
            max_iterations=max_iterations,
            native_tools=native_tools,
            config=config,
            event_bus=event_bus,
            on_stream_delta=on_stream_delta,
            stop_event=stop_event,
            quiet=quiet,
            model_router=model_router,
            approval_callback=approval_callback,
        )

    def run_coding_task(
        self,
        goal: str,
        target: Optional[str] = "localhost",
        scope: Optional[List[str]] = None,
        session_id: Optional[str] = None,
    ) -> CodingOutcome:
        """Execute a coding goal to completion with verification."""
        scope_targets = list(scope) if scope else ["localhost", "127.0.0.1"]
        raw_result = self.run(
            task_prompt=goal,
            target=target,
            scope_targets=scope_targets,
            session_id=session_id,
        )

        status = "completed" if raw_result.get("success") else "failed"
        if getattr(self, "cancelled", False) or (self.stop_event and self.stop_event.is_set()):
            status = "cancelled"

        evidence_report = getattr(self, "latest_evidence_report", None)
        changed_files = list(getattr(self, "modified_files", []))
        tests_passed = bool(getattr(self, "tests_passed", raw_result.get("success", False)))

        return CodingOutcome(
            status=status,
            final_answer=str(raw_result.get("final_answer", "") or raw_result.get("summary", "")),
            error=raw_result.get("error"),
            evidence_report=evidence_report,
            changed_files=changed_files,
            tests_passed=tests_passed,
            metrics=raw_result.get("metrics", {}),
        )
