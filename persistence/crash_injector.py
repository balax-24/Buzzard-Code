"""
Phase 14 Deterministic Crash Injection Engine.

Injects simulated system/process crashes at explicit lifecycle boundaries:
- BEFORE_TOOL_EXECUTION
- AFTER_TOOL_EXECUTION
- BEFORE_EVIDENCE_INGESTION
- AFTER_EVIDENCE_INGESTION
- BEFORE_GRAPH_SYNC
- AFTER_GRAPH_SYNC
- BEFORE_CHECKPOINT_COMMIT
- AFTER_CHECKPOINT_COMMIT
- BEFORE_MODEL_RESPONSE
- AFTER_MODEL_RESPONSE
- DURING_BROWSER_OPERATION

Used in test harnesses and benchmarks to prove that state recovers cleanly with zero loss of committed data.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional, Set, Callable, Dict, Any


class CrashPoint(str, Enum):
    BEFORE_TOOL_EXECUTION = "BEFORE_TOOL_EXECUTION"
    AFTER_TOOL_EXECUTION = "AFTER_TOOL_EXECUTION"
    BEFORE_EVIDENCE_INGESTION = "BEFORE_EVIDENCE_INGESTION"
    AFTER_EVIDENCE_INGESTION = "AFTER_EVIDENCE_INGESTION"
    BEFORE_GRAPH_SYNC = "BEFORE_GRAPH_SYNC"
    AFTER_GRAPH_SYNC = "AFTER_GRAPH_SYNC"
    BEFORE_CHECKPOINT_COMMIT = "BEFORE_CHECKPOINT_COMMIT"
    AFTER_CHECKPOINT_COMMIT = "AFTER_CHECKPOINT_COMMIT"
    BEFORE_MODEL_RESPONSE = "BEFORE_MODEL_RESPONSE"
    AFTER_MODEL_RESPONSE = "AFTER_MODEL_RESPONSE"
    DURING_BROWSER_OPERATION = "DURING_BROWSER_OPERATION"


class SimulatedCrashError(Exception):
    """Raised when a simulated crash is triggered by the CrashInjector."""
    def __init__(self, crash_point: CrashPoint, details: str = ""):
        self.crash_point = crash_point
        self.details = details
        super().__init__(f"CRASH_INJECTED at [{crash_point.value}]: {details}")


class CrashInjector:
    """
    Deterministic crash injection controller.
    """

    def __init__(self):
        self.active_crash_points: Set[CrashPoint] = set()
        self.trigger_turn: Optional[int] = None
        self.trigger_count: int = 0
        self.max_triggers: int = 1
        self.callbacks: Dict[CrashPoint, Callable[[], None]] = {}

    def set_crash_point(
        self,
        crash_point: CrashPoint,
        trigger_turn: Optional[int] = None,
        max_triggers: int = 1
    ) -> None:
        self.active_crash_points.add(crash_point)
        self.trigger_turn = trigger_turn
        self.max_triggers = max_triggers
        self.trigger_count = 0

    def clear(self) -> None:
        self.active_crash_points.clear()
        self.trigger_turn = None
        self.trigger_count = 0

    def check_and_trigger(
        self,
        point: CrashPoint,
        current_turn: Optional[int] = None,
        context_details: str = ""
    ) -> None:
        """
        Evaluates whether a crash should be triggered at this point.
        """
        if point not in self.active_crash_points:
            return

        if self.trigger_turn is not None and current_turn is not None:
            if current_turn != self.trigger_turn:
                return

        if self.trigger_count >= self.max_triggers:
            return

        self.trigger_count += 1

        # Execute hook callback if registered
        if point in self.callbacks:
            self.callbacks[point]()

        raise SimulatedCrashError(point, f"Turn {current_turn or 0}: {context_details}")
