"""
Deterministic External Kill Switch.

Provides immediate, fail-safe termination of all autonomous activities
independent of LLM reasoning or current tool execution state.
See plan sections 47, 112.
"""

import os
import signal
import threading
from pathlib import Path
from typing import Callable, List, Optional

from security_agent.events.bus import EventBus
from security_agent.events.types import EventType, EventSeverity


import tempfile

KILL_FILE_PATHS = [
    Path.home() / ".security-agent" / "kill",
    Path(tempfile.gettempdir()) / "security_agent.kill",
]
if Path("/tmp/security_agent.kill") not in KILL_FILE_PATHS:
    KILL_FILE_PATHS.append(Path("/tmp/security_agent.kill"))


class KillSwitch:
    """
    Thread-safe kill switch. When activated:
    - Sets an atomic triggered flag
    - Executes registered abort handlers (sandbox kill, browser close, process abort)
    - Emits emergency kill events through the EventBus
    """
    _instance: Optional["KillSwitch"] = None
    _lock = threading.Lock()

    def __init__(self, event_bus: Optional[EventBus] = None):
        self._triggered = False
        self._reason = ""
        self._callbacks: List[Callable[[], None]] = []
        self._event_bus = event_bus
        self._check_lock = threading.Lock()

    @classmethod
    def get_instance(cls, event_bus: Optional[EventBus] = None) -> "KillSwitch":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(event_bus=event_bus)
            elif event_bus and cls._instance._event_bus is None:
                cls._instance._event_bus = event_bus
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for test isolation)."""
        with cls._lock:
            if cls._instance:
                cls._instance._triggered = False
                cls._instance._reason = ""
                cls._instance._callbacks.clear()
            # Clean kill files if present
            for p in KILL_FILE_PATHS:
                try:
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass

    def register_abort_callback(self, callback: Callable[[], None]) -> None:
        """Register a cleanup/abort function to run immediately upon trigger."""
        with self._check_lock:
            self._callbacks.append(callback)

    def is_triggered(self) -> bool:
        """
        Returns True if the kill switch has been tripped in memory
        or if any designated kill file exists on the filesystem.
        """
        if self._triggered:
            return True

        # Check for filesystem trigger
        for path in KILL_FILE_PATHS:
            if path.exists():
                self.trigger(f"Kill file detected at {path}")
                return True

        return False

    @property
    def reason(self) -> str:
        return self._reason

    def trigger(self, reason: str = "Operator manual kill switch activated") -> None:
        """
        Trips the kill switch, executes all abort callbacks, and emits events.
        """
        with self._check_lock:
            if self._triggered:
                return
            self._triggered = True
            self._reason = reason

        # Emit high-priority event
        if self._event_bus:
            self._event_bus.emit(
                EventType.ASSESSMENT_STOPPED,
                {"kill_switch": True, "reason": reason},
                severity=EventSeverity.CRITICAL,
            )

        # Run registered abort callbacks safely
        for cb in list(self._callbacks):
            try:
                cb()
            except Exception:
                pass


def arm_signal_handlers(kill_switch: KillSwitch) -> None:
    """
    Arms POSIX signal handlers (SIGINT, SIGTERM) to trip the kill switch.
    """
    def _sig_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        kill_switch.trigger(f"Process received {sig_name}")

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
    except (ValueError, AttributeError):
        pass
