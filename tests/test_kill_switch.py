"""
Tests for KillSwitch subsystem.
"""

import os
from pathlib import Path
import pytest
from security_agent.events.bus import EventBus
from security_agent.events.types import EventType
from security_agent.security.kill_switch import KillSwitch, KILL_FILE_PATHS


@pytest.fixture(autouse=True)
def cleanup_kill_switch():
    KillSwitch.reset()
    yield
    KillSwitch.reset()


def test_kill_switch_trigger_in_memory():
    bus = EventBus()
    events = []
    bus.subscribe(EventType.ASSESSMENT_STOPPED, lambda e: events.append(e))

    ks = KillSwitch(event_bus=bus)
    assert not ks.is_triggered()

    aborted = []
    ks.register_abort_callback(lambda: aborted.append("aborted"))

    ks.trigger("Manual emergency stop")
    assert ks.is_triggered()
    assert ks.reason == "Manual emergency stop"
    assert aborted == ["aborted"]
    assert len(events) == 1
    assert events[0].payload.get("kill_switch") is True


def test_kill_switch_file_trigger(tmp_path):
    bus = EventBus()
    ks = KillSwitch(event_bus=bus)

    # Use first designated path
    test_kill_file = KILL_FILE_PATHS[1]
    try:
        test_kill_file.touch()
        assert ks.is_triggered()
        assert "Kill file detected" in ks.reason
    finally:
        if test_kill_file.exists():
            test_kill_file.unlink()
