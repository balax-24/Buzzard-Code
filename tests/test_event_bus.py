"""Tests for the EventBus, EventStore, and Event types."""

import time
import threading
import pytest
from security_agent.events.types import Event, EventType, EventSeverity
from security_agent.events.bus import EventBus
from security_agent.events.store import EventStore


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class TestEvent:
    def test_event_creation(self):
        e = Event(type=EventType.ASSESSMENT_STARTED, payload={"target": "example.com"})
        assert e.type == EventType.ASSESSMENT_STARTED
        assert e.payload["target"] == "example.com"
        assert e.severity == EventSeverity.INFO
        assert e.id.startswith("evt-")

    def test_event_serialization_roundtrip(self):
        e = Event(
            type=EventType.TOOL_COMPLETED,
            payload={"tool": "browser.get_forms", "duration_ms": 812},
            severity=EventSeverity.INFO,
            assessment_id="session-abc123",
        )
        d = e.to_dict()
        assert d["type"] == "tool.completed"
        assert d["severity"] == "info"
        assert d["assessment_id"] == "session-abc123"

        restored = Event.from_dict(d)
        assert restored.type == EventType.TOOL_COMPLETED
        assert restored.payload["tool"] == "browser.get_forms"
        assert restored.assessment_id == "session-abc123"

    def test_event_summary(self):
        e = Event(type=EventType.FINDING_VERIFIED, payload={"message": "SQL injection confirmed"})
        assert "SQL injection confirmed" in e.summary

    def test_event_summary_empty_payload(self):
        e = Event(type=EventType.ASSESSMENT_STARTED)
        assert "assessment.started" in e.summary


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------

class TestEventBus:
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TOOL_STARTED, lambda e: received.append(e))
        
        bus.emit(EventType.TOOL_STARTED, {"tool": "browser.open"})
        assert len(received) == 1
        assert received[0].payload["tool"] == "browser.open"

    def test_wildcard_subscriber(self):
        bus = EventBus()
        all_events = []
        bus.subscribe_all(lambda e: all_events.append(e))
        
        bus.emit(EventType.TOOL_STARTED)
        bus.emit(EventType.TOOL_COMPLETED)
        bus.emit(EventType.FINDING_VERIFIED)
        assert len(all_events) == 3

    def test_type_filtering(self):
        bus = EventBus()
        tool_events = []
        finding_events = []
        bus.subscribe(EventType.TOOL_STARTED, lambda e: tool_events.append(e))
        bus.subscribe(EventType.FINDING_VERIFIED, lambda e: finding_events.append(e))
        
        bus.emit(EventType.TOOL_STARTED)
        bus.emit(EventType.FINDING_VERIFIED)
        bus.emit(EventType.TOOL_STARTED)
        
        assert len(tool_events) == 2
        assert len(finding_events) == 1

    def test_unsubscribe(self):
        bus = EventBus()
        received = []
        handler = lambda e: received.append(e)
        bus.subscribe(EventType.TOOL_STARTED, handler)
        
        bus.emit(EventType.TOOL_STARTED)
        assert len(received) == 1
        
        bus.unsubscribe(EventType.TOOL_STARTED, handler)
        bus.emit(EventType.TOOL_STARTED)
        assert len(received) == 1  # should not increase

    def test_event_count(self):
        bus = EventBus()
        assert bus.event_count == 0
        bus.emit(EventType.ASSESSMENT_STARTED)
        bus.emit(EventType.TOOL_STARTED)
        assert bus.event_count == 2

    def test_recent_events(self):
        bus = EventBus()
        for i in range(10):
            bus.emit(EventType.TOOL_STARTED, {"index": i})
        
        recent = bus.recent_events(n=5)
        assert len(recent) == 5
        assert recent[0].payload["index"] == 5
        assert recent[-1].payload["index"] == 9

    def test_recent_events_filtered(self):
        bus = EventBus()
        bus.emit(EventType.TOOL_STARTED)
        bus.emit(EventType.FINDING_VERIFIED)
        bus.emit(EventType.TOOL_STARTED)
        
        recent = bus.recent_events(n=10, event_type=EventType.TOOL_STARTED)
        assert len(recent) == 2

    def test_subscriber_exception_isolation(self):
        """A crashing subscriber must not prevent other subscribers from receiving events."""
        bus = EventBus()
        received = []

        def crasher(e):
            raise RuntimeError("boom")

        bus.subscribe(EventType.TOOL_STARTED, crasher)
        bus.subscribe(EventType.TOOL_STARTED, lambda e: received.append(e))
        
        bus.emit(EventType.TOOL_STARTED)
        assert len(received) == 1  # second handler still called

    def test_thread_safety(self):
        bus = EventBus()
        received = []
        bus.subscribe_all(lambda e: received.append(e))
        
        def publisher(n):
            for _ in range(n):
                bus.emit(EventType.TOOL_STARTED)
        
        threads = [threading.Thread(target=publisher, args=(50,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(received) == 200

    def test_emit_returns_event(self):
        bus = EventBus()
        event = bus.emit(EventType.ASSESSMENT_STARTED, {"target": "test"})
        assert isinstance(event, Event)
        assert event.type == EventType.ASSESSMENT_STARTED

    def test_clear(self):
        bus = EventBus()
        bus.emit(EventType.TOOL_STARTED)
        bus.emit(EventType.TOOL_STARTED)
        assert bus.event_count == 2
        
        bus.clear()
        assert bus.event_count == 0
        assert len(bus.recent_events()) == 0


# ---------------------------------------------------------------------------
# EventStore
# ---------------------------------------------------------------------------

class TestEventStore:
    @pytest.fixture
    def store(self, tmp_path):
        db_path = str(tmp_path / "test_events.db")
        return EventStore(db_path=db_path)

    def test_persist_and_retrieve(self, store):
        event = Event(
            type=EventType.TOOL_COMPLETED,
            payload={"tool": "browser.open"},
            assessment_id="session-001",
        )
        store.persist(event)
        
        events = store.get_events("session-001")
        assert len(events) == 1
        assert events[0].type == EventType.TOOL_COMPLETED
        assert events[0].payload["tool"] == "browser.open"

    def test_filter_by_type(self, store):
        store.persist(Event(type=EventType.TOOL_STARTED, assessment_id="s1"))
        store.persist(Event(type=EventType.FINDING_VERIFIED, assessment_id="s1"))
        store.persist(Event(type=EventType.TOOL_STARTED, assessment_id="s1"))
        
        tools = store.get_events("s1", event_type=EventType.TOOL_STARTED)
        assert len(tools) == 2

    def test_filter_by_assessment(self, store):
        store.persist(Event(type=EventType.TOOL_STARTED, assessment_id="s1"))
        store.persist(Event(type=EventType.TOOL_STARTED, assessment_id="s2"))
        
        assert len(store.get_events("s1")) == 1
        assert len(store.get_events("s2")) == 1

    def test_get_recent(self, store):
        for i in range(10):
            e = Event(type=EventType.TOOL_STARTED, payload={"i": i}, assessment_id="s1")
            e.timestamp = 1000.0 + i
            store.persist(e)
        
        recent = store.get_recent("s1", n=3)
        assert len(recent) == 3
        # Should be in chronological order
        assert recent[0].payload["i"] < recent[-1].payload["i"]

    def test_count_events(self, store):
        for _ in range(5):
            store.persist(Event(type=EventType.TOOL_STARTED, assessment_id="s1"))
        assert store.count_events("s1") == 5
        assert store.count_events("s2") == 0

    def test_bus_integration(self, store):
        """EventStore can be used as a bus subscriber."""
        bus = EventBus()
        bus.subscribe_all(store.persist)
        
        bus.emit(EventType.ASSESSMENT_STARTED, {"target": "test"}, assessment_id="s1")
        bus.emit(EventType.TOOL_STARTED, {"tool": "scan"}, assessment_id="s1")
        
        events = store.get_events("s1")
        assert len(events) == 2
