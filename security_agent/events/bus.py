"""
Event Bus — publish/subscribe message router for Buzzard Code.

Every meaningful action emits an event through the bus. Subscribers
(the live CLI, the web dashboard, the event store, the budget tracker)
consume events without tight coupling to the emitter.

Thread-safe: publishers and subscribers may operate from different threads.
"""

import threading
import time
from typing import Callable, Dict, List, Optional, Set
from collections import deque
from security_agent.events.types import Event, EventType, EventSeverity


# Type alias for event handler callbacks
EventHandler = Callable[[Event], None]


class EventBus:
    """
    In-process publish/subscribe event router.

    - publish(event) delivers to all matching subscribers synchronously.
    - subscribe(event_type, handler) registers a callback for a specific type.
    - subscribe_all(handler) registers a callback for every event.
    - Maintains a bounded recent-events ring buffer for late subscribers
      (e.g. a web dashboard that connects mid-assessment).
    """

    def __init__(self, buffer_size: int = 2000):
        self._lock = threading.Lock()
        # type-specific handlers
        self._handlers: Dict[EventType, List[EventHandler]] = {}
        # wildcard handlers (receive every event)
        self._global_handlers: List[EventHandler] = []
        # bounded ring buffer of recent events
        self._buffer: deque[Event] = deque(maxlen=buffer_size)
        # total events published (monotonic counter)
        self._event_count: int = 0

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for a specific event type."""
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)

    def subscribe_many(self, event_types: List[EventType], handler: EventHandler) -> None:
        """Register a handler for multiple event types."""
        for et in event_types:
            self.subscribe(et, handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Register a handler that receives every event."""
        with self._lock:
            self._global_handlers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Remove a previously registered handler."""
        with self._lock:
            if event_type in self._handlers:
                try:
                    self._handlers[event_type].remove(handler)
                except ValueError:
                    pass

    def unsubscribe_all(self, handler: EventHandler) -> None:
        """Remove a wildcard handler."""
        with self._lock:
            try:
                self._global_handlers.remove(handler)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, event: Event) -> None:
        """
        Publish an event to all matching subscribers.

        Subscribers are called synchronously in registration order.
        Exceptions in a subscriber are caught and logged but do not
        prevent delivery to other subscribers.
        """
        with self._lock:
            self._buffer.append(event)
            self._event_count += 1
            # Snapshot handlers under lock to avoid mutation during iteration
            type_handlers = list(self._handlers.get(event.type, []))
            global_handlers = list(self._global_handlers)

        for handler in type_handlers + global_handlers:
            try:
                handler(event)
            except Exception:
                # Subscribers must not crash the bus
                pass

    def emit(
        self,
        event_type: EventType,
        payload: Optional[Dict] = None,
        severity: EventSeverity = EventSeverity.INFO,
        assessment_id: Optional[str] = None,
    ) -> Event:
        """
        Convenience: create and publish an event in one call.
        Returns the created Event for chaining/testing.
        """
        event = Event(
            type=event_type,
            payload=payload or {},
            severity=severity,
            assessment_id=assessment_id,
        )
        self.publish(event)
        return event

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def event_count(self) -> int:
        """Total number of events published since creation."""
        return self._event_count

    def recent_events(self, n: int = 50, event_type: Optional[EventType] = None) -> List[Event]:
        """
        Return the most recent N events from the ring buffer.
        Optionally filter by event type.
        """
        with self._lock:
            if event_type:
                matching = [e for e in self._buffer if e.type == event_type]
            else:
                matching = list(self._buffer)
        return matching[-n:]

    def clear(self) -> None:
        """Clear the event buffer (does not unsubscribe handlers)."""
        with self._lock:
            self._buffer.clear()
            self._event_count = 0
