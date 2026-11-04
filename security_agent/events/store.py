"""
Persistent event store backed by SQLite.

Every event published to the EventBus is persisted here for:
- Resume / replay of assessments
- Debugging agent behavior  
- Audit trails
- Historical reporting
- Live dashboard data source
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any

from security_agent.events.types import Event, EventType, EventSeverity


class EventStore:
    """
    Append-only SQLite store for assessment events.
    
    Subscribes to the EventBus as a global handler and persists every
    event. Provides query methods for replay and reporting.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self._db_path = Path(db_path)
        else:
            self._db_path = Path.home() / ".security-agent" / "events.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS assessment_events (
            id TEXT PRIMARY KEY,
            assessment_id TEXT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp REAL NOT NULL,
            payload TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_assessment
            ON assessment_events (assessment_id, timestamp);

        CREATE INDEX IF NOT EXISTS idx_events_type
            ON assessment_events (type);
        """
        with self._get_conn() as conn:
            conn.executescript(schema)
            conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def persist(self, event: Event) -> None:
        """
        Persist a single event. Designed to be used as an EventBus
        subscriber callback: `bus.subscribe_all(store.persist)`
        """
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO assessment_events
                        (id, assessment_id, type, severity, timestamp, payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.id,
                        event.assessment_id,
                        event.type.value,
                        event.severity.value,
                        event.timestamp,
                        json.dumps(event.payload),
                    ),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_events(
        self,
        assessment_id: str,
        event_type: Optional[EventType] = None,
        limit: int = 500,
    ) -> List[Event]:
        """Retrieve events for an assessment, optionally filtered by type."""
        with self._get_conn() as conn:
            if event_type:
                rows = conn.execute(
                    """
                    SELECT * FROM assessment_events
                    WHERE assessment_id = ? AND type = ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (assessment_id, event_type.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM assessment_events
                    WHERE assessment_id = ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (assessment_id, limit),
                ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def get_recent(self, assessment_id: str, n: int = 20) -> List[Event]:
        """Get the N most recent events for an assessment."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM assessment_events
                WHERE assessment_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (assessment_id, n),
            ).fetchall()
        # Return in chronological order
        return [self._row_to_event(r) for r in reversed(rows)]

    def count_events(self, assessment_id: str) -> int:
        """Total event count for an assessment."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM assessment_events WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
            return row["cnt"] if row else 0

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        d = dict(row)
        return Event(
            id=d["id"],
            assessment_id=d.get("assessment_id"),
            type=EventType(d["type"]),
            severity=EventSeverity(d["severity"]),
            timestamp=d["timestamp"],
            payload=json.loads(d["payload"]),
        )
