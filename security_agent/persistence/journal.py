"""
Phase 12 Append-Only Investigation Journal & Event Replay Engine.

Records all fine-grained events:
- TOOL_SELECTED, TOOL_EXECUTED, TOOL_FAILED
- EVIDENCE_ADDED, HYPOTHESIS_CREATED, HYPOTHESIS_REFUTED, HYPOTHESIS_REOPENED
- CAPABILITY_ACQUIRED, CAPABILITY_VERIFIED, SESSION_CREATED, SESSION_UPDATED, SESSION_EXPIRED
- GRAPH_EXPANDED, GRAPH_NODE_EXHAUSTED, VERIFICATION_REQUIRED, VERIFICATION_SUCCESS
- OBJECTIVE_CHANGED, STRATEGY_CHANGED, CHECKPOINT_CREATED, CHECKPOINT_RESTORED
- BUDGET_WARNING, BUDGET_EXHAUSTED, INVESTIGATION_PAUSED, INVESTIGATION_RESUMED

Supports deterministic full-trajectory event replay.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from security_agent.persistence.models import JournalEntry, JournalEventType
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from security_agent.agent.assessment_state import AssessmentState


class InvestigationJournal:
    """
    Append-only SQLite event journal with deterministic state reconstruction.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self._db_path = Path(db_path)
        else:
            self._db_path = Path.home() / ".security-agent" / "investigation_journal.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS investigation_journal (
            event_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp REAL NOT NULL,
            source TEXT NOT NULL,
            payload TEXT NOT NULL,
            evidence_ids TEXT,
            state_version INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_journal_inv_time
            ON investigation_journal (investigation_id, timestamp);
        """
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript(schema)
                conn.commit()
            finally:
                conn.close()

    def record(
        self,
        investigation_id: str,
        event_type: JournalEventType,
        source: str = "SYSTEM",
        payload: Optional[Dict[str, Any]] = None,
        evidence_ids: Optional[List[str]] = None,
        state_version: int = 1
    ) -> JournalEntry:
        entry = JournalEntry(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            investigation_id=investigation_id,
            event_type=event_type,
            timestamp=time.time(),
            source=source,
            payload=payload or {},
            evidence_ids=evidence_ids or [],
            state_version=state_version
        )

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO investigation_journal
                    (event_id, investigation_id, event_type, timestamp, source, payload, evidence_ids, state_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.event_id,
                        entry.investigation_id,
                        entry.event_type.value,
                        entry.timestamp,
                        entry.source,
                        json.dumps(entry.payload),
                        json.dumps(entry.evidence_ids),
                        entry.state_version
                    )
                )
                conn.commit()
            finally:
                conn.close()
        return entry

    def get_events(self, investigation_id: str) -> List[JournalEntry]:
        with self._lock, self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM investigation_journal WHERE investigation_id = ? ORDER BY timestamp ASC",
                (investigation_id,)
            )
            rows = cursor.fetchall()
            events = []
            for r in rows:
                events.append(JournalEntry(
                    event_id=r["event_id"],
                    investigation_id=r["investigation_id"],
                    event_type=JournalEventType(r["event_type"]),
                    timestamp=r["timestamp"],
                    source=r["source"],
                    payload=json.loads(r["payload"]),
                    evidence_ids=json.loads(r["evidence_ids"]) if r["evidence_ids"] else [],
                    state_version=r["state_version"]
                ))
            return events

    def replay(self, investigation_id: str, target: str = "127.0.0.1") -> "AssessmentState":
        """
        Reconstructs the logical AssessmentState by replaying all historical journal events.
        """
        from security_agent.agent.assessment_state import (
            AssessmentState,
            AssessmentContext,
            ServiceRecord,
            Capability,
            CapabilityType,
            ObjectiveStatus,
            AssessmentPhase,
        )
        from security_agent.intelligence.decision import DecisionRecord, DecisionSource

        events = self.get_events(investigation_id)
        state = AssessmentState(context=AssessmentContext(target=target))

        for ev in events:
            p = ev.payload

            if ev.event_type == JournalEventType.EVIDENCE_ADDED:
                if "service" in p:
                    state.record_service(
                        host=p.get("host", target),
                        port=p["port"],
                        service=p["service"],
                        protocol=p.get("protocol", "tcp"),
                        evidence_id=ev.evidence_ids[0] if ev.evidence_ids else "EVI-0"
                    )

            elif ev.event_type == JournalEventType.CAPABILITY_ACQUIRED:
                cap_id = p["capability_id"]
                state.capabilities[cap_id] = Capability(
                    capability_id=cap_id,
                    capability_type=CapabilityType(p["capability_type"]),
                    target_scope=p.get("target_scope", target),
                    source_evidence_ids=ev.evidence_ids,
                    metadata=p.get("metadata", {}),
                    verified=p.get("verified", True)
                )

            elif ev.event_type == JournalEventType.TOOL_EXECUTED:
                state.record_decision(DecisionRecord(
                    iteration=len(state.decision_records) + 1,
                    source=DecisionSource(ev.source),
                    selected_tool=p.get("tool", "unknown"),
                    target=p.get("target", target),
                    arguments=p.get("arguments", {})
                ))

            elif ev.event_type == JournalEventType.VERIFICATION_SUCCESS:
                state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
                state.verification_success = True
                if "finding" in p:
                    state.findings.append(p["finding"])

        return state
