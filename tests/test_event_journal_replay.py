"""
Tests for Phase 12 Append-Only Journal and Event Replay Engine.
Verifies:
1. Recording fine-grained events.
2. Full logical state reconstruction from event replay.
"""

import pytest
import tempfile
from pathlib import Path

from security_agent.persistence.journal import InvestigationJournal, JournalEventType
from security_agent.agent.assessment_state import CapabilityType, ObjectiveStatus


def test_journal_recording_and_state_replay():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "journal.db"
        journal = InvestigationJournal(db_path=str(db_path))
        inv_id = "INV-REPLAY-01"

        # 1. Event: Service Discovered
        journal.record(
            investigation_id=inv_id,
            event_type=JournalEventType.EVIDENCE_ADDED,
            source="nmap_scan",
            payload={"port": 8080, "service": "http"},
            evidence_ids=["EVI-PORT-01"]
        )

        # 2. Event: Tool Executed (Autonomous Model action)
        journal.record(
            investigation_id=inv_id,
            event_type=JournalEventType.TOOL_EXECUTED,
            source="MODEL",
            payload={"tool": "http.request", "target": "http://127.0.0.1:8080/login", "arguments": {"url": "http://127.0.0.1:8080/login"}},
            evidence_ids=["EVI-HTTP-01"]
        )

        # 3. Event: Capability Acquired
        journal.record(
            investigation_id=inv_id,
            event_type=JournalEventType.CAPABILITY_ACQUIRED,
            source="SYSTEM",
            payload={"capability_id": "cap-user", "capability_type": CapabilityType.AUTHENTICATED.value, "target_scope": "127.0.0.1"},
            evidence_ids=["EVI-AUTH-01"]
        )

        # 4. Event: Objective Verified
        journal.record(
            investigation_id=inv_id,
            event_type=JournalEventType.VERIFICATION_SUCCESS,
            source="finding_verifier",
            payload={"finding": {"title": "SQL Injection Auth Bypass", "severity": "HIGH"}}
        )

        # 5. Replay events to reconstruct state
        replayed_state = journal.replay(inv_id, target="127.0.0.1")

        # 6. Verify Replayed State matches exact facts
        assert "127.0.0.1:8080/tcp" in replayed_state.services
        assert "cap-user" in replayed_state.capabilities
        assert len(replayed_state.decision_records) == 1
        assert replayed_state.decision_records[0].selected_tool == "http.request"
        assert replayed_state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert len(replayed_state.findings) == 1
        assert replayed_state.findings[0]["title"] == "SQL Injection Auth Bypass"

        del journal
        import gc
        gc.collect()
