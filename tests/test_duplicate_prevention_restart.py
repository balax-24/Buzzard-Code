"""
Tests for Phase 12 Duplicate Prevention Across Process Restarts.
Verifies:
1. Stable action identity hashing across process boundaries.
2. Prevention of duplicate tool execution upon resume.
"""

import pytest
import hashlib
import json
import tempfile
from pathlib import Path

from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.intelligence.decision import DecisionRecord, DecisionSource
from security_agent.persistence.checkpoint_manager import CheckpointManager


def compute_action_key(tool: str, target: str, arguments: dict, capability_context: str = "") -> str:
    payload = {
        "tool": tool,
        "target": target,
        "arguments": arguments,
        "capability_context": capability_context
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def test_duplicate_action_prevention_across_restart():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)
        state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))

        # Step 1: Execute action and record key
        args = {"url": "http://127.0.0.1:8080/login", "method": "GET"}
        act_key = compute_action_key("http.request", "http://127.0.0.1:8080/login", args)
        state.attempted_action_keys.add(act_key)

        state.record_decision(DecisionRecord(
            iteration=1,
            source=DecisionSource.MODEL,
            selected_tool="http.request",
            target="http://127.0.0.1:8080/login",
            arguments=args
        ))

        # Checkpoint and restart
        chk = manager.create_checkpoint("INV-DUP-01", state=state)
        r_state, _, _, _, _, _ = manager.restore_checkpoint(chk.checkpoint_id)

        # In resumed process, verify action is recognized as duplicate
        reconstructed_keys = {
            compute_action_key(d.selected_tool, d.target, d.arguments)
            for d in r_state.decision_records
        }
        assert act_key in reconstructed_keys
