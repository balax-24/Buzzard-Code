"""
Tests for Phase 12 Checkpoint Integrity, Tamper Detection, and Corruption Handling.
Verifies:
1. Rejection of corrupted JSON files.
2. Rejection of tampered payloads (hash mismatch).
3. Rejection of incompatible schema versions.
"""

import pytest
import json
import tempfile
from pathlib import Path

from agent.assessment_state import AssessmentState, AssessmentContext
from persistence.checkpoint_manager import CheckpointManager, CheckpointCorruptionError


def test_corrupted_json_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)
        state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
        chk = manager.create_checkpoint("INV-001", state=state)

        chk_path = manager._get_checkpoint_path(chk.checkpoint_id)
        # Corrupt JSON file content
        with open(chk_path, "w") as f:
            f.write("{corrupt_json_structure")

        with pytest.raises(CheckpointCorruptionError, match="JSON is corrupt"):
            manager.restore_checkpoint(chk.checkpoint_id)


def test_tampered_payload_checksum_mismatch():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)
        state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
        chk = manager.create_checkpoint("INV-001", state=state)

        chk_path = manager._get_checkpoint_path(chk.checkpoint_id)
        with open(chk_path, "r") as f:
            data = json.load(f)

        # Silently tamper with the target
        data["state_snapshot"]["target"] = "hacked.attacker.com"
        with open(chk_path, "w") as f:
            json.dump(data, f, indent=2)

        with pytest.raises(CheckpointCorruptionError, match="hash mismatch"):
            manager.restore_checkpoint(chk.checkpoint_id)


def test_incompatible_schema_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)
        state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
        chk = manager.create_checkpoint("INV-001", state=state)

        chk_path = manager._get_checkpoint_path(chk.checkpoint_id)
        with open(chk_path, "r") as f:
            data = json.load(f)

        # Change schema version
        data["integrity"]["schema_version"] = "99.0.0"
        with open(chk_path, "w") as f:
            json.dump(data, f, indent=2)

        with pytest.raises(CheckpointCorruptionError, match="Incompatible checkpoint schema"):
            manager.restore_checkpoint(chk.checkpoint_id)
