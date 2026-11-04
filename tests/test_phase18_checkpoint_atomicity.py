import pytest
from pathlib import Path
from persistence.checkpoint import AtomicCheckpoint, CheckpointError

def test_atomic_checkpoint_write_and_read(tmp_path):
    target = tmp_path / "checkpoints" / "chk_001.json"
    payload = {"engagement_id": "eng-1", "test_key": "test_val"}

    final_path, content_hash = AtomicCheckpoint.write_atomic(target, payload)
    assert Path(final_path).exists()
    assert content_hash != ""

    read_data = AtomicCheckpoint.read_checkpoint(target, verify_integrity=True)
    assert read_data["test_key"] == "test_val"
    assert read_data["content_hash"] == content_hash
