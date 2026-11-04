import pytest
from pathlib import Path
from persistence.checkpoint import AtomicCheckpoint

def test_crash_during_temp_file_leaves_existing_valid(tmp_path):
    target = tmp_path / "chk.json"
    AtomicCheckpoint.write_atomic(target, {"version": 1, "data": "initial"})

    # Simulate abandoned temp file
    abandoned_tmp = tmp_path / "chk.json.tmp.12345.999"
    with open(abandoned_tmp, "w") as f:
        f.write("corrupted incomplete json {")

    # Read target still reads valid initial checkpoint
    data = AtomicCheckpoint.read_checkpoint(target, verify_integrity=True)
    assert data["data"] == "initial"
