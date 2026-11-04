import pytest
import json
from persistence.integrity import StateIntegrity, StateIntegrityError
from persistence.checkpoint import AtomicCheckpoint

def test_tamper_detection(tmp_path):
    target = tmp_path / "tamper_test.json"
    payload = {"engagement_id": "eng-1", "objective": "OBJ_ADMIN"}
    final_path, content_hash = AtomicCheckpoint.write_atomic(target, payload)

    # Tamper with file
    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["objective"] = "MALICIOUSLY_MUTATED_OBJECTIVE"
    with open(target, "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(StateIntegrityError):
        AtomicCheckpoint.read_checkpoint(target, verify_integrity=True)
