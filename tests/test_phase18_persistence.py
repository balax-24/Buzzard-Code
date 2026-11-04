import pytest
import shutil
from pathlib import Path
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_engagement_store_save_load(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="192.168.1.10", scope=["192.168.1.10"]))
    state.add_capability("AUTHENTICATED", "Test flow")

    path, chk_hash = store.checkpoint("eng-test-1", state)
    assert Path(path).exists()
    assert chk_hash != ""

    loaded_state, _, _, _, _, _ = store.load("eng-test-1")
    assert "AUTHENTICATED" in loaded_state.capabilities
    assert loaded_state.context.target == "192.168.1.10"
