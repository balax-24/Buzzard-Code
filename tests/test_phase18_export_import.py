import pytest
from pathlib import Path
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_export_import_portable_archive(tmp_path):
    store_a = EngagementStore(base_dir=tmp_path / "ws_a")
    state = AssessmentState(context=AssessmentContext(target="192.168.1.10", scope=["192.168.1.10"]))
    state.add_capability("ADMIN", "Export test")
    state.credentials = {"admin_jwt": "ey..."}

    store_a.checkpoint("eng-exportable", state)

    zip_path = tmp_path / "exported_eng.zip"
    store_a.export_engagement("eng-exportable", zip_path)
    assert zip_path.exists()

    # Import on Machine/Workspace B
    store_b = EngagementStore(base_dir=tmp_path / "ws_b")
    imported_id = store_b.import_engagement(zip_path, override_engagement_id="eng-imported")

    loaded_b, _, _, _, _, _ = store_b.load("eng-imported")
    assert loaded_b.context.target == "192.168.1.10"
    assert loaded_b.credentials.get("admin_jwt") == "ey..."
