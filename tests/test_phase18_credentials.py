import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_credential_vault_persistence(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="host-c", scope=["host-c"]))
    state.credentials = {"jwt": "ey...", "ssh_key": "-----BEGIN..."}

    store.checkpoint("eng-cred", state)
    loaded, _, _, _, _, _ = store.load("eng-cred")

    assert loaded.credentials.get("jwt") == "ey..."
    assert loaded.credentials.get("ssh_key") == "-----BEGIN..."
