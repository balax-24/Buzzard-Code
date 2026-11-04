import pytest
from agent.assessment_state import AssessmentContext, AssessmentState
from persistence.engagement_store import EngagementStore

def test_findings_persistence_unverified_to_verified(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-find", scope=["target-find"]))
    f_rec = state.record_finding(
        title="Admin Bypass",
        severity="HIGH",
        description="Auth weakness",
        evidence_ids=["EVI-1"],
    )

    store.checkpoint("eng-find", state)
    loaded_state, _, _, _, _, _ = store.load("eng-find")

    assert len(loaded_state.findings) == 1
    loaded_f = list(loaded_state.findings.values())[0] if isinstance(loaded_state.findings, dict) else loaded_state.findings[0]
    assert loaded_f["title"] == "Admin Bypass"
    assert loaded_f.get("verified") is True
