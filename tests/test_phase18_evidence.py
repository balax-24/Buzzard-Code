import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.persistence.engagement_store import EngagementStore

def test_evidence_immutability_and_relationships(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-evi", scope=["target-evi"]))
    state.add_evidence(
        raw_data="WAF: ENABLED",
        source_tool="http_request",
        target="192.168.1.10",
    )

    store.checkpoint("eng-evi", state)
    loaded_state, _, _, _, _, _ = store.load("eng-evi")

    assert len(loaded_state.evidence) == 1
    evi = list(loaded_state.evidence.values())[0]
    assert evi["raw_data"] == "WAF: ENABLED"
