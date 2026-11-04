import pytest
import json
from agent.assessment_state import AssessmentContext, AssessmentState
from intelligence.attack_graph import AttackGraph, NodeKind
from intelligence.branches import BranchManager
from intelligence.failure_memory import FailureAwareMemory
from persistence.engagement_store import ResumeContextBuilder
from persistence.state_serializer import StateSerializer

def test_context_compression_ratio():
    state = AssessmentState(context=AssessmentContext(target="192.168.1.10", scope=["192.168.1.10"]))
    graph = AttackGraph()
    branch_mgr = BranchManager()
    fail_mem = FailureAwareMemory()

    full_payload = StateSerializer.serialize_state(state, graph, None, fail_mem, branch_mgr)
    compact_ctx = ResumeContextBuilder.build_resume_context(state, graph, branch_mgr, fail_mem, full_payload.get("budget", {}))

    full_len = len(json.dumps(full_payload))
    compact_len = len(json.dumps(compact_ctx))

    ratio = compact_len / full_len
    assert ratio < 0.6  # Compressed representation is significantly more compact
