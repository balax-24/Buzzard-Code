"""
Phase 14 Tests: State Invariants & Checkpoint Verification.
Verifies all 7 core integrity rules and ensures loud failure on invariant violations.
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    Capability,
    CapabilityType,
    VulnerabilityHypothesis,
    HypothesisStatus,
)
from security_agent.model.schemas import Finding, Severity, Confidence
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind, EdgeKind, NodeStatus
from security_agent.intelligence.branches import BranchManager, BranchPriority
from security_agent.intelligence.invariants import (
    StateInvariantValidator,
    InvariantViolationError,
)
from security_agent.persistence.checkpoint_manager import CheckpointManager


def test_valid_state_passes_all_invariants():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=("127.0.0.1",)))
    state.current_phase = AssessmentPhase.DISCOVERY
    eid = state.add_evidence("Port 80 open", "nmap", "127.0.0.1")

    graph = AttackGraph()
    host_node = graph.add_node(NodeKind.HOST, "127.0.0.1", metadata={"host": "127.0.0.1"})
    svc_node = graph.add_node(NodeKind.SERVICE, "HTTP 80", parent_id=host_node.node_id, edge_kind=EdgeKind.DISCOVERED_ON, evidence_ids=[eid])

    state.capabilities["cap-admin"] = Capability(
        capability_id="cap-admin",
        capability_type=CapabilityType.ADMIN_ACCESS,
        source_evidence_ids=[eid],
        target_scope="127.0.0.1"
    )

    state.findings.append(Finding(
        id="FIND-01",
        title="Admin interface exposed",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="http://127.0.0.1:80",
        description="Publicly exposed admin",
        evidence=[eid],
        impact="Admin takeover",
        verification="Verified via curl",
        remediation="Restrict access"
    ))

    bm = BranchManager()
    bm.create_branch("Web App", "http://127.0.0.1:80", BranchPriority.HIGH)

    result = StateInvariantValidator.validate_state(
        state=state,
        graph=graph,
        branch_manager=bm,
        raise_on_violation=True
    )
    assert result.is_valid is True
    assert len(result.violations) == 0
    assert result.checked_rules_count >= 5


def test_finding_with_missing_evidence_fails():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.findings.append(Finding(
        id="FIND-BROKEN",
        title="Unverified finding",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="127.0.0.1",
        description="Missing evidence",
        evidence=["non_existent_evidence_123"],
        impact="High",
        verification="Steps",
        remediation="Patch"
    ))

    with pytest.raises(InvariantViolationError) as exc_info:
        StateInvariantValidator.validate_state(state=state, raise_on_violation=True)
    assert "Finding 'FIND-BROKEN' references missing evidence" in str(exc_info.value)


def test_verified_finding_without_evidence_fails():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.findings.append(Finding(
        id="FIND-NO-EVI",
        title="Finding with empty evidence",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        affected_asset="127.0.0.1",
        description="No evidence attached",
        evidence=[],
        impact="High",
        verification="Steps",
        remediation="Patch"
    ))

    with pytest.raises(InvariantViolationError) as exc_info:
        StateInvariantValidator.validate_state(state=state, raise_on_violation=True)
    assert "Verified Finding 'FIND-NO-EVI' has no verification evidence" in str(exc_info.value)


def test_capability_with_missing_evidence_fails():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    state.add_evidence("Real evidence", "tool", "127.0.0.1", evidence_id="real-evi-01")
    state.capabilities["cap-broken"] = Capability(
        capability_id="cap-broken",
        capability_type=CapabilityType.ADMIN_ACCESS,
        source_evidence_ids=["missing-evi-999"],
        target_scope="127.0.0.1"
    )

    with pytest.raises(InvariantViolationError) as exc_info:
        StateInvariantValidator.validate_state(state=state, raise_on_violation=True)
    assert "Capability 'cap-broken' cites missing source evidence 'missing-evi-999'" in str(exc_info.value)


def test_graph_edge_with_missing_node_fails():
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    graph = AttackGraph()
    n1 = graph.add_node(NodeKind.HOST, "127.0.0.1")
    # Manually add an edge pointing to a non-existent node
    from security_agent.intelligence.attack_graph import GraphEdge
    graph.edges.append(GraphEdge(
        edge_id="EDGE-GHOST",
        from_node_id=n1.node_id,
        to_node_id="ghost-node-id",
        kind=EdgeKind.DISCOVERED_ON,
        evidence_ids=[]
    ))

    with pytest.raises(InvariantViolationError) as exc_info:
        StateInvariantValidator.validate_state(state=state, graph=graph, raise_on_violation=True)
    assert "Graph Edge 'EDGE-GHOST' target node 'ghost-node-id' does not exist" in str(exc_info.value)


def test_checkpoint_checksum_integrity_verification(tmp_path):
    cm = CheckpointManager(storage_dir=str(tmp_path))
    state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
    graph = AttackGraph()
    graph.add_node(NodeKind.HOST, "127.0.0.1")

    chk = cm.create_checkpoint(
        investigation_id="inv-inv-test",
        state=state,
        graph=graph,
        hypothesis_engine=None
    )

    # Valid checkpoint should pass invariant check
    res = StateInvariantValidator.validate_checkpoint(chk, raise_on_violation=True)
    assert res.is_valid is True

    # Tampering with checkpoint content hash must fail loudly
    chk.integrity.content_hash = "corrupted_hash_value"
    with pytest.raises(InvariantViolationError) as exc_info:
        StateInvariantValidator.validate_checkpoint(chk, raise_on_violation=True)
    assert "Checkpoint state hash mismatch" in str(exc_info.value)
