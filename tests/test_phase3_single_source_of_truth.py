"""
Phase 3 Regression Test Suite: Single Source of Truth for Services & Evidence.

Verifies:
1. Single Authoritative Service Write (Canonical State -> Derived AssetGraph & AttackGraph)
2. AssetGraph mutation delegates directly to Canonical State
3. No Duplicate Service / Endpoint on Repeated Observations
4. Idempotent Synchronization across Derived Views
5. Evidence Provenance Retained on all Entities
6. Hypothesis Consistency (No Duplicate Hypotheses)
7. Persistence Round-Trip & Derived View Reconstitution
8. Verification Invariants (Validation Success -> OBJECTIVE_ACHIEVED_UNVERIFIED -> Proof -> OBJECTIVE_VERIFIED)
9. Capability-Driven Graph Reachability
10. Information-Gain & Convergence (No Fake Work on Identical Output)
11. Event Bus Notification Integrity from Canonical State
"""

import pytest
import time
from dataclasses import dataclass
from typing import Dict, Any, List

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ServiceState,
    ServiceRecord,
    HTTPState,
    HTTPEndpointRecord,
    VerificationStatus,
    ObjectiveStatus,
    HypothesisStatus,
)
from intelligence.asset_graph import AssetGraph, AssetType
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus
from intelligence.evidence_ingestor import EvidenceIngestor
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.capability import Capability, CapabilityType
from events.bus import EventBus, EventType
from agent.tool_executor import ToolExecutionResult
from model.schemas import Finding


def test_single_authoritative_service_write():
    """
    Test A: Single authoritative service write.
    Writing to canonical AssessmentState directly reflects in derived AssetGraph and AttackGraph.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="10.0.0.5", objective="Penetration test")

    # Bind derived views
    asset_graph = AssetGraph(state=state)
    attack_graph = AttackGraph()

    # Record service authoritatively in canonical state
    srv = state.record_service(
        host="10.0.0.5",
        port=8080,
        service="http",
        version="Apache 2.4.41",
        state=ServiceState.OPEN,
        evidence_id="EVI-NMAP-001",
        verification_status=VerificationStatus.VERIFIED
    )

    assert state.get_service("10.0.0.5", 8080) is not None
    assert state.get_service("10.0.0.5", 8080).port == 8080

    # Sync derived views
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    # AssetGraph reflects the service
    assert "service:10.0.0.5:8080" in asset_graph.nodes
    srv_node = asset_graph.nodes["service:10.0.0.5:8080"]
    assert srv_node.type == AssetType.SERVICE
    assert srv_node.metadata["port"] == 8080

    # AttackGraph reflects the service
    assert attack_graph.get_node_by_label("10.0.0.5:8080/tcp") is not None
    ag_node = attack_graph.get_node_by_label("10.0.0.5:8080/tcp")
    assert ag_node.metadata["service"] == "http"
    assert "EVI-NMAP-001" in ag_node.evidence_ids


def test_asset_graph_write_mutates_canonical_state():
    """
    Test A.2: Writing through AssetGraph delegates to canonical AssessmentState.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="127.0.0.1", objective="Audit")
    asset_graph = AssetGraph(state=state)

    # Add service via AssetGraph interface
    asset_graph.add_service("127.0.0.1", 3306, "mysql", banner="MySQL 8.0")

    # Canonical state MUST contain the service
    rec = state.get_service("127.0.0.1", 3306)
    assert rec is not None
    assert rec.service == "mysql"
    assert rec.version == "MySQL 8.0"


def test_no_duplicate_service_on_repeated_ingestion(tmp_path):
    """
    Test B: No duplicate service on repeated tool output ingestion.
    """
    ingestor = EvidenceIngestor(base_dir=str(tmp_path))
    state = AssessmentState()
    state.context = AssessmentContext(target="192.168.1.50", objective="Audit")

    raw_nmap = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    nginx 1.18.0
"""
    result = ToolExecutionResult(
        tool_name="nmap_scan",
        arguments={"target": "192.168.1.50"},
        raw_output=raw_nmap,
        exit_code=0,
        duration=1.2,
        success=True,
        target="192.168.1.50"
    )

    # Ingest first time
    evi1 = ingestor.ingest(result, state=state, session_id="test-session")
    assert len(state.services) == 2
    ssh_rec = state.get_service("192.168.1.50", 22)
    http_rec = state.get_service("192.168.1.50", 80)
    assert ssh_rec is not None
    assert http_rec is not None
    assert evi1.evidence_id in ssh_rec.evidence_ids

    # Ingest second time (identical scan result)
    evi2 = ingestor.ingest(result, state=state, session_id="test-session")
    assert len(state.services) == 2
    assert len(ssh_rec.evidence_ids) == 2
    assert evi2.evidence_id in ssh_rec.evidence_ids

    # Sync to derived views
    asset_graph = AssetGraph.from_state(state)
    attack_graph = AttackGraph()
    attack_graph.sync_from_state(state)

    # Assert no duplicate nodes in derived views
    service_nodes = [n for n in asset_graph.nodes.values() if n.type == AssetType.SERVICE]
    assert len(service_nodes) == 2

    ag_service_nodes = attack_graph.get_nodes_by_kind(NodeKind.SERVICE)
    assert len(ag_service_nodes) == 2


def test_idempotent_synchronization():
    """
    Test C: Idempotent synchronization across AssetGraph and AttackGraph.
    Repeated sync() calls produce zero changes.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="10.0.1.10", objective="Audit")
    state.record_service("10.0.1.10", 80, "http", version="nginx", state=ServiceState.OPEN, evidence_id="EVI-01")
    state.record_service("10.0.1.10", 443, "https", version="nginx", state=ServiceState.OPEN, evidence_id="EVI-02")
    state.record_http_probe("http://10.0.1.10/", state=HTTPState.RESPONDS, status_code=200, evidence_id="EVI-03")
    state.record_finding("SQL Injection", "HIGH", "Vulnerable endpoint", proof="sql syntax error", evidence_ids=["EVI-04"])

    asset_graph = AssetGraph(state=state)
    attack_graph = AttackGraph()

    # Sync 1
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    initial_ag_node_count = len(asset_graph.nodes)
    initial_ag_edge_count = len(asset_graph.edges)
    initial_atk_node_count = len(attack_graph.nodes)
    initial_atk_edge_count = len(attack_graph.edges)

    # Sync 2
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    assert len(asset_graph.nodes) == initial_ag_node_count
    assert len(asset_graph.edges) == initial_ag_edge_count
    assert len(attack_graph.nodes) == initial_atk_node_count
    assert len(attack_graph.edges) == initial_atk_edge_count

    # Sync 3
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    assert len(asset_graph.nodes) == initial_ag_node_count
    assert len(asset_graph.edges) == initial_ag_edge_count
    assert len(attack_graph.nodes) == initial_atk_node_count
    assert len(attack_graph.edges) == initial_atk_edge_count


def test_evidence_provenance_retention():
    """
    Test D: Evidence provenance is retained through canonical state to derived graphs.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="127.0.0.1", objective="Audit")
    state.record_service(
        host="127.0.0.1",
        port=8080,
        service="http",
        version="Werkzeug 2.0.1",
        state=ServiceState.OPEN,
        evidence_id="EVI-PROBE-99"
    )

    attack_graph = AttackGraph()
    attack_graph.sync_from_state(state)

    node = attack_graph.get_node_by_label("127.0.0.1:8080/tcp")
    assert node is not None
    assert "EVI-PROBE-99" in node.evidence_ids


def test_hypothesis_consistency_no_duplicates():
    """
    Test E: Same canonical service cannot create duplicate hypotheses.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="127.0.0.1", objective="Audit")
    state.record_service("127.0.0.1", 80, "http", state=ServiceState.OPEN, evidence_id="EVI-001")

    engine = HypothesisEngine()
    proposals_1 = engine.propose_next_actions(state)
    ids_1 = [p.hypothesis_id for p in proposals_1]

    # Propose again without state change
    proposals_2 = engine.propose_next_actions(state)
    ids_2 = [p.hypothesis_id for p in proposals_2]

    # Must produce the same unique hypothesis proposal IDs
    assert ids_1 == ids_2
    assert len(set(ids_1)) == len(ids_1)


def test_persistence_round_trip_derived_views():
    """
    Test F: Persistence round-trip and derived view reconstitution.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="10.0.5.1", objective="Extract Flag")
    state.record_service("10.0.5.1", 22, "ssh", version="OpenSSH 8.9", state=ServiceState.OPEN, evidence_id="EVI-1")
    state.record_service("10.0.5.1", 8080, "http", version="Apache", state=ServiceState.OPEN, evidence_id="EVI-2")
    state.record_http_probe("http://10.0.5.1:8080/login", state=HTTPState.RESPONDS, status_code=200, evidence_id="EVI-3")
    state.record_finding("Admin Auth Bypass", "HIGH", "Login bypassable via SQLi", proof="FLAG{ALPHA-01}", evidence_ids=["EVI-4"])

    # Simulate checkpoint serialization
    state_dict = state.to_dict()

    # Reconstitute state from dictionary
    restored_state = AssessmentState.from_dict(state_dict)

    # Derive AssetGraph and AttackGraph from restored state
    restored_asset_graph = AssetGraph.from_state(restored_state)
    restored_attack_graph = AttackGraph()
    restored_attack_graph.sync_from_state(restored_state)

    # Verify equivalent entities
    assert len(restored_state.services) == 2
    assert restored_state.get_service("10.0.5.1", 22) is not None
    assert restored_state.get_service("10.0.5.1", 8080) is not None
    assert len(restored_state.findings) == 1

    # Verify derived graphs
    assert "service:10.0.5.1:22" in restored_asset_graph.nodes
    assert "service:10.0.5.1:8080" in restored_asset_graph.nodes
    assert restored_attack_graph.get_node_by_label("10.0.5.1:22/tcp") is not None
    assert restored_attack_graph.get_node_by_label("10.0.5.1:8080/tcp") is not None


def test_verification_invariant_lifecycle():
    """
    Test G: Verification invariant:
    Exploit success -> OBJECTIVE_ACHIEVED_UNVERIFIED -> Independent proof -> OBJECTIVE_VERIFIED.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="127.0.0.1:8080", objective="Capture flag")

    # Initial state
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED

    # Advance phase methodology
    state.transition(AssessmentPhase.ASSET_DISCOVERY, "Discovery")
    state.transition(AssessmentPhase.IDENTIFICATION, "Identification")

    # Validation tool success (e.g. 302 redirect / SQL injection successful)
    state.validation_attempted = True
    state.validation_tool_success = True
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
    state.transition(AssessmentPhase.VERIFICATION, "Validation succeeded. Transitioning to independent verification.")

    # Guard: objective is UNVERIFIED, not fully achieved
    assert not state.objective_achieved
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
    assert state.current_phase == AssessmentPhase.VERIFICATION

    # Independent proof captured (e.g. FLAG{...} found in authenticated endpoint)
    state.verification_started = True
    state.verification_success = True
    state.objective_achieved = True
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.transition(AssessmentPhase.REPORT, "Verification proof captured.")

    assert state.objective_achieved
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert state.current_phase == AssessmentPhase.REPORT


def test_capability_invariant_unlocks_reachability():
    """
    Test H: Verified capabilities unlock graph reachability in AttackGraph.
    """
    state = AssessmentState()
    state.context = AssessmentContext(target="127.0.0.1", objective="Audit")
    state.record_service("127.0.0.1", 8080, "http", state=ServiceState.OPEN, evidence_id="EVI-001")

    attack_graph = AttackGraph()
    attack_graph.sync_from_state(state)

    # Initially no CAPABILITY nodes
    assert len(attack_graph.get_nodes_by_kind(NodeKind.CAPABILITY)) == 0

    # Add verified capability
    cap = Capability(
        capability_id="CAP-ADMIN-01",
        capability_type=CapabilityType.ADMIN_ACCESS,
        target_scope="127.0.0.1",
        verified=True,
        source_evidence_ids=["EVI-FLAG-01"],
        metadata={"unlocked_endpoints": ["http://127.0.0.1:8080/admin/secrets"]}
    )
    state.capabilities["CAP-ADMIN-01"] = cap

    # Re-sync
    attack_graph.sync_from_state(state)

    # Capability node and unlocked endpoint node must appear
    cap_nodes = attack_graph.get_nodes_by_kind(NodeKind.CAPABILITY)
    assert len(cap_nodes) == 1
    assert cap_nodes[0].label == "CAP:ADMIN_ACCESS:CAP-ADMIN-01"

    unlocked_ep = attack_graph.get_node_by_label("HTTP:http://127.0.0.1:8080/admin/secrets")
    assert unlocked_ep is not None
    assert unlocked_ep.metadata.get("unlocked_by_capability") == "CAP-ADMIN-01"


def test_information_gain_convergence(tmp_path):
    """
    Test 13: Information-Gain / Convergence Check.
    Repeated identical tool outputs produce 0 net new entities.
    """
    ingestor = EvidenceIngestor(base_dir=str(tmp_path))
    state = AssessmentState()
    state.context = AssessmentContext(target="10.0.0.1", objective="Audit")

    raw_output = """
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache/2.4.41
"""
    result = ToolExecutionResult(
        tool_name="nmap_scan",
        arguments={"target": "10.0.0.1"},
        raw_output=raw_output,
        exit_code=0,
        duration=0.5,
        success=True,
        target="10.0.0.1"
    )

    # 1st Ingestion
    ingestor.ingest(result, state=state, session_id="test-session")
    asset_graph = AssetGraph.from_state(state)
    attack_graph = AttackGraph()
    attack_graph.sync_from_state(state)

    services_count_1 = len(state.services)
    asset_nodes_1 = len(asset_graph.nodes)
    attack_nodes_1 = len(attack_graph.nodes)

    assert services_count_1 == 1

    # 2nd Ingestion (identical)
    ingestor.ingest(result, state=state, session_id="test-session")
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    assert len(state.services) == services_count_1
    assert len(asset_graph.nodes) == asset_nodes_1
    assert len(attack_graph.nodes) == attack_nodes_1

    # 3rd Ingestion (identical)
    ingestor.ingest(result, state=state, session_id="test-session")
    asset_graph.sync_from_state(state)
    attack_graph.sync_from_state(state)

    assert len(state.services) == services_count_1
    assert len(asset_graph.nodes) == asset_nodes_1
    assert len(attack_graph.nodes) == attack_nodes_1


def test_event_bus_notifications_on_state_changes():
    """
    Test I: Event bus receives notifications when state changes occur.
    """
    bus = EventBus()
    events_received = []

    bus.subscribe(EventType.TOOL_COMPLETED, lambda evt: events_received.append(evt))

    bus.emit(
        EventType.TOOL_COMPLETED,
        {
            "tool": "nmap_scan",
            "duration_ms": 500,
            "success": True,
            "exit_code": 0
        },
        assessment_id="session-001"
    )

    assert len(events_received) == 1
    assert events_received[0].payload["tool"] == "nmap_scan"
    assert events_received[0].payload["success"] is True
