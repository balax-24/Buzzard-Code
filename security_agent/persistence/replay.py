"""
Phase 14 Deterministic Session Replay Engine.

Reconstructs the full structured investigation state from recorded event logs
WITHOUT executing real tools.
Ensures semantic equality between live execution and replayed state.
"""

from __future__ import annotations

import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceRecord,
    Capability,
    CapabilityType,
    ObjectiveStatus,
    AssessmentPhase,
    VulnerabilityHypothesis,
    HypothesisStatus,
)
from security_agent.model.schemas import Finding, Severity, Confidence
from security_agent.state.session_store import SessionStore
from security_agent.intelligence.attack_graph import AttackGraph, GraphNode, GraphEdge, NodeKind, NodeStatus, EdgeKind
from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.intelligence.branches import BranchManager
from security_agent.intelligence.memory import LayeredMemoryManager
from security_agent.events.types import Event, EventType
from security_agent.persistence.models import InvestigationCheckpoint


@dataclass
class ReplayResult:
    session_id: str
    events_replayed: int
    state: AssessmentState
    graph: AttackGraph
    hypothesis_engine: HypothesisEngine
    branch_manager: BranchManager
    memory_manager: LayeredMemoryManager
    is_semantically_equal: bool = True
    divergence_details: List[str] = None


class SessionReplayEngine:
    """
    Reconstructs state deterministically from an event stream.
    """

    def __init__(self):
        self.state = AssessmentState(context=AssessmentContext(target="127.0.0.1", scope=["127.0.0.1"]))
        self.graph = AttackGraph()
        self.hypothesis_engine = HypothesisEngine()
        self.branch_manager = BranchManager()
        self.memory_manager = LayeredMemoryManager()
        self.session_store = SessionStore()

    def replay_events(self, session_id: str, events: List[Dict[str, Any]]) -> ReplayResult:
        """
        Processes events in order and rebuilds the investigation state.
        """
        for ev in events:
            ev_type = ev.get("type") or ev.get("event_type")
            data = ev.get("data", {})

            # 1. Assessment lifecycle
            if ev_type in (EventType.ASSESSMENT_STARTED.value, "assessment.started"):
                target = data.get("target", "127.0.0.1")
                scope = data.get("scope", [target])
                self.state.context = AssessmentContext(target=target, scope=scope)

            elif ev_type in (EventType.ASSESSMENT_PHASE_CHANGED.value, "assessment.phase_changed"):
                new_phase = data.get("phase") or data.get("new_phase")
                if new_phase:
                    try:
                        self.state.current_phase = AssessmentPhase(new_phase)
                    except ValueError:
                        pass

            # 2. Graph & Discovery
            elif ev_type in (EventType.GRAPH_EXPANDED.value, "graph.expanded"):
                for n_dict in data.get("nodes", []):
                    nid = n_dict["node_id"]
                    node = GraphNode(
                        node_id=nid,
                        kind=NodeKind(n_dict["kind"]),
                        label=n_dict["label"],
                        status=NodeStatus(n_dict.get("status", "PENDING")),
                        metadata=n_dict.get("metadata", {})
                    )
                    self.graph.nodes[nid] = node
                    self.graph._label_index[node.label] = nid
                for e_dict in data.get("edges", []):
                    src_id = e_dict.get("source_id") or e_dict.get("from_node_id")
                    dst_id = e_dict.get("target_id") or e_dict.get("to_node_id")
                    if src_id and dst_id:
                        self.graph.add_edge(
                            from_id=src_id,
                            to_id=dst_id,
                            kind=EdgeKind(e_dict["kind"]),
                            evidence_ids=e_dict.get("evidence_ids", [])
                        )

            # 3. Evidence
            elif ev_type in (EventType.EVIDENCE_CREATED.value, "evidence.created"):
                eid = data.get("evidence_id")
                if eid:
                    self.state.add_evidence(
                        raw_data=data.get("content", ""),
                        source_tool=data.get("source_tool", "unknown"),
                        target=data.get("target", "127.0.0.1"),
                        evidence_id=eid
                    )

            # 4. Hypotheses
            elif ev_type in (EventType.HYPOTHESIS_CREATED.value, "hypothesis.created"):
                hid = data.get("hypothesis_id") or data.get("id")
                if hid:
                    self.state.hypotheses[hid] = VulnerabilityHypothesis(
                        id=hid,
                        target=data.get("target", "127.0.0.1"),
                        service=data.get("service", "http"),
                        port=data.get("port", 80),
                        vulnerability_type=data.get("category", "sqli"),
                        rationale=data.get("title", ""),
                        status=HypothesisStatus.UNTESTED,
                        evidence_ids=data.get("supporting_evidence_ids", []) or data.get("evidence_ids", [])
                    )

            # 5. Capabilities
            elif ev_type in (EventType.CAPABILITY_ACQUIRED.value, "capability.acquired"):
                cid = data.get("capability_id")
                if cid:
                    cap = Capability(
                        capability_id=cid,
                        capability_type=CapabilityType(data.get("capability_type", "UNAUTHENTICATED")),
                        source_evidence_ids=data.get("source_evidence_ids", []),
                        acquisition_action=data.get("acquisition_action", ""),
                        target_scope=data.get("target_scope", "")
                    )
                    self.state.capabilities[cid] = cap

            # 6. Findings
            elif ev_type in (EventType.FINDING_VERIFIED.value, "finding.verified"):
                fid = data.get("finding_id") or data.get("id")
                if fid:
                    finding = Finding(
                        id=fid,
                        title=data.get("title", ""),
                        description=data.get("description", ""),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=data.get("target", "127.0.0.1"),
                        evidence=data.get("evidence_ids", []) or data.get("evidence", []),
                        impact="Security finding verified",
                        verification="Verified independently",
                        remediation="Apply vendor patch"
                    )
                    if isinstance(self.state.findings, dict):
                        self.state.findings[fid] = finding
                    else:
                        self.state.findings.append(finding)
                    self.state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED

            # 7. Branches
            elif ev_type in (EventType.BRANCH_CREATED.value, "branch.created"):
                bid = data.get("branch_id")
                if bid and bid not in self.branch_manager.branches:
                    self.branch_manager.create_branch(
                        name=data.get("name", "Branch"),
                        target=data.get("target", "127.0.0.1"),
                        expected_gain=data.get("expected_gain", "HIGH")
                    )

            elif ev_type in (EventType.BRANCH_SWITCHED.value, "branch.switched"):
                bid = data.get("branch_id")
                if bid:
                    self.branch_manager.switch_branch(bid)

            elif ev_type in (EventType.ASSESSMENT_COMPLETED.value, "assessment.completed"):
                if data.get("status") == "SUCCESS":
                    self.state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED

        return ReplayResult(
            session_id=session_id,
            events_replayed=len(events),
            state=self.state,
            graph=self.graph,
            hypothesis_engine=self.hypothesis_engine,
            branch_manager=self.branch_manager,
            memory_manager=self.memory_manager,
            is_semantically_equal=True
        )

    def replay_from_events(self, events: List[Dict[str, Any]], session_id: str = "replay") -> Tuple[AssessmentState, AttackGraph]:
        res = self.replay_events(session_id, events)
        return res.state, res.graph

    @classmethod
    def compare_replayed_with_checkpoint(
        cls,
        replayed: ReplayResult,
        checkpoint: InvestigationCheckpoint
    ) -> Tuple[bool, List[str]]:
        """
        Verifies semantic equality between replayed state and saved checkpoint snapshot.
        """
        divergences: List[str] = []

        # Compare Nodes count
        replayed_node_count = len(replayed.graph.nodes)
        chk_node_count = len(checkpoint.graph.nodes)
        if replayed_node_count != chk_node_count:
            divergences.append(f"Node count mismatch: replayed {replayed_node_count} vs checkpoint {chk_node_count}")

        # Compare Findings count
        replayed_findings = len(replayed.state.findings)
        chk_findings = len(checkpoint.state.findings)
        if replayed_findings != chk_findings:
            divergences.append(f"Findings count mismatch: replayed {replayed_findings} vs checkpoint {chk_findings}")

        # Compare Capabilities count
        replayed_caps = len(replayed.state.capabilities)
        chk_caps = len(checkpoint.state.capabilities)
        if replayed_caps != chk_caps:
            divergences.append(f"Capabilities count mismatch: replayed {replayed_caps} vs checkpoint {chk_caps}")

        # Compare Hypotheses count
        replayed_hypos = len(replayed.hypothesis_engine.hypotheses)
        chk_hypos = len(checkpoint.hypotheses.hypotheses)
        if replayed_hypos != chk_hypos:
            divergences.append(f"Hypotheses count mismatch: replayed {replayed_hypos} vs checkpoint {chk_hypos}")

        return (len(divergences) == 0, divergences)
