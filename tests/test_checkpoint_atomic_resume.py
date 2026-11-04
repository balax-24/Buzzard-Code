"""
Tests for Phase 12 Atomic Checkpoint & Resume System.
Verifies:
1. Complete state reconstruction (services, capabilities, sessions, attack graph, decisions, budget).
2. Atomic serialization and zero state loss.
"""

import pytest
import tempfile
from pathlib import Path

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
    AssessmentPhase,
    ObjectiveStatus,
)
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind, EdgeKind
from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.intelligence.decision import DecisionRecord, DecisionSource
from security_agent.persistence.models import BudgetSnapshot, InvestigationStatus
from security_agent.persistence.checkpoint_manager import CheckpointManager


def test_atomic_checkpoint_and_resume():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)

        # 1. Build initial state
        state = AssessmentState(context=AssessmentContext(target="target.corp.local", scope=["target.corp.local"]))
        state.current_phase = AssessmentPhase.EXPLOITATION
        state.record_service("target.corp.local", 8080, "http", evidence_id="EVI-001")
        state.capabilities["cap-admin"] = Capability(
            capability_id="cap-admin",
            capability_type=CapabilityType.ADMIN_ACCESS,
            target_scope="target.corp.local",
            source_evidence_ids=["EVI-AUTH-01"]
        )

        # Add session
        store = state.get_session_store()
        sess = store.create_session(target_origin="http://target.corp.local:8080", role="admin")
        sess.is_authenticated = True

        # Add decision record
        state.record_decision(DecisionRecord(
            iteration=1,
            source=DecisionSource.MODEL,
            selected_tool="http.request",
            target="http://target.corp.local:8080/admin",
            arguments={"url": "http://target.corp.local:8080/admin"}
        ))

        # Add attack graph
        graph = AttackGraph()
        graph.sync_from_state(state)
        assert len(graph.nodes) >= 2

        # Add budget
        budget = BudgetSnapshot(
            elapsed_seconds=120.5,
            max_seconds=3600.0,
            tool_calls_used=15,
            max_tool_calls=100,
            iterations_used=5,
            max_iterations=40
        )

        # 2. Create checkpoint
        chk = manager.create_checkpoint(
            investigation_id="INV-001",
            state=state,
            graph=graph,
            budget=budget,
            status=InvestigationStatus.RUNNING
        )
        assert chk.checkpoint_id.startswith("chk-")
        assert len(chk.integrity.content_hash) == 64

        # 3. Simulate process restart and restore
        r_state, r_graph, r_hyp, r_store, r_budget, r_chk = manager.restore_checkpoint(chk.checkpoint_id)

        # 4. Verify 100% Fidelity
        assert r_state.context.target == "target.corp.local"
        assert r_state.current_phase == AssessmentPhase.EXPLOITATION
        assert "target.corp.local:8080/tcp" in r_state.services
        assert "cap-admin" in r_state.capabilities
        assert r_state.capabilities["cap-admin"].capability_type == CapabilityType.ADMIN_ACCESS

        # Verify Session
        assert len(r_store.sessions) == 1
        r_sess = list(r_store.sessions.values())[0]
        assert r_sess.is_authenticated
        assert r_sess.role == "admin"

        # Verify Decision Record
        assert len(r_state.decision_records) == 1
        assert r_state.decision_records[0].source == DecisionSource.MODEL
        assert r_state.decision_records[0].selected_tool == "http.request"

        # Verify Graph
        assert len(r_graph.nodes) == len(graph.nodes)
        assert len(r_graph.edges) == len(graph.edges)

        # Verify Budget
        assert r_budget.tool_calls_used == 15
        assert r_budget.iterations_used == 5
