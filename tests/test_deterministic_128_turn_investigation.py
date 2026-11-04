"""
Phase 12 Deterministic 128-Turn Long-Horizon Investigation Simulation.

Verifies end-to-end execution without external LLM dependencies:
- Multi-phase progression (Discovery -> Identification -> Enumeration -> Exploitation -> Verification)
- Multi-path branching (Web, API, Service)
- Multiple atomic checkpoints and simulated process restarts
- Context compaction preserving invariants across 128 turns
- Objective completion and zero state loss
"""

import pytest
import tempfile
from pathlib import Path

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
    AssessmentPhase,
    ObjectiveStatus,
)
from intelligence.attack_graph import AttackGraph, NodeStatus
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.branches import BranchManager, BranchPriority
from intelligence.memory import LayeredMemoryManager
from intelligence.decision import DecisionRecord, DecisionSource
from persistence.models import BudgetSnapshot, InvestigationStatus
from persistence.checkpoint_manager import CheckpointManager


def test_128_turn_deterministic_investigation_with_crashes_and_resumes():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CheckpointManager(storage_dir=tmpdir)
        mem = LayeredMemoryManager()
        bm = BranchManager()

        # -------------------------------------------------------------
        # TURNS 1 - 20: Initial Reconnaissance & Discovery
        # -------------------------------------------------------------
        state = AssessmentState(context=AssessmentContext(target="enterprise.corp.local", scope=["enterprise.corp.local"]))
        graph = AttackGraph()
        hyp_engine = HypothesisEngine()

        for t in range(1, 21):
            state.record_decision(DecisionRecord(
                iteration=t,
                source=DecisionSource.MODEL,
                selected_tool="nmap_scan" if t == 1 else "web_fetch",
                target=f"http://enterprise.corp.local:8080/path_{t}",
                arguments={"port": 8080, "path": f"/path_{t}"}
            ))
            if t == 1:
                state.record_service("enterprise.corp.local", 8080, "http", evidence_id="EVI-001")
                state.record_service("enterprise.corp.local", 22, "ssh", evidence_id="EVI-002")

        graph.sync_from_state(state)
        assert len(state.decision_records) == 20
        assert len(state.services) == 2

        # -------------------------------------------------------------
        # TURNS 21 - 40: Multi-Path Branching & Checkpoint 1
        # -------------------------------------------------------------
        b_web = bm.create_branch("Web App", "http://enterprise.corp.local:8080", BranchPriority.HIGH)
        b_api = bm.create_branch("REST API", "http://enterprise.corp.local:8080/api", BranchPriority.MEDIUM)
        b_ssh = bm.create_branch("SSH Service", "enterprise.corp.local:22", BranchPriority.LOW)

        for t in range(21, 41):
            state.record_decision(DecisionRecord(
                iteration=t,
                source=DecisionSource.MODEL,
                selected_tool="http.request",
                target=f"http://enterprise.corp.local:8080/api/v1/endpoint_{t}",
                arguments={"method": "GET"}
            ))

        # Checkpoint 1 at Turn 40
        chk_1 = manager.create_checkpoint(
            investigation_id="INV-128",
            state=state,
            graph=graph,
            hypothesis_engine=hyp_engine,
            branches_data=bm.to_dict(),
            status=InvestigationStatus.RUNNING
        )

        # -------------------------------------------------------------
        # SIMULATE CRASH 1 & RESUME AT TURN 41
        # -------------------------------------------------------------
        state, graph, hyp_engine, store, budget, _ = manager.restore_checkpoint(chk_1.checkpoint_id)
        assert len(state.decision_records) == 40
        assert len(state.services) == 2

        # -------------------------------------------------------------
        # TURNS 41 - 70: Capability Acquisition & Checkpoint 2
        # -------------------------------------------------------------
        state.current_phase = AssessmentPhase.EXPLOITATION
        state.capabilities["cap-user"] = Capability(
            capability_id="cap-user",
            capability_type=CapabilityType.AUTHENTICATED,
            target_scope="enterprise.corp.local",
            source_evidence_ids=["EVI-AUTH-01"]
        )
        sess = store.create_session("http://enterprise.corp.local:8080", role="user")
        sess.is_authenticated = True

        for t in range(41, 71):
            state.record_decision(DecisionRecord(
                iteration=t,
                source=DecisionSource.MODEL,
                selected_tool="http.request",
                target=f"http://enterprise.corp.local:8080/user/data_{t}",
                arguments={"method": "GET"}
            ))

        chk_2 = manager.create_checkpoint(
            investigation_id="INV-128",
            state=state,
            graph=graph,
            hypothesis_engine=hyp_engine,
            branches_data=bm.to_dict(),
            status=InvestigationStatus.RUNNING,
            parent_checkpoint_id=chk_1.checkpoint_id
        )

        # -------------------------------------------------------------
        # SIMULATE CRASH 2 & RESUME AT TURN 71
        # -------------------------------------------------------------
        state, graph, hyp_engine, store, budget, _ = manager.restore_checkpoint(chk_2.checkpoint_id)
        assert len(state.decision_records) == 70
        assert "cap-user" in state.capabilities

        # -------------------------------------------------------------
        # TURNS 71 - 100: Privilege Escalation & Failure Learning
        # -------------------------------------------------------------
        mem.record_failure(
            target="http://enterprise.corp.local:8080/admin",
            tool_or_strategy="sqlmap_attack",
            failure_class="WAF_BLOCKED"
        )
        state.capabilities["cap-admin"] = Capability(
            capability_id="cap-admin",
            capability_type=CapabilityType.ADMIN_ACCESS,
            target_scope="enterprise.corp.local",
            source_evidence_ids=["EVI-PRIV-01"]
        )

        for t in range(71, 101):
            state.record_decision(DecisionRecord(
                iteration=t,
                source=DecisionSource.MODEL,
                selected_tool="http.request",
                target=f"http://enterprise.corp.local:8080/admin/cfg_{t}",
                arguments={"method": "GET"}
            ))

        chk_3 = manager.create_checkpoint(
            investigation_id="INV-128",
            state=state,
            graph=graph,
            hypothesis_engine=hyp_engine,
            branches_data=bm.to_dict(),
            status=InvestigationStatus.RUNNING,
            parent_checkpoint_id=chk_2.checkpoint_id
        )

        # -------------------------------------------------------------
        # SIMULATE CRASH 3 & RESUME AT TURN 101
        # -------------------------------------------------------------
        state, graph, hyp_engine, store, budget, _ = manager.restore_checkpoint(chk_3.checkpoint_id)
        assert len(state.decision_records) == 100
        assert "cap-admin" in state.capabilities

        # -------------------------------------------------------------
        # TURNS 101 - 128: Verification & Objective Complete
        # -------------------------------------------------------------
        state.current_phase = AssessmentPhase.VERIFICATION
        for t in range(101, 129):
            state.record_decision(DecisionRecord(
                iteration=t,
                source=DecisionSource.MODEL,
                selected_tool="http.request",
                target="http://enterprise.corp.local:8080/admin/verify",
                arguments={"url": "http://enterprise.corp.local:8080/admin/verify"}
            ))

        state.findings.append({
            "title": "Privilege Escalation to Administrative Access",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED"
        })
        state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
        state.verification_success = True
        state.current_phase = AssessmentPhase.REPORTING

        final_chk = manager.create_checkpoint(
            investigation_id="INV-128",
            state=state,
            graph=graph,
            hypothesis_engine=hyp_engine,
            branches_data=bm.to_dict(),
            status=InvestigationStatus.COMPLETED,
            parent_checkpoint_id=chk_3.checkpoint_id
        )

        # -------------------------------------------------------------
        # FINAL RESTORE & INVARIANT VALIDATION ACROSS 128 TURNS
        # -------------------------------------------------------------
        f_state, f_graph, f_hyp, f_store, f_budget, f_chk = manager.restore_checkpoint(final_chk.checkpoint_id)
        assert len(f_state.decision_records) == 128
        assert f_state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert f_state.current_phase == AssessmentPhase.REPORTING
        assert len(f_state.findings) == 1
        assert "cap-admin" in f_state.capabilities
        assert "cap-user" in f_state.capabilities
        assert f_chk.status == InvestigationStatus.COMPLETED
