"""
Phase 7D — Canonical 3-Tier Recursive E2E Scenario Test Suite.

Validates the full model-independent recursive assessment lifecycle:
  SURFACE A -> FINDING A -> CAPABILITY A ->
  SURFACE B -> FINDING B -> CAPABILITY B ->
  SURFACE C -> FINDING C -> INDEPENDENT VERIFICATION -> OBJECTIVE_VERIFIED

ABSOLUTE REQUIREMENT:
  NO MANUAL B/C ACTION INJECTION.
  Surface B and C are discovered and investigated strictly through
  evidence -> canonical AssessmentState -> derived AttackGraph -> HypothesisEngine ->
  ActionSelectionEngine -> DeterministicController.
"""

import copy
import pytest
from typing import Dict, Any, Optional, List

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    ServiceState,
    HypothesisStatus,
    CapabilityType,
    VerificationStatus,
)
from intelligence.attack_graph import (
    AttackGraph,
    NodeKind,
    NodeStatus,
    EdgeKind,
)
from agent.completion_engine import (
    CompletionEngine,
    CompletionAction,
    AssessmentMode,
    BudgetSnapshot,
)
from agent.deterministic_controller import (
    DeterministicController,
    ControllerStepResult,
    highest_priority_candidate,
)


# ===========================================================================
# 1. CANONICAL DETERMINISTIC MOCK LAB
# ===========================================================================

class CanonicalRecursiveMockLab:
    """
    Isolated Deterministic 3-Tier Laboratory Environment:
      Surface A: Port 80 HTTP /login -> SQLi auth bypass -> grants AUTHENTICATED & reveals /admin/backup.php
      Surface B: /admin/backup.php (requires AUTH) -> LFI config disclosure -> grants FILE_READ & reveals /internal/exec
      Surface C: /internal/exec (requires FILE_READ) -> Command injection -> returns root proof marker
      Independent Verification: Validates root proof marker
    """
    def __init__(self, host: str = "10.10.10.50"):
        self.host = host
        self.base_url = f"http://{host}:80"
        self.actions_executed: List[str] = []

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        url = args.get("url", "")
        headers = args.get("headers", {})
        action_sig = f"{tool_name}:{url}"
        self.actions_executed.append(action_sig)

        # Initial Probe on base target
        if url in (self.base_url, f"http://{self.host}", self.host):
            return {
                "success": True,
                "status_code": 200,
                "output": "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nDiscovered endpoints: /login",
                "discovered_services": [{"host": self.host, "port": 80, "service": "http"}],
                "discovered_endpoints": [f"{self.base_url}/login"],
                "evidence_id": "EVI-DISC-001",
            }

        # Stage A: SQLi on Surface A (/login)
        if "/login" in url:
            return {
                "success": True,
                "status_code": 200,
                "output": "HTTP/1.1 200 OK\nSet-Cookie: session=admin_token_sec99\n\nWelcome, Administrator! Admin Dashboard.",
                "session_cookie": "session=admin_token_sec99",
                "unlocked_endpoint": f"{self.base_url}/admin/backup.php",
                "evidence_id": "EVI-SQLI-001",
                "finding_id": "FIND-001",
                "capability_id": "CAP-AUTH-001",
            }

        # Stage B: LFI on Surface B (/admin/backup.php)
        if "/admin/backup.php" in url:
            cookie = headers.get("Cookie", "") or headers.get("session", "")
            if "admin_token_sec99" in cookie or "admin" in cookie:
                return {
                    "success": True,
                    "status_code": 200,
                    "output": "HTTP/1.1 200 OK\n\n[CONFIG FILE READ SUCCESS]\nAPI_KEY=int_secret_k88\nINTERNAL_EXEC_ENDPOINT=/internal/exec",
                    "revealed_endpoint": f"{self.base_url}/internal/exec",
                    "secret": "int_secret_k88",
                    "evidence_id": "EVI-LFI-002",
                    "finding_id": "FIND-002",
                    "capability_id": "CAP-FILE-002",
                }
            return {
                "success": False,
                "status_code": 403,
                "output": "403 Forbidden - Authentication required",
            }

        # Stage C: RCE on Surface C (/internal/exec)
        if "/internal/exec" in url:
            return {
                "success": True,
                "status_code": 200,
                "output": "HTTP/1.1 200 OK\nuid=0(root) gid=0(root)\nPROOF-FLAG-ALPHA-ROOT-7B-SUCCESS",
                "proof_marker": "PROOF-FLAG-ALPHA-ROOT-7B-SUCCESS",
                "evidence_id": "EVI-RCE-003",
                "finding_id": "FIND-003",
                "capability_id": "CAP-RCE-003",
            }

        return {"success": False, "status_code": 404, "output": "404 Not Found"}


def _make_canonical_state(lab: CanonicalRecursiveMockLab) -> AssessmentState:
    ctx = AssessmentContext(
        target=lab.base_url,
        scope=[lab.base_url, f"http://{lab.host}", lab.host, f"{lab.host}:80"],
        objective="Root flag capture and vulnerability assessment",
    )
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.ASSESSMENT_START
    return state


# ===========================================================================
# 2. CANONICAL THREE-TIER RECURSIVE TEST
# ===========================================================================

class TestPhase7DCanonicalScenario:
    """
    Validates autonomous recursive expansion from Surface A -> B -> C without manual injection.
    """

    def test_canonical_three_tier_recursive_progression(self):
        lab = CanonicalRecursiveMockLab()
        state = _make_canonical_state(lab)
        controller = DeterministicController(state=state, tool_executor=lab.execute_tool)

        # -------------------------------------------------------------------
        # Step 0: Controller Initialization & Scope Validation
        # -------------------------------------------------------------------
        assert "ASSESSMENT_START" in controller.trace
        assert "SCOPE_VALIDATED" in controller.trace
        assert state.current_phase == AssessmentPhase.SCOPE_VALIDATED
        assert not state.has_capability(CapabilityType.AUTHENTICATED)
        assert not state.has_capability(CapabilityType.FILE_READ)
        assert not state.has_capability(CapabilityType.COMMAND_EXECUTION)

        # Ensure Surface B and C do NOT exist in initial state or graph
        assert f"{lab.base_url}/admin/backup.php" not in state.http_endpoints
        assert f"{lab.base_url}/internal/exec" not in state.http_endpoints
        assert f"HTTP:{lab.base_url}/admin/backup.php" not in controller.graph._label_index
        assert f"HTTP:{lab.base_url}/internal/exec" not in controller.graph._label_index

        # -------------------------------------------------------------------
        # Step 1: Initial Discovery
        # -------------------------------------------------------------------
        step1 = controller.step()
        assert not step1.completed
        assert step1.success
        assert step1.information_gain > 0.0, "Initial discovery must produce positive information gain"
        assert "DISCOVERY" in controller.trace
        assert "SURFACE_ENUMERATION" in controller.trace
        assert 80 in state.get_open_ports()
        assert f"{lab.base_url}/login" in state.http_endpoints
        assert f"HTTP:{lab.base_url}/login" in controller.graph._label_index

        # Surface B and C still do NOT exist
        assert f"{lab.base_url}/admin/backup.php" not in state.http_endpoints
        assert f"{lab.base_url}/internal/exec" not in state.http_endpoints

        # -------------------------------------------------------------------
        # Step 2: Surface A -> Finding A -> Capability A -> Surface B Unlocked
        # -------------------------------------------------------------------
        step2 = controller.step()
        assert not step2.completed
        assert step2.success
        assert step2.information_gain > 0.0, "A->B transition must produce positive information gain"
        assert "HYPOTHESIS" in controller.trace
        assert "PRECONDITION" in controller.trace
        assert "VALIDATION" in controller.trace
        assert "CAPABILITY" in controller.trace
        assert "GRAPH_EXPANSION" in controller.trace
        assert "RECURSIVE_INVESTIGATION" in controller.trace

        # Canonical State assertions for Step 2
        assert state.has_capability(CapabilityType.AUTHENTICATED)
        assert "CAP-AUTH-001" in state.capabilities
        cap_a = state.capabilities["CAP-AUTH-001"]
        assert cap_a.verified
        assert "EVI-SQLI-001" in cap_a.source_evidence_ids
        assert any(f.get("finding_id") == "FIND-001" or f.get("title", "").startswith("Authentication") for f in state.findings)

        # Surface B is now unlocked and present in state and graph
        assert f"{lab.base_url}/admin/backup.php" in state.http_endpoints
        node_b = controller.graph.get_node_by_label(f"HTTP:{lab.base_url}/admin/backup.php")
        assert node_b is not None, "Surface B must become reachable in graph after Capability A"

        # Surface C still does NOT exist
        assert f"{lab.base_url}/internal/exec" not in state.http_endpoints
        assert f"HTTP:{lab.base_url}/internal/exec" not in controller.graph._label_index

        # -------------------------------------------------------------------
        # Step 3: Surface B -> Finding B -> Capability B -> Surface C Unlocked
        # -------------------------------------------------------------------
        step3 = controller.step()
        assert not step3.completed
        assert step3.success
        assert step3.information_gain > 0.0, "B->C transition must produce positive information gain"
        assert "SECOND CAPABILITY" in controller.trace
        assert "THIRD SURFACE" in controller.trace

        # Canonical State assertions for Step 3
        assert state.has_capability(CapabilityType.FILE_READ)
        assert "CAP-FILE-002" in state.capabilities
        cap_b = state.capabilities["CAP-FILE-002"]
        assert cap_b.verified
        assert "EVI-LFI-002" in cap_b.source_evidence_ids
        assert any(f.get("finding_id") == "FIND-002" or "File Read" in f.get("title", "") for f in state.findings)

        # Surface C is now unlocked and present in state and graph
        assert f"{lab.base_url}/internal/exec" in state.http_endpoints
        node_c = controller.graph.get_node_by_label(f"HTTP:{lab.base_url}/internal/exec")
        assert node_c is not None, "Surface C must become reachable in graph after Capability B"

        # -------------------------------------------------------------------
        # Step 4: Surface C -> Finding C -> Capability C -> Proof Marker
        # -------------------------------------------------------------------
        step4 = controller.step()
        assert not step4.completed
        assert step4.success
        assert step4.information_gain > 0.0, "C execution must produce positive information gain"
        assert state.has_capability(CapabilityType.COMMAND_EXECUTION)
        assert "PROOF-FLAG-ALPHA-ROOT-7B-SUCCESS" in state.proof_markers
        assert state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

        # -------------------------------------------------------------------
        # Step 5: Independent Verification -> Objective Verified
        # -------------------------------------------------------------------
        step5 = controller.step()
        assert step5.completed
        assert step5.status == "OBJECTIVE_VERIFIED"
        assert "INDEPENDENT_VERIFICATION" in controller.trace
        assert "OBJECTIVE_VERIFIED" in controller.trace
        assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert state.verification_started
        assert state.verification_success
        assert state.objective_achieved

        # -------------------------------------------------------------------
        # ASSERT EVERY TRANSITION (Exact sequence verification)
        # -------------------------------------------------------------------
        required_transitions = [
            "ASSESSMENT_START",
            "SCOPE_VALIDATED",
            "DISCOVERY",
            "SURFACE_ENUMERATION",
            "HYPOTHESIS",
            "PRECONDITION",
            "VALIDATION",
            "CAPABILITY",
            "GRAPH_EXPANSION",
            "RECURSIVE_INVESTIGATION",
            "SECOND CAPABILITY",
            "THIRD SURFACE",
            "INDEPENDENT_VERIFICATION",
            "OBJECTIVE_VERIFIED",
        ]
        trace_indices = [controller.trace.index(t) for t in required_transitions]
        assert trace_indices == sorted(trace_indices), f"Trace transitions must appear in chronological order: {controller.trace}"

        # -------------------------------------------------------------------
        # ASSERT CANONICAL STATE
        # -------------------------------------------------------------------
        # Surfaces A, B, C exist
        assert f"{lab.base_url}/login" in state.http_endpoints
        assert f"{lab.base_url}/admin/backup.php" in state.http_endpoints
        assert f"{lab.base_url}/internal/exec" in state.http_endpoints

        # Findings A, B, C exist
        finding_ids = [f.get("finding_id") for f in state.findings]
        assert "FIND-001" in finding_ids
        assert "FIND-002" in finding_ids
        assert "FIND-003" in finding_ids

        # Capabilities A, B exist and are evidence-backed
        assert "CAP-AUTH-001" in state.capabilities
        assert state.capabilities["CAP-AUTH-001"].source_evidence_ids == ["EVI-SQLI-001"]
        assert "CAP-FILE-002" in state.capabilities
        assert state.capabilities["CAP-FILE-002"].source_evidence_ids == ["EVI-LFI-002"]

        # Verification evidence exists
        verif_evis = [eid for eid, ed in state.evidence.items() if "verify" in ed.get("source_tool", "").lower()]
        assert len(verif_evis) > 0

        # Graph node & edge integrity: No duplicate nodes or edges
        node_ids = list(controller.graph.nodes.keys())
        assert len(node_ids) == len(set(node_ids)), "Graph must have no duplicate nodes"

        edge_keys = [(e.from_node_id, e.to_node_id, e.kind) for e in controller.graph.edges]
        assert len(edge_keys) == len(set(edge_keys)), "Graph must have no duplicate edges"

        # Edge kind ENABLES connects Capability -> Endpoint
        enables_edges = [e for e in controller.graph.edges if e.kind == EdgeKind.ENABLES]
        assert len(enables_edges) >= 2, "AttackGraph must contain ENABLES edges for unlocked surfaces"

        # -------------------------------------------------------------------
        # ASSERT PROVENANCE CHAIN
        # -------------------------------------------------------------------
        # A -> Finding A
        assert "EVI-SQLI-001" in state.evidence
        # Finding A -> Capability A
        assert "EVI-SQLI-001" in state.capabilities["CAP-AUTH-001"].source_evidence_ids
        # Capability A -> B (unlocked endpoint in metadata)
        assert f"{lab.base_url}/admin/backup.php" in state.capabilities["CAP-AUTH-001"].metadata["unlocked_endpoints"]
        # B -> Finding B
        assert "EVI-LFI-002" in state.evidence
        # Finding B -> Capability B
        assert "EVI-LFI-002" in state.capabilities["CAP-FILE-002"].source_evidence_ids
        # Capability B -> C (revealed endpoint in metadata)
        assert f"{lab.base_url}/internal/exec" in state.capabilities["CAP-FILE-002"].metadata["unlocked_endpoints"]
        # C -> Finding C
        assert "EVI-RCE-003" in state.evidence
        # Finding C -> Verification
        assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED

        # -------------------------------------------------------------------
        # ASSERT NO REDISCOVERY / TERMINATION
        # -------------------------------------------------------------------
        step6 = controller.step()
        assert step6.completed
        assert step6.status in ("OBJECTIVE_VERIFIED", "CONCLUDE_SUCCESS")
        assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED


# ===========================================================================
# 3. CHECKPOINT & RESUME PERSISTENCE TEST
# ===========================================================================

class TestCheckpointResumePersistence:
    """
    Validates state checkpointing after Surface B and resuming through Surface C
    to verify objective without information loss.
    """

    def test_checkpoint_after_surface_b_and_resume_to_completion(self):
        lab = CanonicalRecursiveMockLab()
        state = _make_canonical_state(lab)
        controller = DeterministicController(state=state, tool_executor=lab.execute_tool)

        # Step 1: Discovery
        controller.step()
        # Step 2: Surface A -> Capability A
        controller.step()
        # Step 3: Surface B -> Capability B
        controller.step()

        # Check state after Surface B
        assert state.has_capability(CapabilityType.AUTHENTICATED)
        assert state.has_capability(CapabilityType.FILE_READ)
        assert f"{lab.base_url}/internal/exec" in state.http_endpoints

        # -------------------------------------------------------------------
        # CHECKPOINT
        # -------------------------------------------------------------------
        serialized = state.to_dict()
        assert "capabilities" in serialized
        assert "evidence" in serialized
        assert "http_endpoints" in serialized

        # -------------------------------------------------------------------
        # RESTORE
        # -------------------------------------------------------------------
        restored_state = AssessmentState.from_dict(serialized)
        assert restored_state.has_capability(CapabilityType.AUTHENTICATED)
        assert restored_state.has_capability(CapabilityType.FILE_READ)
        assert "EVI-SQLI-001" in restored_state.evidence
        assert "EVI-LFI-002" in restored_state.evidence
        assert f"{lab.base_url}/internal/exec" in restored_state.http_endpoints

        # Regenerate attack graph from restored state
        restored_graph = AttackGraph()
        restored_graph.sync_from_state(restored_state)
        assert restored_graph.get_node_by_label(f"HTTP:{lab.base_url}/internal/exec") is not None

        # -------------------------------------------------------------------
        # RESUME CONTROLLER
        # -------------------------------------------------------------------
        resumed_controller = DeterministicController(
            state=restored_state,
            graph=restored_graph,
            tool_executor=lab.execute_tool,
        )

        # Execute Surface C from resumed controller
        step_c = resumed_controller.step()
        assert not step_c.completed
        assert step_c.success
        assert restored_state.has_capability(CapabilityType.COMMAND_EXECUTION)
        assert "PROOF-FLAG-ALPHA-ROOT-7B-SUCCESS" in restored_state.proof_markers
        assert restored_state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

        # Execute Independent Verification
        step_verif = resumed_controller.step()
        assert step_verif.completed
        assert step_verif.status == "OBJECTIVE_VERIFIED"
        assert restored_state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
        assert restored_state.verification_success
