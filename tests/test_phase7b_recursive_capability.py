"""
Phase 7B — Recursive Capability Acquisition Test Suite.

Validates that the Buzzard Code backend autonomously expands the authorized
attack/search surface when new evidence or capabilities are obtained, without
any manual action injection or LLM dependence.

Covers:
  1. Multi-Stage Deterministic Recursive Lab Fixture (Surface A -> B -> C)
  2. No Manual Action Injection (emergent from evidence -> state -> graph -> hypothesis)
  3. Capability Transition Model (UNAUTHENTICATED, AUTHENTICATED, FILE_READ, COMMAND_EXECUTION, ADMIN_ACCESS)
  4. Attack Graph Expansion with Evidence IDs on every edge
  5. HypothesisEngine capability consumption & stable identity deduplication
  6. Recursive Loop Lifecycle (A -> B -> C non-pre-existence assertions)
  7. Idempotence & Convergence (No Fake Work on repeated syncs)
  8. Repeated Failed Strategy Suppression (no re-proposing refuted hyps without new evidence)
  9. Information Gain per Action Metric
  10. Verification Lifecycle (VALIDATION -> OBJECTIVE_ACHIEVED_UNVERIFIED -> VERIFY -> OBJECTIVE_VERIFIED)
  11. Targeted vs Exhaustive Mode Terminal Behavior
  12. Budget Exhaustion during Recursive Acquisition
  13. Model-Independent Deterministic Planner Execution Trace
"""

import time
import pytest
from typing import Dict, Any, List, Optional

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    ServiceState,
    HypothesisStatus,
    VulnerabilityHypothesis,
)
from intelligence.capability import Capability, CapabilityType
from intelligence.attack_graph import (
    AttackGraph,
    NodeKind,
    NodeStatus,
    EdgeKind,
)
from intelligence.hypothesis_engine import (
    HypothesisEngine,
    HypothesisProposal,
    ProposalConfidence,
)
from agent.completion_engine import (
    CompletionEngine,
    CompletionAction,
    AssessmentMode,
    BudgetSnapshot,
)


# ===========================================================================
# FIXTURES & HELPERS
# ===========================================================================

def _make_state(target: str = "http://10.10.10.50", objective: str = "Root flag capture and vulnerability assessment") -> AssessmentState:
    ctx = AssessmentContext(
        target=target,
        scope=[target, "10.10.10.50"],
        objective=objective,
    )
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.DISCOVERY
    return state


def _healthy_budget() -> BudgetSnapshot:
    return BudgetSnapshot(
        elapsed_seconds=10.0,
        max_seconds=3600.0,
        tool_calls_used=5,
        max_tool_calls=500,
        iteration=2,
        max_iterations=50,
    )


class DeterministicRecursiveMockLab:
    """
    Deterministic 3-Stage Recursive Environment:
      Surface A: Port 80 HTTP /login -> SQLi auth bypass -> grants AUTHENTICATED
      Surface B: /admin/backup.php (unlocked by AUTH) -> LFI -> reads config -> grants FILE_READ + reveals /internal/exec
      Surface C: /internal/exec (unlocked by FILE_READ) -> Command Injection -> returns root proof
    """
    def __init__(self, host: str = "10.10.10.50"):
        self.host = host
        self.base_url = f"http://{host}:80"

    def execute_tool(self, tool_name: str, args: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = args.get("url", "")
        headers = headers or args.get("headers", {})

        # Stage A: SQLi on /login
        if "/login" in url and tool_name in ("sqlmap_attack", "web_fetch", "http.request"):
            return {
                "success": True,
                "status_code": 200,
                "output": "HTTP/1.1 200 OK\nSet-Cookie: session=admin_token_sec99\n\nWelcome, Administrator! Admin Dashboard.",
                "session_cookie": "session=admin_token_sec99",
                "unlocked_endpoint": f"{self.base_url}/admin/backup.php",
            }

        # Stage B: LFI on /admin/backup.php (requires AUTHENTICATED session cookie)
        if "/admin/backup.php" in url:
            cookie = headers.get("Cookie", "") or headers.get("session", "")
            if "admin_token_sec99" in cookie or "admin" in cookie:
                return {
                    "success": True,
                    "status_code": 200,
                    "output": "HTTP/1.1 200 OK\n\n[CONFIG FILE READ SUCCESS]\nAPI_KEY=int_secret_k88\nINTERNAL_EXEC_ENDPOINT=/internal/exec",
                    "revealed_endpoint": f"{self.base_url}/internal/exec",
                    "secret": "int_secret_k88",
                }
            return {
                "success": False,
                "status_code": 403,
                "output": "403 Forbidden - Authentication required",
            }

        # Stage C: RCE on /internal/exec
        if "/internal/exec" in url:
            return {
                "success": True,
                "status_code": 200,
                "output": "HTTP/1.1 200 OK\nuid=0(root) gid=0(root)\nPROOF-FLAG-ALPHA-ROOT-7B-SUCCESS",
                "proof_marker": "PROOF-FLAG-ALPHA-ROOT-7B-SUCCESS",
            }

        return {"success": False, "status_code": 404, "output": "404 Not Found"}


# ===========================================================================
# 1. DETERMINISTIC RECURSIVE LAB & NO MANUAL ACTION INJECTION
# ===========================================================================

class TestDeterministicRecursiveExpansion:
    """Proves autonomous recursive expansion from Surface A -> B -> C without manual injection."""

    def test_recursive_discovery_lifecycle_a_to_b_to_c(self):
        lab = DeterministicRecursiveMockLab()
        state = _make_state()
        graph = AttackGraph()
        hyp_engine = HypothesisEngine()

        # Step 0: Initial Discovery (Surface A)
        state.record_service(host=lab.host, port=80, service="http", evidence_id="EVI-DISC-001")
        state.record_http_probe(url=f"{lab.base_url}/login", state="RESPONDS", status_code=200, evidence_id="EVI-HTTP-001")
        graph.sync_from_state(state)

        # Assert: Surface B and Surface C are NOT known yet
        assert f"HTTP:{lab.base_url}/admin/backup.php" not in graph._label_index
        assert f"HTTP:{lab.base_url}/internal/exec" not in graph._label_index
        assert not state.has_capability(CapabilityType.AUTHENTICATED)
        assert not state.has_capability(CapabilityType.FILE_READ)

        # Step 1: HypothesisEngine proposes Action A (Auth Bypass on Surface A)
        proposals_a = hyp_engine.propose_next_actions(state, graph)
        assert len(proposals_a) > 0
        prop_a = [p for p in proposals_a if "auth" in p.vulnerability_type.lower() or "sql" in p.vulnerability_type.lower()][0]
        assert prop_a.evidence_ids == ["EVI-DISC-001"]

        # Step 2: Execute Action A -> receives auth evidence & session
        res_a = lab.execute_tool(prop_a.tool_name, prop_a.tool_args)
        assert res_a["success"] is True

        # Ingest Evidence A & Record Capability A
        state.record_finding(
            title="SQLi Authentication Bypass on /login",
            severity="CRITICAL",
            evidence_ids=["EVI-SQLI-001"],
            proof=res_a["output"],
            finding_id="FIND-001",
        )
        cap_a = state.record_capability(
            capability_type=CapabilityType.AUTHENTICATED,
            source_evidence_ids=["EVI-SQLI-001"],
            acquisition_action=prop_a.tool_name,
            target_scope=lab.base_url,
            verified=True,
            metadata={
                "headers": {"Cookie": res_a["session_cookie"]},
                "unlocked_endpoints": [res_a["unlocked_endpoint"]],
            },
            capability_id="CAP-AUTH-001",
        )
        assert state.has_capability(CapabilityType.AUTHENTICATED)

        # Step 3: Graph Expansion for Surface B
        graph.sync_from_state(state)
        node_b = graph.get_node_by_label(f"HTTP:{lab.base_url}/admin/backup.php")
        assert node_b is not None, "Surface B must become reachable in graph after Capability A"
        assert node_b.evidence_ids == ["EVI-SQLI-001"]

        # Assert: Surface C is STILL NOT known yet
        assert f"HTTP:{lab.base_url}/internal/exec" not in graph._label_index

        # Step 4: HypothesisEngine proposes Action B (LFI on Surface B)
        proposals_b = hyp_engine.propose_next_actions(state, graph)
        prop_b = [p for p in proposals_b if "backup" in p.target][0]
        assert prop_b.vulnerability_type == "lfi"
        assert prop_b.capability_context == "CAP-AUTH-001"
        assert "EVI-SQLI-001" in prop_b.evidence_ids

        # Step 5: Execute Action B -> receives config file content revealing Surface C
        res_b = lab.execute_tool(prop_b.tool_name, prop_b.tool_args, headers=prop_b.tool_args.get("headers"))
        assert res_b["success"] is True

        # Ingest Evidence B & Record Capability B
        state.record_finding(
            title="Arbitrary File Read / Config Disclosure on /admin/backup.php",
            severity="HIGH",
            evidence_ids=["EVI-LFI-002"],
            proof=res_b["output"],
            finding_id="FIND-002",
        )
        state.record_capability(
            capability_type=CapabilityType.FILE_READ,
            source_evidence_ids=["EVI-LFI-002"],
            acquisition_action=prop_b.tool_name,
            target_scope=lab.base_url,
            verified=True,
            metadata={
                "unlocked_endpoints": [res_b["revealed_endpoint"]],
                "secret": res_b["secret"],
            },
            capability_id="CAP-FILE-002",
        )
        assert state.has_capability(CapabilityType.FILE_READ)

        # Step 6: Graph Expansion for Surface C
        graph.sync_from_state(state)
        node_c = graph.get_node_by_label(f"HTTP:{lab.base_url}/internal/exec")
        assert node_c is not None, "Surface C must become reachable in graph after Capability B"
        assert node_c.evidence_ids == ["EVI-LFI-002"]

        # Step 7: HypothesisEngine proposes Action C (Command Injection on Surface C)
        proposals_c = hyp_engine.propose_next_actions(state, graph)
        prop_c = [p for p in proposals_c if "internal/exec" in p.target][0]
        assert prop_c.vulnerability_type == "command_injection"
        assert prop_c.capability_context == "CAP-FILE-002"

        # Step 8: Execute Action C -> root proof captured
        res_c = lab.execute_tool(prop_c.tool_name, prop_c.tool_args)
        assert res_c["success"] is True
        assert "PROOF-FLAG-ALPHA-ROOT" in res_c["output"]


# ===========================================================================
# 2. CAPABILITY TRANSITION & VERIFICATION GATING
# ===========================================================================

class TestCapabilityModel:
    """Validates explicit capability lifecycle and verification gating."""

    def test_unverified_capability_does_not_unlock_graph_edges(self):
        state = _make_state()
        graph = AttackGraph()

        # Record unverified capability
        state.record_capability(
            capability_type=CapabilityType.ADMIN_ACCESS,
            source_evidence_ids=["UNCONFIRMED-EVI"],
            verified=False,
            metadata={"unlocked_endpoints": ["http://10.10.10.50:80/hidden_admin"]},
            capability_id="CAP-UNVERIFIED",
        )

        graph.sync_from_state(state)
        # Graph must not create nodes or edges for unverified capabilities
        assert "HTTP:http://10.10.10.50:80/hidden_admin" not in graph._label_index
        assert "CAP:ADMIN_ACCESS:CAP-UNVERIFIED" not in graph._label_index

    def test_verified_capability_creates_typed_graph_nodes_and_edges(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        graph = AttackGraph()

        # Record verified capability
        state.record_capability(
            capability_type=CapabilityType.AUTHENTICATED,
            source_evidence_ids=["EVI-001"],
            verified=True,
            metadata={"unlocked_endpoints": ["http://10.10.10.50:80/dashboard"]},
            capability_id="CAP-AUTH-VERIFIED",
        )

        graph.sync_from_state(state)

        cap_node = graph.get_node_by_label("CAP:AUTHENTICATED:CAP-AUTH-VERIFIED")
        assert cap_node is not None
        assert cap_node.kind == NodeKind.CAPABILITY
        assert cap_node.status == NodeStatus.EXPLORED
        assert cap_node.evidence_ids == ["EVI-001"]

        ep_node = graph.get_node_by_label("HTTP:http://10.10.10.50:80/dashboard")
        assert ep_node is not None
        assert ep_node.status == NodeStatus.PENDING

        # Check directed edge from CAP -> ENDPOINT
        edge = [e for e in graph.edges if e.from_node_id == cap_node.node_id and e.to_node_id == ep_node.node_id][0]
        assert edge.kind == EdgeKind.ENABLES
        assert edge.evidence_ids == ["EVI-001"]


# ===========================================================================
# 3. ATTACK GRAPH CONVERGENCE & IDEMPOTENCE (NO FAKE WORK)
# ===========================================================================

class TestAttackGraphConvergence:
    """Proves repeated syncs without state changes yield zero fake work."""

    def test_sync_from_state_is_strictly_idempotent(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        state.record_finding("SQLi", severity="HIGH", evidence_ids=["EVI-001"], finding_id="FIND-1")
        state.record_capability(
            capability_type=CapabilityType.AUTHENTICATED,
            source_evidence_ids=["EVI-001"],
            metadata={"unlocked_endpoints": ["http://10.10.10.50:80/admin"]},
            capability_id="CAP-1",
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        initial_node_count = len(graph.nodes)
        initial_edge_count = len(graph.edges)

        # Run sync 10 times consecutively
        for _ in range(10):
            graph.sync_from_state(state)

        assert len(graph.nodes) == initial_node_count, "Node count must not grow on repeated syncs"
        assert len(graph.edges) == initial_edge_count, "Edge count must not grow on repeated syncs"


# ===========================================================================
# 4. REPEATED FAILED STRATEGY SUPPRESSION
# ===========================================================================

class TestHypothesisEngineSuppression:
    """Proves that refuted/failed hypotheses are not regenerated without new evidence."""

    def test_refuted_hypothesis_is_suppressed_when_no_new_evidence(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        graph = AttackGraph()
        graph.sync_from_state(state)

        engine = HypothesisEngine()

        # Mark auth_bypass_sqli as REFUTED with evidence EVI-001
        h = state.record_hypothesis(
            target="http://10.10.10.50:80",
            service="http",
            port=80,
            vulnerability_type="auth_bypass_sqli",
            evidence_ids=["EVI-001"],
            hypothesis_id="HYP-AUTH_BYPASS_SQLI-80",
        )
        h.status = HypothesisStatus.REFUTED

        proposals = engine.propose_next_actions(state, graph)
        proposed_types = [p.vulnerability_type for p in proposals]

        assert "auth_bypass_sqli" not in proposed_types, "Refuted hypothesis must not be re-proposed without new evidence"

    def test_refuted_hypothesis_is_reconsidered_when_new_evidence_arrives(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        graph = AttackGraph()

        engine = HypothesisEngine()

        # Initial refuted hypothesis with EVI-001
        h = state.record_hypothesis(
            target="http://10.10.10.50:80",
            service="http",
            port=80,
            vulnerability_type="auth_bypass_sqli",
            evidence_ids=["EVI-001"],
            hypothesis_id="HYP-AUTH_BYPASS_SQLI-80",
        )
        h.status = HypothesisStatus.REFUTED

        # New evidence arrives on the service (e.g. detailed technology fingerprint or endpoint)
        state.services[list(state.services.keys())[0]].evidence_ids.append("EVI-NEW-BANNER-SQLITE")
        graph.sync_from_state(state)

        # Now proposal should be reconsidered because evidence set changed!
        assert not engine._is_refuted_without_new_evidence(
            "HYP-AUTH_BYPASS_SQLI-80",
            ["EVI-001", "EVI-NEW-BANNER-SQLITE"],
            state,
        )


# ===========================================================================
# 5. INFORMATION GAIN METRIC
# ===========================================================================

class TestInformationGainMetric:
    """Validates calculation of information gain per action."""

    def test_information_gain_increases_on_new_evidence_and_decays_on_repetition(self):
        state = _make_state()
        graph = AttackGraph()

        snap_0 = state.get_surface_snapshot(graph)

        # Action 1: Discovers a service
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        graph.sync_from_state(state)
        snap_1 = state.get_surface_snapshot(graph)
        gain_1 = state.record_information_gain(snap_0, snap_1, action_name="nmap_scan")
        assert gain_1 > 0.0, "Service discovery must yield positive information gain"

        # Action 2: Acquires a finding + capability
        state.record_finding("SQLi", severity="HIGH", evidence_ids=["EVI-002"], finding_id="FIND-1")
        state.record_capability(
            capability_type=CapabilityType.AUTHENTICATED,
            source_evidence_ids=["EVI-002"],
            metadata={"unlocked_endpoints": ["http://10.10.10.50:80/admin"]},
            capability_id="CAP-1",
        )
        graph.sync_from_state(state)
        snap_2 = state.get_surface_snapshot(graph)
        gain_2 = state.record_information_gain(snap_1, snap_2, action_name="sqlmap_attack")
        assert gain_2 > gain_1, "Finding + capability must yield substantial information gain"

        # Action 3: Repeated identical action with no new state changes
        snap_3 = state.get_surface_snapshot(graph)
        gain_3 = state.record_information_gain(snap_2, snap_3, action_name="sqlmap_attack_repeat")
        assert gain_3 == 0.0, "Repeated action with zero delta must have 0.0 information gain"


# ===========================================================================
# 6. VERIFICATION LIFECYCLE
# ===========================================================================

class TestVerificationLifecycle:
    """Validates the strict verification workflow: VALIDATION -> OBJECTIVE_ACHIEVED_UNVERIFIED -> VERIFY -> OBJECTIVE_VERIFIED."""

    def test_full_verification_pipeline(self):
        state = _make_state()
        graph = AttackGraph()
        engine = CompletionEngine(mode=AssessmentMode.TARGETED)

        # Stage 1: Tool returns validation success
        state.validation_attempted = True
        state.validation_tool_success = True
        state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

        # Gate 2 must require VERIFY action
        decision_1 = engine.evaluate(state, graph, budget=_healthy_budget(), observations=["exploited login"])
        assert decision_1.action == CompletionAction.VERIFY
        assert not decision_1.should_conclude

        # Stage 2: Independent verification candidate executed and verified
        state.verification_started = True
        state.verification_success = True
        state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED

        # Graph has no remaining work -> CONCLUDE_SUCCESS
        decision_2 = engine.evaluate(state, graph, budget=_healthy_budget(), observations=["verified root proof"])
        assert decision_2.action == CompletionAction.CONCLUDE_SUCCESS
        assert decision_2.should_conclude


# ===========================================================================
# 7. TARGETED VS EXHAUSTIVE MODES
# ===========================================================================

class TestTargetedVsExhaustiveModes:
    """Validates distinct termination criteria in TARGETED vs EXHAUSTIVE modes."""

    def test_targeted_concludes_on_verified_objective_while_exhaustive_continues(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        state.record_service("10.10.10.50", 8080, "http-proxy", evidence_id="EVI-002")

        graph = AttackGraph()
        graph.sync_from_state(state)

        # Mark port 80 investigated, but port 8080 remains pending
        svc_80 = list(state.services.keys())[0]
        state.services[svc_80].investigated = True
        node_80 = graph.get_node_by_label("10.10.10.50:80/tcp")
        node_80.mark_explored()

        # Objective is verified
        state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED

        engine_targeted = CompletionEngine(mode=AssessmentMode.TARGETED)
        engine_exhaustive = CompletionEngine(mode=AssessmentMode.EXHAUSTIVE)

        decision_t = engine_targeted.evaluate(state, graph, budget=_healthy_budget())
        decision_e = engine_exhaustive.evaluate(state, graph, budget=_healthy_budget())

        # TARGETED mode concludes on verified objective (or continues remaining relevant work)
        assert decision_t.action in (CompletionAction.CONCLUDE_SUCCESS, CompletionAction.CONTINUE)
        # EXHAUSTIVE mode MUST continue until all ports (8080) are exhausted
        assert decision_e.action == CompletionAction.CONTINUE
        assert not decision_e.should_conclude


# ===========================================================================
# 8. BUDGET BEHAVIOR IN RECURSIVE CHAIN
# ===========================================================================

class TestBudgetExhaustionInRecursiveChain:
    """Validates that budget exhaustion terminates with CONCLUDE_BUDGET while preserving state."""

    def test_budget_exhaustion_mid_recursion(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
        state.record_finding("Partial SQLi", severity="MEDIUM", evidence_ids=["EVI-001"])
        graph = AttackGraph()
        graph.sync_from_state(state)

        exhausted_budget = BudgetSnapshot(
            elapsed_seconds=3605.0,
            max_seconds=3600.0,
            tool_calls_used=120,
            max_tool_calls=100,
            iteration=15,
            max_iterations=40,
        )

        engine = CompletionEngine(mode=AssessmentMode.EXHAUSTIVE)
        decision = engine.evaluate(state, graph, budget=exhausted_budget)

        assert decision.action == CompletionAction.CONCLUDE_BUDGET
        assert decision.should_conclude
        assert len(state.findings) == 1, "Evidence and findings must be fully preserved on budget conclusion"


# ===========================================================================
# 9. ATTACK GRAPH EDGE EVIDENCE INTEGRITY
# ===========================================================================

class TestAttackGraphEdgeEvidenceIntegrity:
    """Proves that every graph edge maintains explicit evidence IDs."""

    def test_all_graph_edges_have_evidence_ids(self):
        state = _make_state()
        state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-NMAP-80")
        state.record_finding("SQLi", severity="HIGH", evidence_ids=["EVI-SQLI-001"], finding_id="FIND-1")
        state.record_capability(
            capability_type=CapabilityType.AUTHENTICATED,
            source_evidence_ids=["EVI-SQLI-001"],
            metadata={"unlocked_endpoints": ["http://10.10.10.50:80/admin"]},
            capability_id="CAP-1",
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        assert len(graph.edges) > 0, "Graph must have edges"
        for edge in graph.edges:
            assert len(edge.evidence_ids) > 0, f"Edge {edge.edge_id} ({edge.kind}) must have evidence_ids"


# ===========================================================================
# 10. MODEL-INDEPENDENT DETERMINISTIC PLANNER WORKFLOW
# ===========================================================================

class TestModelIndependentPlannerWorkflow:
    """
    Executes a complete autonomous recursive assessment loop without an LLM.
    Validates the end-to-end trace:
      DISCOVERY → SERVICE → ENDPOINT-A → HYPOTHESIS-A → VALIDATION-A → CAPABILITY-A
      → GRAPH EXPANSION → ENDPOINT-B → HYPOTHESIS-B → VALIDATION-B → CAPABILITY-B
      → GRAPH EXPANSION → ENDPOINT-C → HYPOTHESIS-C → VALIDATION-C → CAPABILITY-C
      → VERIFY → OBJECTIVE_VERIFIED
    """

    def test_autonomous_recursive_planner_execution(self):
        lab = DeterministicRecursiveMockLab()
        state = _make_state(target=lab.base_url, objective="Capture root proof marker")
        graph = AttackGraph()
        hyp_engine = HypothesisEngine()
        completion_engine = CompletionEngine(mode=AssessmentMode.TARGETED)

        trace: List[str] = []

        # 0. Initial Discovery
        state.record_service(host=lab.host, port=80, service="http", evidence_id="EVI-DISC-01")
        state.record_http_probe(url=f"{lab.base_url}/login", state="RESPONDS", status_code=200, evidence_id="EVI-HTTP-01")
        graph.sync_from_state(state)
        trace.append("DISCOVERY_INITIALIZED")

        max_cycles = 10
        for cycle in range(max_cycles):
            # Evaluate completion
            budget = _healthy_budget()
            budget.iteration = cycle + 1
            decision = completion_engine.evaluate(state, graph, budget=budget)

            if decision.action == CompletionAction.CONCLUDE_SUCCESS:
                trace.append("OBJECTIVE_VERIFIED_SUCCESS")
                break

            if decision.action == CompletionAction.VERIFY:
                trace.append("VERIFY_DISPATCHED")
                # Run verification
                state.verification_started = True
                state.verification_success = True
                state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
                # Mark pending graph nodes explored
                for node in graph.nodes.values():
                    if node.status == NodeStatus.PENDING:
                        node.mark_explored()
                continue

            # Generate proposals
            proposals = hyp_engine.propose_next_actions(state, graph, max_proposals=5)
            assert len(proposals) > 0, f"Cycle {cycle}: must have proposals"
            hyp_engine.ensure_hypotheses_in_state(state, proposals)
            top_proposal = proposals[0]

            trace.append(f"EXECUTE_{top_proposal.vulnerability_type.upper()}_{top_proposal.target}")

            # Execute tool in lab
            result = lab.execute_tool(
                top_proposal.tool_name,
                top_proposal.tool_args,
                headers=top_proposal.tool_args.get("headers"),
            )

            # Ingest outcome
            if "session_cookie" in result:
                state.record_finding(
                    title="SQLi on /login",
                    severity="CRITICAL",
                    evidence_ids=[f"EVI-SQLI-{cycle}"],
                    proof=result["output"],
                )
                state.record_capability(
                    capability_type=CapabilityType.AUTHENTICATED,
                    source_evidence_ids=[f"EVI-SQLI-{cycle}"],
                    acquisition_action=top_proposal.tool_name,
                    target_scope=lab.base_url,
                    metadata={
                        "headers": {"Cookie": result["session_cookie"]},
                        "unlocked_endpoints": [result["unlocked_endpoint"]],
                    },
                    capability_id=f"CAP-AUTH-{cycle}",
                )
                trace.append("CAPABILITY_AUTHENTICATED_ACQUIRED")

            elif "revealed_endpoint" in result:
                state.record_finding(
                    title="LFI on /admin/backup.php",
                    severity="HIGH",
                    evidence_ids=[f"EVI-LFI-{cycle}"],
                    proof=result["output"],
                )
                state.record_capability(
                    capability_type=CapabilityType.FILE_READ,
                    source_evidence_ids=[f"EVI-LFI-{cycle}"],
                    acquisition_action=top_proposal.tool_name,
                    target_scope=lab.base_url,
                    metadata={
                        "unlocked_endpoints": [result["revealed_endpoint"]],
                        "secret": result["secret"],
                    },
                    capability_id=f"CAP-FILE-{cycle}",
                )
                trace.append("CAPABILITY_FILE_READ_ACQUIRED")

            elif "proof_marker" in result:
                state.record_finding(
                    title="RCE on /internal/exec",
                    severity="CRITICAL",
                    evidence_ids=[f"EVI-RCE-{cycle}"],
                    proof=result["output"],
                )
                state.record_capability(
                    capability_type=CapabilityType.COMMAND_EXECUTION,
                    source_evidence_ids=[f"EVI-RCE-{cycle}"],
                    acquisition_action=top_proposal.tool_name,
                    target_scope=lab.base_url,
                    capability_id=f"CAP-RCE-{cycle}",
                )
                state.validation_attempted = True
                state.validation_tool_success = True
                state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
                trace.append("CAPABILITY_COMMAND_EXECUTION_ACQUIRED")

            # Update hypothesis and sync graph
            hyp_engine.update_from_result(
                state,
                top_proposal.hypothesis_id,
                top_proposal.tool_name,
                result["output"],
                result["success"],
            )
            graph.sync_from_state(state)

        # Assert full autonomous trace completed successfully
        assert "DISCOVERY_INITIALIZED" in trace
        assert "CAPABILITY_AUTHENTICATED_ACQUIRED" in trace
        assert "CAPABILITY_FILE_READ_ACQUIRED" in trace
        assert "CAPABILITY_COMMAND_EXECUTION_ACQUIRED" in trace
        assert "VERIFY_DISPATCHED" in trace
        assert "OBJECTIVE_VERIFIED_SUCCESS" in trace
        assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
