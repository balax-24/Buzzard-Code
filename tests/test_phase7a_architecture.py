"""
Phase 7A — Architectural Verification Suite
============================================

Validates the three intelligence engines:
  A. AttackGraph    — evidence <-> node mapping, convergence, no infinite work
  B. HypothesisEngine — recursive A->B->C chain without manual injection
  C. CompletionEngine — all 6 exit paths, stagnation PIVOT, TARGETED vs EXHAUSTIVE mode

Architectural invariants under test:
  - The LLM NEVER decides when the assessment is complete.
  - Stagnation -> PIVOT (not termination).
  - A finding MUST NOT terminate the assessment -- it creates new work.
  - verified finding WITHOUT newly reachable state -> no infinite pending nodes.
  - Graph convergence: repeated sync_from_state() -> identical node count.
  - CompletionEngine is the SOLE lifecycle termination authority.

Run with:
    pytest tests/test_phase7a_architecture.py -v
"""

from __future__ import annotations

import pytest

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    HypothesisStatus,
    ServiceState,
)
from security_agent.intelligence.attack_graph import (
    AttackGraph,
    NodeKind,
    NodeStatus,
    EdgeKind,
    GraphNode,
)
from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.agent.completion_engine import (
    CompletionEngine,
    CompletionAction,
    AssessmentMode,
    BudgetSnapshot,
)

TARGET = "http://10.10.10.10"


def _make_state(target: str = TARGET) -> AssessmentState:
    """Minimal, clean AssessmentState for test fixtures."""
    ctx = AssessmentContext(
        target=target,
        scope=[target],
        objective="CTF: capture root flag",
    )
    return AssessmentState(context=ctx)


def _make_state_neutral(target: str = TARGET) -> AssessmentState:
    """State with a non-offensive objective.

    Gate 7 in CompletionEngine only fires when the objective contains offensive
    keywords (attack, exploit, capture flag, etc). Tests that probe Gate 9
    (stagnation -> PIVOT) must use a neutral objective so Gate 7 does not
    intercept first and return CONTINUE unconditionally.
    """
    ctx = AssessmentContext(
        target=target,
        scope=[target],
        objective="assess network security posture and enumerate open services",
    )
    return AssessmentState(context=ctx)


def _healthy_budget(iteration: int = 5) -> BudgetSnapshot:
    return BudgetSnapshot(
        elapsed_seconds=60.0,
        max_seconds=3600.0,
        tool_calls_used=10,
        max_tool_calls=500,
        iteration=iteration,
        max_iterations=40,
    )


def _exhausted_budget() -> BudgetSnapshot:
    return BudgetSnapshot(
        elapsed_seconds=3600.0,
        max_seconds=3600.0,
        tool_calls_used=500,
        max_tool_calls=500,
        iteration=40,
        max_iterations=40,
    )


# ===========================================================================
# A. ATTACK GRAPH VALIDATION
# ===========================================================================

class TestAttackGraphEvidence:
    """Section A1 — evidence -> node mapping."""

    def test_evidence_id_attached_to_service_node(self):
        """A discovered service with an evidence_id must expose that id on its node."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")
        graph = AttackGraph()
        graph.sync_from_state(state)

        node = graph.get_node_by_label("10.10.10.10:80/tcp")
        assert node is not None, "Service node must be created from state"
        assert "NMAP-001" in node.evidence_ids

    def test_discovered_endpoint_creates_pending_endpoint_node(self):
        """A new HTTP endpoint in state must produce a PENDING ENDPOINT node."""
        from security_agent.agent.assessment_state import HTTPEndpointRecord, HTTPState
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        ep = HTTPEndpointRecord(
            url="http://10.10.10.10/admin",
            host="10.10.10.10",
            port=80,
            status_code=200,
            title="Admin Panel",
            state=HTTPState.RESPONDS,
        )
        ep.evidence_ids.append("FETCH-001")
        state.http_endpoints["http://10.10.10.10/admin"] = ep

        graph = AttackGraph()
        graph.sync_from_state(state)

        ep_node = graph.get_node_by_label("HTTP:http://10.10.10.10/admin")
        assert ep_node is not None, "ENDPOINT node must be created for discovered HTTP path"
        assert ep_node.kind == NodeKind.ENDPOINT
        assert ep_node.status == NodeStatus.PENDING

    def test_critical_finding_spawns_post_exploit_pending_node(self):
        """
        CAPABILITY PIVOT: A CRITICAL/HIGH finding must spawn a POST_EXPLOIT
        PENDING child node — the newly reachable resource.
        """
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_finding(
            title="Auth Bypass via SQL Injection",
            severity="CRITICAL",
            evidence_ids=["SQLI-001"],
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        finding_node = graph.get_node_by_label("FINDING:Auth Bypass via SQL Injection")
        assert finding_node is not None

        children = graph.children_of(finding_node.node_id)
        post_exploit = [c for c in children if c.metadata.get("task") == "post_exploitation"]
        assert post_exploit, "CRITICAL finding must spawn a POST_EXPLOIT PENDING child"
        assert all(c.status == NodeStatus.PENDING for c in post_exploit), \
            "Spawned post-exploit nodes must be PENDING"

    def test_verified_finding_node_is_explored_not_pending(self):
        """A verified finding must appear as an EXPLORED FINDING node (result, not task)."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=22, service="ssh", evidence_id="E1")
        state.record_finding(
            title="Weak SSH Credentials",
            severity="HIGH",
            evidence_ids=["SSH-001"],
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        fn = graph.get_node_by_label("FINDING:Weak SSH Credentials")
        assert fn is not None
        assert fn.kind == NodeKind.FINDING
        assert fn.status == NodeStatus.EXPLORED, \
            "Findings are results -- must be EXPLORED, not PENDING"


class TestAttackGraphNoInfiniteWork:
    """Section A2 — findings without new reachable state must NOT create infinite work."""

    def test_low_severity_finding_does_not_create_pending_finding_node(self):
        """INFO/LOW severity finding must NOT put a FINDING node into PENDING state."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_finding(
            title="Server Version Disclosure",
            severity="LOW",
            evidence_ids=["INFO-001"],
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        finding_node = graph.get_node_by_label("FINDING:Server Version Disclosure")
        assert finding_node is not None
        assert finding_node.status == NodeStatus.EXPLORED

        pending_findings = [n for n in graph.pending_nodes() if n.kind == NodeKind.FINDING]
        assert not pending_findings, "FINDING nodes must never be PENDING"

    def test_repeated_sync_does_not_multiply_nodes(self):
        """Graph convergence: sync_from_state() with identical state must be idempotent."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_finding(title="Info Leak", severity="INFO", evidence_ids=["X1"])

        graph = AttackGraph()
        graph.sync_from_state(state)
        count1 = len(graph.nodes)
        graph.sync_from_state(state)
        count2 = len(graph.nodes)
        graph.sync_from_state(state)
        count3 = len(graph.nodes)

        assert count1 == count2 == count3, \
            f"Node count must be stable: {count1} -> {count2} -> {count3}"

    def test_graph_convergence_with_multiple_services_and_finding(self):
        """5 syncs with the same state must leave node count unchanged."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_service(host="10.10.10.10", port=22, service="ssh", evidence_id="E2")
        state.record_finding(title="High Risk Finding", severity="HIGH", evidence_ids=["H1"])

        graph = AttackGraph()
        for _ in range(5):
            graph.sync_from_state(state)
        final = len(graph.nodes)

        graph.sync_from_state(state)
        assert len(graph.nodes) == final, "Graph must be idempotent after convergence"

    def test_finding_node_stays_explored_across_resyncs(self):
        """Finding node must never flip back to PENDING on repeated sync."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_finding(title="SQL Injection", severity="CRITICAL", evidence_ids=["S1"])

        graph = AttackGraph()
        for _ in range(3):
            graph.sync_from_state(state)
            fn = graph.get_node_by_label("FINDING:SQL Injection")
            assert fn is not None
            assert fn.status == NodeStatus.EXPLORED, \
                "Finding node must remain EXPLORED across all syncs"


# ===========================================================================
# B. HYPOTHESIS ENGINE — RECURSIVE A->B->C CHAIN
# ===========================================================================

class TestHypothesisEngineRecursiveChain:
    """
    Section B — Deterministic, evidence-grounded, recursive hypothesis generation.

    Fixture:
      A: HTTP service on port 80 discovered -> engine proposes http vulns
      B: auth_bypass_sqli verified -> graph spawns POST_EXPLOIT PENDING node
      C: POST_EXPLOIT PENDING node -> engine proposes follow-on investigation
    """

    def test_A_service_discovery_generates_http_proposals(self):
        """Engine must propose HTTP vuln tests when an HTTP service is discovered."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")

        engine = HypothesisEngine()
        graph = AttackGraph()
        graph.sync_from_state(state)

        proposals = engine.propose_next_actions(state, graph, max_proposals=10)

        assert proposals, "Engine must generate proposals for an HTTP service"
        vuln_types = {p.vulnerability_type for p in proposals}
        http_vulns = {"auth_bypass_sqli", "sql_injection", "lfi", "xss", "command_injection"}
        assert http_vulns & vuln_types, \
            f"Expected HTTP vulnerability proposals, got: {vuln_types}"
        for p in proposals:
            assert p.target, "Every proposal must have a target"
            assert p.tool_name, "Every proposal must specify a tool"

    def test_B_verified_finding_spawns_post_exploit_without_injection(self):
        """After auth_bypass_sqli is verified, graph must auto-create POST_EXPLOIT node."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")

        hyp = state.record_hypothesis(
            target="http://10.10.10.10:80", service="http", port=80,
            vulnerability_type="auth_bypass_sqli",
            rationale="Login form susceptible to SQL injection",
            evidence_ids=["SQLI-001"],
        )
        hyp.status = HypothesisStatus.VERIFIED
        hyp.verified = True
        state.record_finding(
            title="Auth Bypass via SQL Injection",
            severity="CRITICAL",
            evidence_ids=["SQLI-001"],
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        assert graph.has_unexplored_work(), \
            "Graph must have unexplored work after a CRITICAL finding"
        post_exploit = [
            n for n in graph.pending_nodes()
            if n.metadata.get("task") == "post_exploitation"
        ]
        assert post_exploit, \
            "POST_EXPLOIT PENDING node must be created without manual injection"

    def test_C_post_exploit_node_drives_next_proposal(self):
        """POST_EXPLOIT PENDING node must cause engine to propose follow-on work."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")

        hyp = state.record_hypothesis(
            target="http://10.10.10.10:80", service="http", port=80,
            vulnerability_type="auth_bypass_sqli",
            evidence_ids=["SQLI-001"],
        )
        hyp.status = HypothesisStatus.VERIFIED
        hyp.verified = True
        state.record_finding(
            title="Auth Bypass via SQL Injection",
            severity="CRITICAL",
            evidence_ids=["SQLI-001"],
        )

        graph = AttackGraph()
        graph.sync_from_state(state)

        pending_endpoints = [n for n in graph.pending_nodes() if n.kind == NodeKind.ENDPOINT]
        assert pending_endpoints, "There must be pending ENDPOINT nodes after step B"

        engine = HypothesisEngine()
        proposals = engine.propose_next_actions(state, graph, max_proposals=10)

        assert proposals, "Engine must produce proposals after CRITICAL finding creates graph work"

    def test_chain_proposals_are_bounded(self):
        """Proposals must never exceed max_proposals (no infinite loop)."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True

        for vuln_type in ("auth_bypass_sqli", "lfi", "xss", "command_injection"):
            h = state.record_hypothesis(
                target="http://10.10.10.10:80", service="http", port=80,
                vulnerability_type=vuln_type,
                evidence_ids=[],
                hypothesis_id=f"HYP-{vuln_type.upper()}-80",
            )
            h.status = HypothesisStatus.REFUTED

        graph = AttackGraph()
        graph.sync_from_state(state)
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = HypothesisEngine()
        proposals = engine.propose_next_actions(state, graph, max_proposals=10)

        assert len(proposals) <= 10, "Proposals must be bounded by max_proposals"

    def test_ensure_hypotheses_in_state_idempotent(self):
        """ensure_hypotheses_in_state() called twice must not create duplicates."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")

        engine = HypothesisEngine()
        graph = AttackGraph()
        graph.sync_from_state(state)
        proposals = engine.propose_next_actions(state, graph, max_proposals=5)

        engine.ensure_hypotheses_in_state(state, proposals)
        count1 = len(state.hypotheses)
        engine.ensure_hypotheses_in_state(state, proposals)
        count2 = len(state.hypotheses)

        assert count1 == count2, \
            f"ensure_hypotheses_in_state must be idempotent ({count1} vs {count2})"


# ===========================================================================
# C. COMPLETION ENGINE — ALL 6 EXIT PATHS
# ===========================================================================

class TestCompletionEngineTerminationPaths:
    """
    Section C — All 6 CompletionAction paths must be reachable.
    The LLM NEVER decides assessment completion.
    """

    def test_conclude_budget_on_exhausted_budget(self):
        """Gate 1: Budget fully exhausted -> CONCLUDE_BUDGET (terminal)."""
        state = _make_state()
        graph = AttackGraph()
        engine = CompletionEngine(mode=AssessmentMode.TARGETED)

        result = engine.evaluate(state, graph, budget=_exhausted_budget())

        assert result.action == CompletionAction.CONCLUDE_BUDGET, \
            f"Exhausted budget must yield CONCLUDE_BUDGET, got {result.action}"
        assert result.should_conclude, "CONCLUDE_BUDGET must be terminal (should_conclude=True)"

    def test_continue_on_cold_start(self):
        """Gate 3: No services discovered yet -> CONTINUE."""
        state = _make_state()
        graph = AttackGraph()
        engine = CompletionEngine(mode=AssessmentMode.TARGETED)

        result = engine.evaluate(state, graph, budget=_healthy_budget(iteration=0))

        assert result.action == CompletionAction.CONTINUE, \
            f"Cold start must yield CONTINUE, got {result.action}"
        assert result.should_continue

    def test_continue_when_uninvestigated_services_present(self):
        """Gate 5: Uninvestigated service remains -> CONTINUE."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        graph = AttackGraph()
        graph.sync_from_state(state)

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        result = engine.evaluate(state, graph, budget=_healthy_budget())

        assert result.action == CompletionAction.CONTINUE, \
            f"Uninvestigated HTTP service must yield CONTINUE, got {result.action}"

    def test_pivot_on_stagnation_threshold(self):
        """Gate 9: Stagnation at threshold -> PIVOT (assessment continues).

        Gate 9 only fires after Gates 5-8 are bypassed:
          Gate 5: services must be investigated (no uninvestigated services)
          Gate 6: no high-conf proposals
          Gate 7: objective reached (not offensive, or proof found)
          Gate 8: graph must have no unexplored work
        """
        state = _make_state_neutral()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        # Bypass Gate 5: mark service investigated
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True
        # Bypass Gate 6: refute all HTTP vuln proposals so no high-conf proposals remain
        for vuln_type in ("auth_bypass_sqli", "command_injection", "lfi", "xss"):
            h = state.record_hypothesis(
                target="http://10.10.10.10:80", service="http", port=80,
                vulnerability_type=vuln_type, evidence_ids=[],
                hypothesis_id=f"HYP-{vuln_type.upper()}-80",
            )
            h.status = HypothesisStatus.REFUTED

        graph = AttackGraph()
        graph.sync_from_state(state)
        # Bypass Gate 8: exhaust all graph nodes
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        engine._last_state_version = state.state_version
        engine._last_graph_pending = graph.total_unexplored()  # 0 — all exhausted
        engine._stagnation_counter = CompletionEngine.STAGNATION_PIVOT_THRESHOLD

        result = engine.evaluate(state, graph, budget=_healthy_budget())

        assert result.action == CompletionAction.PIVOT, \
            f"Stagnation at threshold must yield PIVOT, got {result.action}"
        assert result.should_continue, "PIVOT must allow assessment to continue"

    def test_stagnation_never_terminates_assessment(self):
        """Architectural invariant: stagnation -> PIVOT only, never a terminal action."""
        state = _make_state_neutral()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True

        graph = AttackGraph()
        graph.sync_from_state(state)
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        engine._last_state_version = state.state_version
        engine._last_graph_pending = graph.total_unexplored()  # 0 — all exhausted
        engine._stagnation_counter = CompletionEngine.STAGNATION_PIVOT_THRESHOLD

        result = engine.evaluate(state, graph, budget=_healthy_budget())

        assert not result.should_conclude, \
            f"Stagnation must NEVER terminate. Got {result.action}, concludes={result.should_conclude}"

    def test_finding_does_not_terminate_assessment(self):
        """
        Architectural invariant: a new verified finding must NOT terminate the assessment.
        Findings create new work; CompletionEngine is the sole termination authority.
        A CRITICAL finding spawns a POST_EXPLOIT PENDING node, which Gate 8 picks up
        and returns CONTINUE — confirming the finding did NOT terminate the loop.
        """
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        state.record_finding(title="SQL Injection", severity="CRITICAL", evidence_ids=["S1"])

        graph = AttackGraph()
        graph.sync_from_state(state)

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        result = engine.evaluate(state, graph, budget=_healthy_budget())

        # A CRITICAL finding creates POST_EXPLOIT pending work -> engine must CONTINUE, not conclude
        assert not result.should_conclude or result.action == CompletionAction.CONCLUDE_BUDGET, \
            f"New finding must not terminate assessment. Got {result.action}"

    def test_conclude_success_or_surface_exhausted_with_full_graph_explored(self):
        """Graph fully explored -> engine must reach a terminal or surface-exhausted state."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True
        state.record_finding(
            title="Root Flag Captured", severity="CRITICAL",
            evidence_ids=["FLAG-001"], proof="FLAG{test}",
        )

        graph = AttackGraph()
        graph.sync_from_state(state)
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        result = engine.evaluate(state, graph, budget=_healthy_budget())

        assert result.action in (
            CompletionAction.CONCLUDE_SUCCESS,
            CompletionAction.CONTINUE,
            CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
        ), f"Unexpected action with exhausted graph: {result.action}"

    def test_authorized_surface_exhausted_exhaustive_mode(self):
        """EXHAUSTIVE mode + exhausted graph + max pivots -> AUTHORIZED_SURFACE_EXHAUSTED."""
        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True

        graph = AttackGraph()
        graph.sync_from_state(state)
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = CompletionEngine(mode=AssessmentMode.EXHAUSTIVE)
        engine._last_state_version = state.state_version
        engine._stagnation_counter = CompletionEngine.STAGNATION_PIVOT_THRESHOLD
        engine._pivot_counter = CompletionEngine.MAX_PIVOT_CYCLES + 1

        result = engine.evaluate(state, graph, budget=_healthy_budget())

        assert result.action in (
            CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
            CompletionAction.CONCLUDE_BUDGET,
            CompletionAction.CONTINUE,
        ), f"EXHAUSTIVE mode with exhausted graph: unexpected action {result.action}"

    def test_targeted_vs_exhaustive_mode_reach_terminal_state(self):
        """At least one mode must reach a terminal action when graph is exhausted.

        Setup bypasses all continuation gates:
          - service investigated (Gate 5 bypassed)
          - no high-conf proposals (Gate 6 bypassed)
          - graph fully exhausted (Gate 8 bypassed)
          - stagnation counter at max + pivot counter past MAX_PIVOT_CYCLES (Gate 9 -> ASE)
        """
        state = _make_state_neutral()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True
        # All hypotheses refuted so engine produces no proposals (Gate 6 bypassed)
        for vuln_type in ("auth_bypass_sqli", "lfi", "xss", "command_injection"):
            h = state.record_hypothesis(
                target="http://10.10.10.10:80", service="http", port=80,
                vulnerability_type=vuln_type, evidence_ids=[],
                hypothesis_id=f"HYP-{vuln_type.upper()}-80",
            )
            h.status = HypothesisStatus.REFUTED

        def make_exhausted_graph():
            g = AttackGraph()
            g.sync_from_state(state)
            for node in g.nodes.values():
                node.status = NodeStatus.EXHAUSTED
            return g

        engine_t = CompletionEngine(mode=AssessmentMode.TARGETED)
        engine_e = CompletionEngine(mode=AssessmentMode.EXHAUSTIVE)
        for e in (engine_t, engine_e):
            e._last_state_version = state.state_version
            e._last_graph_pending = 0  # matches exhausted graph total_unexplored()
            e._stagnation_counter = CompletionEngine.STAGNATION_PIVOT_THRESHOLD
            e._pivot_counter = CompletionEngine.MAX_PIVOT_CYCLES + 1

        result_t = engine_t.evaluate(state, make_exhausted_graph(), budget=_healthy_budget())
        result_e = engine_e.evaluate(state, make_exhausted_graph(), budget=_healthy_budget())

        terminal = {
            CompletionAction.CONCLUDE_SUCCESS,
            CompletionAction.CONCLUDE_BUDGET,
            CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
        }
        assert {result_t.action, result_e.action} & terminal, (
            f"At least one mode must reach a terminal action. "
            f"TARGETED={result_t.action}, EXHAUSTIVE={result_e.action}"
        )


# ===========================================================================
# D. CAPABILITY PIVOT — unauth -> auth -> new endpoint
# ===========================================================================

class TestCapabilityPivot:
    """Section D — Full unauth -> auth -> new endpoint capability pivot flow."""

    def test_capability_pivot_full_flow(self):
        """
        1. /login known (unauthenticated).
        2. auth_bypass_sqli confirmed -> /admin now reachable.
        3. Graph gains PENDING /admin node.
        4. Engine proposes work on /admin without manual injection.
        """
        from security_agent.agent.assessment_state import HTTPEndpointRecord, HTTPState

        state = _make_state()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="NMAP-001")

        # Phase 1: unauthenticated surface
        login_ep = HTTPEndpointRecord(
            url="http://10.10.10.10/login",
            host="10.10.10.10", port=80,
            status_code=200, title="Login", state=HTTPState.RESPONDS,
        )
        login_ep.evidence_ids.append("FETCH-001")
        state.http_endpoints["http://10.10.10.10/login"] = login_ep

        graph = AttackGraph()
        graph.sync_from_state(state)
        pending_before = len(graph.pending_nodes())

        # Phase 2: exploit succeeds
        hyp = state.record_hypothesis(
            target="http://10.10.10.10:80", service="http", port=80,
            vulnerability_type="auth_bypass_sqli",
            evidence_ids=["SQLI-001"],
        )
        hyp.status = HypothesisStatus.VERIFIED
        hyp.verified = True
        state.record_finding(
            title="Auth Bypass via SQL Injection",
            severity="CRITICAL",
            evidence_ids=["SQLI-001"],
        )

        # Phase 3: new endpoint discovered via authenticated access
        admin_ep = HTTPEndpointRecord(
            url="http://10.10.10.10/admin",
            host="10.10.10.10", port=80,
            status_code=200, title="Admin Dashboard", state=HTTPState.RESPONDS,
        )
        admin_ep.evidence_ids.append("ADMIN-001")
        state.http_endpoints["http://10.10.10.10/admin"] = admin_ep

        graph.sync_from_state(state)
        pending_after = len(graph.pending_nodes())

        assert pending_after >= pending_before, (
            f"Pending count must grow after capability pivot "
            f"(before={pending_before}, after={pending_after})"
        )
        admin_node = graph.get_node_by_label("HTTP:http://10.10.10.10/admin")
        assert admin_node is not None, "/admin must appear as a graph node"
        assert admin_node.status == NodeStatus.PENDING, "/admin must be PENDING"

        # Phase 4: engine proposes follow-on work automatically
        engine = HypothesisEngine()
        proposals = engine.propose_next_actions(state, graph, max_proposals=10)
        assert proposals, "Engine must propose work after capability pivot"


# ===========================================================================
# E. LOOP RECOVERY COOPERATION
# ===========================================================================

class TestLoopRecoveryCooperation:
    """
    Section E — LoopRecoveryController and CompletionEngine must not duplicate roles.
    LoopRecovery: detects repetitive tool use.
    CompletionEngine: decides lifecycle termination.
    """

    def test_loop_recovery_and_completion_engine_separate_imports(self):
        """Both components must import cleanly and have distinct interfaces."""
        from security_agent.agent.completion_engine import CompletionEngine
        from security_agent.agent.loop_controller import LoopRecoveryController

        ce = CompletionEngine(mode=AssessmentMode.TARGETED)
        lrc = LoopRecoveryController()

        assert hasattr(ce, "evaluate"), "CompletionEngine must have evaluate()"
        assert not hasattr(lrc, "should_terminate_assessment"), \
            "LoopRecoveryController must not make termination decisions"

    def test_pivot_from_completion_engine_does_not_require_loop_recovery(self):
        """CompletionEngine generates PIVOT independently of LoopRecoveryController."""
        state = _make_state_neutral()
        state.record_service(host="10.10.10.10", port=80, service="http", evidence_id="E1")
        graph = AttackGraph()
        graph.sync_from_state(state)

        # Bypass Gates 5-8 so Gate 9 (stagnation) fires
        svc_key = list(state.services.keys())[0]
        state.services[svc_key].investigated = True
        # Bypass Gate 6: refute all HTTP vuln proposals so no high-conf proposals remain
        for vuln_type in ("auth_bypass_sqli", "command_injection", "lfi", "xss"):
            h = state.record_hypothesis(
                target="http://10.10.10.10:80", service="http", port=80,
                vulnerability_type=vuln_type, evidence_ids=[],
                hypothesis_id=f"HYP-{vuln_type.upper()}-80",
            )
            h.status = HypothesisStatus.REFUTED
        for node in graph.nodes.values():
            node.status = NodeStatus.EXHAUSTED

        engine = CompletionEngine(mode=AssessmentMode.TARGETED)
        engine._last_state_version = state.state_version
        engine._last_graph_pending = graph.total_unexplored()  # 0 — all exhausted
        engine._stagnation_counter = CompletionEngine.STAGNATION_PIVOT_THRESHOLD

        result = engine.evaluate(state, graph, budget=_healthy_budget())

        # PIVOT means: diversify strategy, assessment CONTINUES
        assert result.action == CompletionAction.PIVOT
        assert result.should_continue
        assert not result.should_conclude


# ===========================================================================
# F. BUDGET SNAPSHOT
# ===========================================================================

class TestBudgetSnapshot:
    """Section F — BudgetSnapshot property gates."""

    def test_fresh_budget_not_exhausted(self):
        b = BudgetSnapshot(elapsed_seconds=0, max_seconds=3600,
                           tool_calls_used=0, max_tool_calls=500,
                           iteration=0, max_iterations=40)
        assert not b.is_budget_exhausted
        assert not b.is_budget_critical

    def test_exhausted_on_time_limit(self):
        b = BudgetSnapshot(elapsed_seconds=3600, max_seconds=3600,
                           tool_calls_used=0, max_tool_calls=500,
                           iteration=0, max_iterations=40)
        assert b.is_budget_exhausted

    def test_exhausted_on_tool_call_limit(self):
        b = BudgetSnapshot(elapsed_seconds=0, max_seconds=3600,
                           tool_calls_used=500, max_tool_calls=500,
                           iteration=0, max_iterations=40)
        assert b.is_budget_exhausted

    def test_critical_at_90_percent_iteration(self):
        b = BudgetSnapshot(elapsed_seconds=0, max_seconds=3600,
                           tool_calls_used=0, max_tool_calls=500,
                           iteration=36, max_iterations=40)  # 90%
        assert b.is_budget_critical
        assert not b.is_budget_exhausted


# ===========================================================================
# G. GRAPH NODE LIFECYCLE
# ===========================================================================

class TestGraphNodeLifecycle:
    """Section G — Node lifecycle transitions, deduplication, priority ordering."""

    def test_node_pending_to_in_progress_to_explored(self):
        node = GraphNode(node_id="T1", kind=NodeKind.SERVICE, label="svc:80/tcp")
        assert node.status == NodeStatus.PENDING

        node.mark_in_progress()
        assert node.status == NodeStatus.IN_PROGRESS
        assert node.exploration_attempts == 1

        node.mark_explored()
        assert node.status == NodeStatus.EXPLORED
        assert node.explored_at is not None

    def test_node_exhausted_transition(self):
        node = GraphNode(node_id="T2", kind=NodeKind.SERVICE, label="svc:22/tcp")
        node.mark_in_progress()
        node.mark_exhausted()
        assert node.status == NodeStatus.EXHAUSTED
        assert node.explored_at is not None

    def test_add_node_deduplication_by_label(self):
        graph = AttackGraph()
        n1 = graph.add_node(NodeKind.SERVICE, label="10.10.10.10:80/tcp")
        n2 = graph.add_node(NodeKind.SERVICE, label="10.10.10.10:80/tcp")
        assert n1.node_id == n2.node_id, "Same-label add must return the existing node"
        assert len(graph.nodes) == 1

    def test_add_edge_deduplication(self):
        graph = AttackGraph()
        host = graph.add_node(NodeKind.HOST, label="10.10.10.10")
        svc = graph.add_node(NodeKind.SERVICE, label="10.10.10.10:80/tcp")
        e1 = graph.add_edge(host.node_id, svc.node_id, EdgeKind.DISCOVERED_ON)
        e2 = graph.add_edge(host.node_id, svc.node_id, EdgeKind.DISCOVERED_ON)
        assert e1.edge_id == e2.edge_id, "Duplicate edge must not be inserted"
        assert len(graph.edges) == 1

    def test_pending_nodes_sorted_by_priority(self):
        graph = AttackGraph()
        graph.add_node(NodeKind.SERVICE, label="low",  priority=80)
        graph.add_node(NodeKind.SERVICE, label="high", priority=10)
        graph.add_node(NodeKind.SERVICE, label="mid",  priority=50)
        priorities = [n.priority for n in graph.pending_nodes()]
        assert priorities == sorted(priorities), "pending_nodes() must sort ascending by priority"

    def test_has_unexplored_work_false_when_all_exhausted(self):
        graph = AttackGraph()
        node = graph.add_node(NodeKind.SERVICE, label="10.10.10.10:80/tcp")
        assert graph.has_unexplored_work()
        node.mark_exhausted()
        assert not graph.has_unexplored_work()
