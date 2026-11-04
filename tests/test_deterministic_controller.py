"""
Tests for P0-3 Deterministic Controller.

Validates:
1. controller_initializes_from_state
2. highest_priority_candidate_is_deterministic
3. controller_selects_available_candidate
4. controller_respects_preconditions
5. controller_updates_canonical_state
6. controller_updates_graph
7. controller_updates_hypotheses
8. controller_records_information_gain
9. controller_remembers_failed_actions
10. controller_does_not_repeat_zero_gain_actions
11. controller_respects_budget
12. controller_stops_after_verification
13. controller_stops_when_surface_exhausted
14. controller_does_not_require_llm
"""

import pytest
from typing import Dict, Any

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    ServiceState,
    HypothesisStatus,
    CapabilityType,
    VerificationStatus,
)
from security_agent.intelligence.attack_graph import (
    AttackGraph,
    NodeKind,
    NodeStatus,
)
from security_agent.intelligence.decision import DecisionSource
from security_agent.agent.completion_engine import (
    CompletionEngine,
    CompletionAction,
    AssessmentMode,
    BudgetSnapshot,
)
from security_agent.agent.deterministic_controller import (
    DeterministicController,
    highest_priority_candidate,
)


def _make_test_state(target: str = "http://10.10.10.50:80") -> AssessmentState:
    ctx = AssessmentContext(
        target=target,
        scope=[target, "10.10.10.50", "http://10.10.10.50:80"],
        objective="Capture proof marker on authorized lab target",
    )
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.DISCOVERY
    return state


def test_controller_initializes_from_state():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
    controller = DeterministicController(state=state)

    assert controller.state is state
    assert len(controller.graph.nodes) > 0
    assert controller.budget.iteration == 0
    assert controller.ATTRIBUTION == "DETERMINISTIC_CONTROLLER"


def test_highest_priority_candidate_is_deterministic():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
    state.record_http_probe("http://10.10.10.50:80/login", state="RESPONDS", status_code=200, evidence_id="EVI-002")

    cand1 = highest_priority_candidate(state)
    cand2 = highest_priority_candidate(state)

    assert cand1 is not None
    assert cand2 is not None
    assert cand1.tool == cand2.tool
    assert cand1.target == cand2.target
    assert cand1.utility_score == cand2.utility_score
    assert cand1.candidate_id == cand2.candidate_id


def test_controller_selects_available_candidate():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")
    controller = DeterministicController(state=state)

    cand = controller.highest_priority_candidate()
    assert cand is not None
    assert cand.tool in ("sqlmap_attack", "web_fetch", "http.request", "lfi_scan", "xss_scan")
    assert "10.10.10.50" in cand.target


def test_controller_respects_preconditions():
    state = _make_test_state()
    # Out of scope candidate target
    state.record_service("192.168.1.1", 80, "http", evidence_id="EVI-OUT-SCOPE")
    controller = DeterministicController(state=state)

    # Force candidate target outside authorized scope
    cand = controller.highest_priority_candidate()
    if cand:
        cand.target = "http://192.168.1.1:80/secret"
        # Temporarily mock highest_priority_candidate to return out-of-scope candidate
        controller.highest_priority_candidate = lambda: cand

        res = controller.step()
        assert not res.success
        assert res.status == "PRECONDITION_FAILED"
        assert "scope" in res.details.lower()


def test_controller_updates_canonical_state():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "status_code": 200,
            "output": "HTTP/1.1 200 OK\nSet-Cookie: session=adm_val\nAdmin area unlocked",
            "session_cookie": "session=adm_val",
            "unlocked_endpoint": "http://10.10.10.50:80/admin",
        }

    controller = DeterministicController(state=state, tool_executor=mock_executor)
    init_findings = len(state.findings)
    init_caps = len(state.capabilities)

    res = controller.step()
    assert res.success
    assert len(state.findings) > init_findings
    assert len(state.capabilities) > init_caps
    assert state.has_capability(CapabilityType.AUTHENTICATED)
    assert len(state.decision_records) == 1
    assert state.decision_records[0].source == DecisionSource.DETERMINISTIC


def test_controller_updates_graph():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "status_code": 200,
            "output": "Welcome Admin",
            "session_cookie": "session=adm_val",
            "unlocked_endpoint": "http://10.10.10.50:80/admin/settings",
        }

    controller = DeterministicController(state=state, tool_executor=mock_executor)
    init_node_count = len(controller.graph.nodes)

    controller.step()
    assert len(controller.graph.nodes) > init_node_count
    # Verify capability node was derived into graph
    cap_nodes = [n for n in controller.graph.nodes.values() if n.kind == NodeKind.CAPABILITY]
    assert len(cap_nodes) >= 1


def test_controller_updates_hypotheses():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "output": "HTTP/1.1 200 OK login valid",
            "session_cookie": "session=adm_val",
        }

    controller = DeterministicController(state=state, tool_executor=mock_executor)
    cand = controller.highest_priority_candidate()
    assert cand is not None

    res = controller.step()
    assert res.success
    if cand.hypothesis_id in state.hypotheses:
        assert state.hypotheses[cand.hypothesis_id].status in (HypothesisStatus.VERIFIED, HypothesisStatus.ACTIVE)


def test_controller_records_information_gain():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "output": "HTTP/1.1 200 OK\nAdmin token revealed",
            "session_cookie": "session=token123",
            "unlocked_endpoint": "http://10.10.10.50:80/admin",
        }

    controller = DeterministicController(state=state, tool_executor=mock_executor)
    res = controller.step()
    assert res.information_gain > 0.0
    assert controller.total_information_gain > 0.0


def test_controller_remembers_failed_actions():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_failing_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {"success": False, "exit_code": 1, "output": "Connection refused"}

    controller = DeterministicController(state=state, tool_executor=mock_failing_executor)
    res = controller.step()
    assert not res.success
    assert len(state.failed_actions) == 1
    assert (state.failed_actions[0].get("tool") or state.failed_actions[0].get("tool_name")) == res.tool_name



def test_controller_does_not_repeat_zero_gain_actions():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    # Mock no-op executor that yields zero state changes
    def mock_noop_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {"success": True, "exit_code": 0, "output": "No change"}

    controller = DeterministicController(state=state, tool_executor=mock_noop_executor, max_zero_gain_streak=3)
    summary = controller.run(max_steps=10)

    # Controller must terminate instead of running indefinitely
    assert summary.total_steps <= 5
    assert summary.terminal_status in ("ZERO_GAIN_EXHAUSTED", "SURFACE_EXHAUSTED")


def test_controller_respects_budget():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    budget = BudgetSnapshot(
        elapsed_seconds=0.0,
        max_seconds=3600.0,
        tool_calls_used=0,
        max_tool_calls=2,  # Strict tool call limit
        iteration=0,
        max_iterations=10,
    )

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {"success": True, "exit_code": 0, "output": "OK"}

    controller = DeterministicController(state=state, tool_executor=mock_executor, budget=budget)
    summary = controller.run(max_steps=10)

    assert budget.tool_calls_used <= 2
    assert summary.terminal_status == "CONCLUDE_BUDGET"
    assert state.objective_status == ObjectiveStatus.BUDGET_EXHAUSTED


def test_controller_stops_after_verification():
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "output": "FLAG{MOCK_VERIFIED_ROOT_SUCCESS}",
            "proof_marker": "FLAG{MOCK_VERIFIED_ROOT_SUCCESS}",
        }

    controller = DeterministicController(state=state, tool_executor=mock_executor)

    # Step 1: Capture proof marker
    res1 = controller.step()
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # Step 2: Verification dispatched & completed
    res2 = controller.step()
    assert res2.completed
    assert res2.status == "OBJECTIVE_VERIFIED"
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED


def test_controller_stops_when_surface_exhausted():
    # Empty state with no services, endpoints, or target
    ctx = AssessmentContext(target="", scope=[], objective="test")
    state = AssessmentState(context=ctx)
    controller = DeterministicController(state=state)

    res = controller.step()
    assert res.completed
    assert res.status == "SURFACE_EXHAUSTED"
    assert state.objective_status == ObjectiveStatus.SURFACE_EXHAUSTED


def test_controller_does_not_require_llm():
    # Verify that full controller cycle executes entirely without any model provider or network LLM
    state = _make_test_state()
    state.record_service("10.10.10.50", 80, "http", evidence_id="EVI-001")

    call_count = 0
    def mock_executor(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal call_count
        call_count += 1
        return {"success": True, "output": f"Deterministic execution #{call_count}"}

    controller = DeterministicController(state=state, tool_executor=mock_executor)
    summary = controller.run(max_steps=3)

    assert summary.total_steps >= 1
    assert summary.decisions_count >= 1
    assert all(d.source == DecisionSource.DETERMINISTIC for d in state.decision_records)
