"""
P2-1 Tests: Information Gain Signals in CompletionEngine.

Verifies:
1. Zero gain once -> continue (does not prematurely terminate on single low/zero gain)
2. Zero gain repeatedly -> terminate appropriately (triggers PIVOT then AUTHORIZED_SURFACE_EXHAUSTED)
3. Gain resets/decays zero-gain streak (positive gain resets streak and clears stagnation)
4. Rolling gain calculation (accurate rolling window and useful action rates)
5. Verified objective overrides exploration (in TARGETED mode with zero gain streak)
6. Unresolved but exhausted state terminates (clean exit on exhausted authorized surface)
7. Recursive discovery continues while gaining information (positive gain preserves loop)
8. Deterministic behavior across repeated runs (identical inputs produce identical decisions)
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ObjectiveStatus,
    ServiceRecord,
    ServiceState,
    HypothesisStatus,
    CapabilityType,
)
from security_agent.agent.completion_engine import (
    CompletionEngine,
    AssessmentMode,
    CompletionAction,
    BudgetSnapshot,
)
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus
from security_agent.intelligence.information_gain import InformationGainEngine


def _make_state(target: str = "127.0.0.1") -> AssessmentState:
    state = AssessmentState(context=AssessmentContext(target=target, scope=[target]))
    return state


def _make_budget(iteration: int = 5, max_iterations: int = 40) -> BudgetSnapshot:
    return BudgetSnapshot(
        elapsed_seconds=100.0,
        max_seconds=3600.0,
        tool_calls_used=iteration,
        max_tool_calls=200,
        iteration=iteration,
        max_iterations=max_iterations,
    )


def test_zero_gain_once_continues():
    """Single action with zero information gain does NOT terminate assessment."""
    state = _make_state()
    state.record_service("127.0.0.1", 80, "http", evidence_id="EVI-01")
    graph = AttackGraph()
    graph.sync_from_state(state)

    engine = CompletionEngine(mode=AssessmentMode.TARGETED, zero_gain_threshold=4)

    # 1 zero-gain action recorded
    engine.record_action_gain(0.0, action_name="probe_port")
    assert engine.zero_gain_streak == 1
    assert engine.rolling_information_gain == 0.0

    decision = engine.evaluate(state, graph, _make_budget(iteration=2), target="127.0.0.1")
    assert decision.action == CompletionAction.CONTINUE
    assert not decision.should_conclude


def test_zero_gain_repeatedly_triggers_pivot_and_termination():
    """
    Repeated zero-gain actions first trigger PIVOT for strategy diversification,
    and then terminate with AUTHORIZED_SURFACE_EXHAUSTED when pivots fail to yield new information.
    """
    state = _make_state()
    state.record_service("127.0.0.1", 80, "http", evidence_id="EVI-01")
    svc_key = list(state.services.keys())[0]
    state.services[svc_key].investigated = True

    graph = AttackGraph()
    graph.sync_from_state(state)

    engine = CompletionEngine(mode=AssessmentMode.TARGETED, zero_gain_threshold=3)

    # Record 3 consecutive zero-gain actions -> triggers first PIVOT
    for i in range(3):
        engine.record_action_gain(0.0, action_name=f"probe_{i}")

    assert engine.zero_gain_streak == 3
    budget = _make_budget(iteration=10)
    decision1 = engine.evaluate(state, graph, budget, target="127.0.0.1")
    assert decision1.action == CompletionAction.PIVOT
    assert decision1.should_continue
    assert engine._pivot_counter == 1

    # Record more zero-gain actions until max pivot cycles exceeded
    for i in range(10):
        engine.record_action_gain(0.0, action_name=f"pivot_probe_{i}")

    engine._pivot_counter = CompletionEngine.MAX_PIVOT_CYCLES + 1
    decision2 = engine.evaluate(state, graph, budget, target="127.0.0.1")
    assert decision2.action == CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED
    assert decision2.should_conclude


def test_gain_resets_zero_gain_streak():
    """Positive information gain immediately resets the zero_gain_streak to zero."""
    engine = CompletionEngine(zero_gain_threshold=4, min_progress_gain=0.05)

    # 3 zero-gain actions
    engine.record_action_gain(0.0)
    engine.record_action_gain(0.01)  # Below min_progress_gain
    engine.record_action_gain(0.0)
    assert engine.zero_gain_streak == 3

    # Meaningful gain action (e.g. finding discovered)
    engine.record_action_gain(10.0, action_name="sqli_exploit")
    assert engine.zero_gain_streak == 0
    assert engine.useful_action_count == 1
    assert engine.rolling_information_gain > 0.0

    # Another zero gain increments streak from 0 to 1
    engine.record_action_gain(0.0)
    assert engine.zero_gain_streak == 1


def test_rolling_gain_calculation():
    """Rolling information gain accurately reflects windowed empirical action gain."""
    engine = CompletionEngine(rolling_window_size=4)

    engine.record_action_gain(2.0)
    engine.record_action_gain(4.0)
    assert engine.rolling_information_gain == 3.0
    assert engine.useful_action_rate == 1.0

    engine.record_action_gain(0.0)
    engine.record_action_gain(0.0)
    # Window has [2.0, 4.0, 0.0, 0.0] -> avg = 1.5
    assert engine.rolling_information_gain == 1.5
    assert engine.useful_action_rate == 0.5  # 2 useful out of 4 total

    # Push another 0.0 -> window slides to [4.0, 0.0, 0.0, 0.0] -> avg = 1.0
    engine.record_action_gain(0.0)
    assert engine.rolling_information_gain == 1.0
    assert engine.total_actions_evaluated == 5
    assert engine.useful_action_count == 2
    assert engine.useful_action_rate == 0.4


def test_verified_objective_overrides_exploration():
    """In TARGETED mode, once the objective is verified and information gain ceases, conclude immediately."""
    state = _make_state()
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_started = True
    state.verification_success = True
    state.record_finding("Root RCE", severity="CRITICAL", evidence_ids=["EVI-RCE"])

    graph = AttackGraph()
    # Add a pending node to simulate lingering potential work
    n = graph.add_node(NodeKind.SERVICE, "127.0.0.1:8080/tcp")
    n.status = NodeStatus.PENDING

    engine = CompletionEngine(mode=AssessmentMode.TARGETED)

    # When zero-gain streak occurs after objective is verified:
    engine.record_action_gain(0.0)
    assert engine.zero_gain_streak >= 1

    decision = engine.evaluate(state, graph, _make_budget(iteration=8), target="127.0.0.1")
    assert decision.action == CompletionAction.CONCLUDE_SUCCESS
    assert decision.should_conclude
    assert "objective verified" in decision.rationale.lower()


def test_unresolved_but_exhausted_state_terminates():
    """When the objective is unresolved and authorized attack surface is exhausted, terminate cleanly."""
    state = _make_state()
    state.objective_status = ObjectiveStatus.OBJECTIVE_UNREACHED
    state.record_service("127.0.0.1", 80, "http", evidence_id="EVI-01")
    svc_key = list(state.services.keys())[0]
    state.services[svc_key].investigated = True

    graph = AttackGraph()
    graph.sync_from_state(state)
    for node in graph.nodes.values():
        node.mark_exhausted()

    engine = CompletionEngine(mode=AssessmentMode.TARGETED)
    # Simulate repeated zero-gain across full exploration
    for _ in range(5):
        engine.record_action_gain(0.0)

    decision = engine.evaluate(state, graph, _make_budget(iteration=12), target="127.0.0.1")
    assert decision.action == CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED
    assert decision.should_conclude
    assert "exhausted" in decision.rationale.lower()


def test_recursive_discovery_continues_while_gaining_information():
    """
    While active recursive discovery is acquiring capabilities and unlocking nodes,
    positive information gain keeps the assessment active and prevents premature cutoff.
    """
    state = _make_state()
    state.record_service("127.0.0.1", 80, "http", evidence_id="EVI-01")
    graph = AttackGraph()
    graph.sync_from_state(state)

    engine = CompletionEngine(mode=AssessmentMode.TARGETED, zero_gain_threshold=3)

    # Step 1: Initial discovery gives gain
    engine.record_action_gain(2.5, action_name="service_scan")
    assert engine.zero_gain_streak == 0
    d1 = engine.evaluate(state, graph, _make_budget(iteration=1), target="127.0.0.1")
    assert d1.action == CompletionAction.CONTINUE

    # Step 2: Capability acquisition yields substantial gain
    state.record_capability(
        capability_type=CapabilityType.AUTHENTICATED,
        source_evidence_ids=["EVI-01"],
        acquisition_action="auth_bypass",
        target_scope="127.0.0.1",
        verified=True,
    )
    graph.sync_from_state(state)
    engine.record_action_gain(5.0, action_name="auth_bypass")
    assert engine.zero_gain_streak == 0
    d2 = engine.evaluate(state, graph, _make_budget(iteration=2), target="127.0.0.1")
    assert d2.action == CompletionAction.CONTINUE

    # Step 3: Zero gain once -> still continues!
    engine.record_action_gain(0.0, action_name="enum_tier2")
    assert engine.zero_gain_streak == 1
    d3 = engine.evaluate(state, graph, _make_budget(iteration=3), target="127.0.0.1")
    assert d3.action == CompletionAction.CONTINUE


def test_deterministic_behavior_across_repeated_runs():
    """Repeated runs with identical states and gain sequences produce byte-for-byte identical decisions."""
    def run_simulation():
        state = _make_state()
        state.record_service("127.0.0.1", 80, "http", evidence_id="E1")
        graph = AttackGraph()
        graph.sync_from_state(state)
        engine = CompletionEngine(mode=AssessmentMode.TARGETED, zero_gain_threshold=3)
        budget = _make_budget(iteration=5)

        decisions = []
        # Action 1: positive gain
        engine.record_action_gain(2.0, "scan")
        decisions.append(engine.evaluate(state, graph, budget, target="127.0.0.1").action.value)

        # Action 2: zero gain
        engine.record_action_gain(0.0, "probe1")
        decisions.append(engine.evaluate(state, graph, budget, target="127.0.0.1").action.value)

        # Action 3: zero gain
        engine.record_action_gain(0.0, "probe2")
        decisions.append(engine.evaluate(state, graph, budget, target="127.0.0.1").action.value)

        # Action 4: zero gain (hits threshold -> pivot)
        engine.record_action_gain(0.0, "probe3")
        decisions.append(engine.evaluate(state, graph, budget, target="127.0.0.1").action.value)

        return decisions, engine.rolling_information_gain, engine.zero_gain_streak

    run1_decisions, run1_gain, run1_streak = run_simulation()
    run2_decisions, run2_gain, run2_streak = run_simulation()

    assert run1_decisions == run2_decisions
    assert run1_gain == run2_gain
    assert run1_streak == run2_streak == 3
