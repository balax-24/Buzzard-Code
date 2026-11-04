"""
Tests for Phase 10 Information Gain Driven Planning.
Verifies:
1. Information gain per action is tracked and exposed.
2. 0.0 information gain emits actionable pivot guidance in planner context.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord
from security_agent.intelligence.attack_graph import AttackGraph
from security_agent.intelligence.long_horizon import LongHorizonContextCompactor


def test_information_gain_signals_pivot():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    graph = AttackGraph()

    snap0 = state.get_surface_snapshot(graph)
    state.record_service("target.local", 8080, "http", evidence_id="EVI-001")
    graph.sync_from_state(state)
    snap1 = state.get_surface_snapshot(graph)

    gain1 = state.record_information_gain(snap0, snap1, action_name="nmap_scan")
    assert gain1 > 0.0

    # Repeated identical action -> 0.0 gain
    snap2 = state.get_surface_snapshot(graph)
    gain2 = state.record_information_gain(snap1, snap2, action_name="nmap_scan")
    assert gain2 == 0.0

    ctx = LongHorizonContextCompactor.build_compact_context(
        state=state,
        graph=graph,
        last_information_gain=gain2,
        last_action_note="Identical scan result"
    )
    assert "Last Action Info Gain: 0.00" in ctx
    assert "PIVOT ADVICE" in ctx
