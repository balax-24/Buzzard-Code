"""
Phase 14 Tests: Deterministic Session Replay & Canonical Golden Trace.
Verifies full offline state reconstruction from event streams without executing live tools.
"""

from security_agent.benchmark.golden_trace import generate_golden_trace_events
from security_agent.persistence.replay import SessionReplayEngine
from security_agent.agent.assessment_state import ObjectiveStatus, CapabilityType
from security_agent.intelligence.invariants import StateInvariantValidator


def test_golden_trace_replay_deterministic_reconstruction():
    events = generate_golden_trace_events(session_id="golden-test-01", target="127.0.0.1")
    assert len(events) >= 15

    engine = SessionReplayEngine()
    reconstructed_state, reconstructed_graph = engine.replay_from_events(events)

    # 1. Verify Ground Truth State reconstructed
    assert reconstructed_state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert len(reconstructed_state.evidence) >= 3
    assert len(reconstructed_state.findings) >= 1
    assert "cap-admin-session" in reconstructed_state.capabilities
    assert reconstructed_state.capabilities["cap-admin-session"].capability_type == CapabilityType.ADMIN_ACCESS

    # 2. Verify Attack Graph reconstructed
    assert len(reconstructed_graph.nodes) >= 4
    assert len(reconstructed_graph.edges) >= 3

    # 3. Verify Reconstructed State passes all invariants
    res = StateInvariantValidator.validate_state(
        state=reconstructed_state,
        graph=reconstructed_graph,
        raise_on_violation=True
    )
    assert res.is_valid is True
    assert len(res.violations) == 0
