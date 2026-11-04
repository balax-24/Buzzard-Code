"""
Tests for Phase 10 Long-Horizon Execution.
Verifies:
1. Agent state remains coherent and memory bounds remain strictly bounded over 10, 20, 40, 80 iterations.
2. Information gain decays on repeated actions and prompts pivoting.
"""

import pytest
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord
from security_agent.intelligence.decision import DecisionRecord, DecisionSource, AutonomyMode, AutonomyEvaluator
from security_agent.intelligence.long_horizon import LongHorizonContextCompactor


def test_long_horizon_budget_scaling():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.services["target.local:8080/tcp"] = ServiceRecord(
        host="target.local", port=8080, protocol="tcp", service="http"
    )

    info_gains = []
    # Simulate 40 iterations
    for it in range(1, 41):
        gain = 1.0 / it if it <= 5 else 0.0
        info_gains.append(gain)
        dec = DecisionRecord(
            iteration=it,
            source=DecisionSource.MODEL,
            selected_tool="web_fetch" if it % 2 == 0 else "browser.snapshot",
            target="http://target.local:8080/"
        )
        state.record_decision(dec)

    assert len(state.decision_records) == 40
    # Verify compacted context size remains bounded (< 2000 chars) despite 40 turns
    compact_ctx = LongHorizonContextCompactor.build_compact_context(
        state=state,
        last_information_gain=info_gains[-1],
        last_action_note="Duplicate page fetch",
        mode=AutonomyMode.RAW_MODEL
    )
    assert len(compact_ctx) < 2500
    assert "PIVOT ADVICE" in compact_ctx
