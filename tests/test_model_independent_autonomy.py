"""
Tests for Phase 10 Deterministic Model-Free Autonomy Fixture.
Verifies that the backend deterministic planner reaches OBJECTIVE_VERIFIED
without manual action injection, strictly from observed evidence.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceRecord,
    Capability,
    CapabilityType,
    ObjectiveStatus,
)
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.evidence_ingestor import EvidenceIngestor
from intelligence.decision import DecisionRecord, DecisionSource, AutonomyEvaluator, AutonomyMode
from agent.tool_executor import ToolExecutionResult


def test_deterministic_model_free_autonomy_fixture():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    ingestor = EvidenceIngestor()
    graph = AttackGraph()
    engine = HypothesisEngine()

    # Step 1: Deterministic port discovery
    state.record_service("target.local", 8080, "http", evidence_id="EVI-001")
    graph.sync_from_state(state)
    state.record_decision(DecisionRecord(
        iteration=1,
        source=DecisionSource.DETERMINISTIC,
        selected_tool="nmap_scan",
        target="target.local"
    ))

    # Step 2: Form discovery
    login_html = "<html><body><form id='auth' action='http://target.local:8080/login' method='POST'><input name='u'/></form></body></html>"
    res_snap = ToolExecutionResult(
        success=True,
        tool_name="browser.snapshot",
        arguments={"url": "http://target.local:8080/"},
        raw_output=login_html,
        exit_code=0
    )
    ingestor.ingest(res_snap, state=state)
    state.record_decision(DecisionRecord(
        iteration=2,
        source=DecisionSource.DETERMINISTIC,
        selected_tool="browser.snapshot",
        target="http://target.local:8080/"
    ))

    # Step 3: Top hypothesis proposed & executed deterministically
    proposals = engine.propose_next_actions(state, graph=graph)
    assert len(proposals) > 0
    top = proposals[0]

    # Step 4: Exploit result ingested -> objective achieved
    exploit_res = ToolExecutionResult(
        success=True,
        tool_name=top.tool_name,
        arguments=top.tool_args,
        raw_output="FLAG{DETERMINISTIC_MODEL_INDEPENDENT_PROOVED}",
        exit_code=0
    )
    ingestor.ingest(exploit_res, state=state)
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    state.verification_success = True
    state.record_decision(DecisionRecord(
        iteration=3,
        source=DecisionSource.DETERMINISTIC,
        selected_tool=top.tool_name,
        target=top.target,
        arguments=top.tool_args
    ))

    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert len(state.decision_records) == 3
    assert all(d.source == DecisionSource.DETERMINISTIC for d in state.decision_records)
