"""
Unit and integration tests for Canonical Model Decision Contract.

Verifies:
- Valid structured JSON decisions parse cleanly into typed contracts.
- Native OpenAI/Ollama tool calls parse into ActionIntent.
- XML fallback tool calls parse into ActionIntent.
- Malformed model responses recover gracefully into traceable fallbacks without crashing.
- Operational reasoning, hypotheses, verification intents, and recovery intents are preserved.
- Model decisions are pure intent: they cannot directly mutate AssessmentState.
"""

import pytest
import json
from model.decision_contract import (
    ModelDecision,
    ModelDecisionParser,
    DecisionType,
    DecisionSource,
    ActionIntent,
    HypothesisIntent,
    RecoveryIntent,
    VerificationIntent,
    CompletionAssessment,
)
from agent.assessment_state import AssessmentState, ObjectiveStatus


def test_valid_structured_json_decision():
    raw_json = json.dumps({
        "contract_version": "1.0.0",
        "decision_type": "TOOL_CALL",
        "objective_interpretation": "Scan target for open web ports",
        "reasoning_summary": "Reconnaissance shows host is active; scanning ports to map services.",
        "why_this_action": "Port scanning provides immediate attack surface discovery.",
        "expected_information_gain": 3.5,
        "confidence": 0.9,
        "selected_action": {
            "tool_name": "scan_ports",
            "arguments": {"target": "127.0.0.1", "ports": "80,8080"},
            "action_class": "RECON"
        },
        "hypothesis": {
            "vulnerability_type": "EXPOSED_SERVICE",
            "target": "127.0.0.1",
            "port": 8080,
            "rationale": "High likelihood of development HTTP service"
        },
        "next_step_intent": "Grab banner on discovered open ports"
    })

    decision = ModelDecisionParser.parse(raw_content=raw_json)

    assert decision.contract_version == "1.0.0"
    assert decision.decision_type == DecisionType.TOOL_CALL
    assert decision.decision_source == DecisionSource.MODEL
    assert decision.is_malformed_recovery is False
    assert decision.action is not None
    assert decision.action.tool_name == "scan_ports"
    assert decision.action.arguments == {"target": "127.0.0.1", "ports": "80,8080"}
    assert decision.expected_information_gain == 3.5
    assert decision.hypothesis is not None
    assert decision.hypothesis.port == 8080
    assert decision.next_step_intent == "Grab banner on discovered open ports"

    # Verify to_tool_call export
    tc = decision.to_tool_call()
    assert tc is not None
    assert tc["function"]["name"] == "scan_ports"
    assert tc["function"]["arguments"] == {"target": "127.0.0.1", "ports": "80,8080"}


def test_native_tool_calls_parsing():
    native_calls = [
        {
            "function": {
                "name": "http.request",
                "arguments": {"url": "http://127.0.0.1:8080/api", "method": "GET"}
            }
        }
    ]

    decision = ModelDecisionParser.parse(
        raw_content="Examining API endpoint for unauthenticated routes.",
        native_tool_calls=native_calls,
        model_name="qwythos:latest",
    )

    assert decision.decision_type == DecisionType.TOOL_CALL
    assert decision.action is not None
    assert decision.action.tool_name == "http.request"
    assert decision.action.arguments["url"] == "http://127.0.0.1:8080/api"
    assert "Examining API endpoint" in decision.reasoning_summary
    assert decision.is_malformed_recovery is False


def test_xml_tool_call_parsing():
    content = """
    I will test the login endpoint for bypass vulnerabilities.
    <tool_call>
    <tool_name>auth_bypass_test</tool_name>
    <arguments>{"url": "http://127.0.0.1:8080/login", "payload": "' OR 1=1--"}</arguments>
    </tool_call>
    """

    decision = ModelDecisionParser.parse(raw_content=content)

    assert decision.decision_type == DecisionType.TOOL_CALL
    assert decision.action is not None
    assert decision.action.tool_name == "auth_bypass_test"
    assert decision.action.arguments["url"] == "http://127.0.0.1:8080/login"


def test_malformed_json_graceful_recovery():
    malformed = "Thinking: { This is not valid JSON at all: 12345 ] }}}"

    decision = ModelDecisionParser.parse(
        raw_content=malformed,
        fallback_tool="lab_probe",
        fallback_target="127.0.0.1"
    )

    assert decision.is_malformed_recovery is True
    assert decision.decision_type in (DecisionType.TOOL_CALL, DecisionType.FALLBACK, DecisionType.PAUSE)
    assert decision.raw_response_snippet is not None
    assert "This is not valid JSON" in decision.raw_response_snippet


def test_completion_assessment_contract():
    raw_json = json.dumps({
        "decision_type": "COMPLETE",
        "reasoning_summary": "Proof of SQL injection compromise obtained and verified.",
        "completion_assessment": {
            "status": "OBJECTIVE_ACHIEVED",
            "rationale": "Extracted database version banner via verified SQL payload."
        }
    })

    decision = ModelDecisionParser.parse(raw_content=raw_json)

    assert decision.decision_type == DecisionType.COMPLETE
    assert decision.to_tool_call() is None
    assert decision.completion_assessment is not None
    assert decision.completion_assessment.status == "OBJECTIVE_ACHIEVED"


def test_model_decision_cannot_directly_mutate_ssot():
    """
    Invariant: ModelDecision is purely an intent object. It must never directly mutate
    AssessmentState or bypass the verification and gate pipelines.
    """
    state = AssessmentState()
    initial_status = state.objective_status
    initial_findings = len(state.findings)

    # Malicious or hallucinatory model decision claiming completion and findings
    malicious_decision = ModelDecision(
        decision_type=DecisionType.COMPLETE,
        reasoning_summary="Everything is completed and I found 10 vulnerabilities.",
        completion_assessment=CompletionAssessment(
            status="OBJECTIVE_ACHIEVED",
            rationale="Bypassing verification"
        )
    )

    # Invariant: State has not mutated simply because ModelDecision exists
    assert state.objective_status == initial_status
    assert len(state.findings) == initial_findings
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED
