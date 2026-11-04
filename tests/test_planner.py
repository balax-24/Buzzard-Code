"""
Unit tests for the Planner module (agent/planner.py).

Verifies:
1. Valid tool selection and XML/JSON parsing
2. Malformed model output handling
3. Missing arguments and default fallback mapping
4. Out-of-scope target candidate validation
5. Placeholder target rejection
6. Ineligible tool rejection (e.g. unverified service exploitation)
7. Duplicate action / loop detection
8. Planner timeout and prioritized auto-recovery
9. Deterministic fallback generation
10. Compact context construction and message history compaction
"""

import pytest
from typing import Dict, Any

from agent.planner import Planner, PlannerDecision
from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ServiceRecord,
    HTTPEndpointRecord,
    HTTPState,
    ServiceState,
    VerificationStatus,
)


@pytest.fixture
def planner():
    return Planner(max_planner_time=45.0)


@pytest.fixture
def base_state():
    ctx = AssessmentContext(
        target="127.0.0.1",
        scope={"127.0.0.1", "localhost"},
        objective="Vulnerability Assessment"
    )
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.ASSET_DISCOVERY
    return state


def test_valid_xml_tool_selection(planner):
    """Verifies XML tool call parsing with arguments and thinking traces."""
    content = """
    <thinking>We should run a port scan on localhost.</thinking>
    <tool_call name="nmap_scan">
      <host>127.0.0.1</host>
      <ports>1-1000</ports>
    </tool_call>
    """
    tool_name, args, thinking = planner.parse_xml_tool_call(content)
    assert tool_name == "nmap_scan"
    assert args == {"host": "127.0.0.1", "ports": "1-1000"}
    assert "port scan" in thinking


def test_valid_json_decision_resolution(planner):
    """Verifies parsing of structured JSON decision payloads."""
    content = '{"tool": "whatweb_scan", "arguments": {"url": "http://127.0.0.1:8080"}, "reason": "Fingerprint HTTP"}'
    tool_calls, summary = planner.resolve_decision(content)
    assert len(tool_calls) == 1
    assert tool_calls[0]["function"]["name"] == "whatweb_scan"
    assert tool_calls[0]["function"]["arguments"]["url"] == "http://127.0.0.1:8080"
    assert summary["decision"] == "whatweb_scan"


def test_malformed_model_output(planner):
    """Verifies graceful handling of non-JSON, non-XML malformed output."""
    raw = "I am not sure what to do next without structured tags {broken json"
    tool_calls, summary = planner.resolve_decision(raw)
    assert len(tool_calls) == 0
    assert summary["decision"] == "complete"
    assert "Analyzing next step" in summary["reason"] or raw in summary["reason"]


def test_missing_arguments_mapping(planner):
    """Verifies that single raw parameter values are mapped to primary tool arguments."""
    content = """
    <tool_call name="browser.open">
      http://127.0.0.1:5000
    </tool_call>
    """
    tool_name, args, _ = planner.parse_xml_tool_call(content)
    assert tool_name == "browser.open"
    assert args.get("url") == "http://127.0.0.1:5000"


def test_out_of_scope_target_validation(planner, base_state):
    """Verifies that candidate actions against out-of-scope targets are strictly rejected."""
    is_valid, reason, _ = planner.validate_candidate_action(
        tool_name="nmap_scan",
        arguments={"host": "192.168.1.50"},
        state=base_state
    )
    assert is_valid is False
    assert "OUT OF SCOPE" in reason.upper() or "ACTION BLOCKED" in reason.upper() or "TARGET_OUT_OF_SCOPE" in reason


def test_placeholder_target_rejection(planner, base_state):
    """Verifies that literal placeholders like <target> or target.com are rejected."""
    is_valid, reason, _ = planner.validate_candidate_action(
        tool_name="http_probe",
        arguments={"target": "<target>"},
        state=base_state
    )
    assert is_valid is False
    assert "ACTION BLOCKED" in reason or "ACTION REJECTED" in reason or "placeholder" in reason.lower()


def test_ineligible_tool_without_evidence(planner, base_state):
    """Verifies that HTTP-specific tools are rejected if the port was confirmed closed/connection refused."""
    # Record closed port 8080
    base_state.record_service(
        host="127.0.0.1",
        port=8080,
        service="http",
        state=ServiceState.CLOSED,
        verification_status=VerificationStatus.VERIFIED
    )
    base_state.record_http_probe(
        url="http://127.0.0.1:8080",
        state=HTTPState.REFUSED
    )

    is_valid, reason, _ = planner.validate_candidate_action(
        tool_name="whatweb_scan",
        arguments={"url": "http://127.0.0.1:8080"},
        state=base_state
    )
    assert is_valid is False
    assert "CONNECTION REFUSED" in reason or "CLOSED" in reason or "ACTION BLOCKED" in reason


def test_planner_timeout_and_synthetic_response(planner, base_state):
    """Verifies that planner timeout produces valid synthetic tool call and fast-path decision."""
    # When no services are present, should fallback to port discovery on canonical target
    resp_payload, decision = planner.handle_timeout(
        state=base_state,
        target="127.0.0.1",
        native_tools=True
    )
    assert decision.is_fallback is True
    assert decision.tool_name == "nmap_scan"
    assert decision.arguments.get("host") == "127.0.0.1"
    assert "message" in resp_payload
    assert len(resp_payload["message"]["tool_calls"]) == 1
    assert resp_payload["message"]["tool_calls"][0]["function"]["name"] == "nmap_scan"


def test_deterministic_fallback_on_unambiguous_state(planner, base_state):
    """Verifies deterministic fallback selection when open uninvestigated services exist."""
    base_state.record_service(
        host="127.0.0.1",
        port=80,
        service="http",
        state=ServiceState.OPEN,
        verification_status=VerificationStatus.VERIFIED
    )
    det_action = base_state.get_deterministic_next_action()
    assert det_action is not None
    assert det_action["tool"] in ("whatweb_scan", "http_probe")
    assert "80" in str(det_action["args"])


def test_compact_context_construction(planner, base_state):
    """Verifies rolling message window compaction and state injection."""
    messages = [
        {"role": "system", "content": "You are a security agent."},
        {"role": "user", "content": "Assess 127.0.0.1"},
        {"role": "assistant", "content": "Step 1", "thinking": "Deep historical thought..."},
        {"role": "user", "content": "Result 1"},
        {"role": "assistant", "content": "Step 2", "thinking": "Deep historical thought 2..."},
        {"role": "user", "content": "Result 2"},
        {"role": "assistant", "content": "Step 3"},
        {"role": "user", "content": "Result 3"},
    ]
    compact = planner.compact_message_history(messages, state=base_state)
    assert len(compact) < len(messages)
    assert compact[0]["content"] == "You are a security agent."
    assert compact[1]["content"] == "Assess 127.0.0.1"
    # State status injected
    assert any("=== CANONICAL ASSESSMENT PLANNER CONTEXT ===" in str(m.get("content")) for m in compact)


def test_prompt_question_interception(planner, base_state):
    """Verifies that model questions asking user for target/objective are intercepted and auto-dispatched."""
    content = "Could you please specify what is the target IP or host for this scan?"
    decision = planner.check_target_prompt_interception(
        content=content,
        state=base_state,
        target="127.0.0.1",
        task_goal="Perform vulnerability assessment",
        iteration=1
    )
    assert decision is not None
    assert decision.tool_name == "nmap_scan"
    assert decision.is_fallback is True
