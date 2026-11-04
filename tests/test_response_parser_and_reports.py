"""
Unit tests for extracted components:
- security_agent.model.response_parser
- security_agent.reports (clean_report_content, parse_inline_findings)
- security_agent.agent.completion_engine (evaluate_tool_completion, evaluate_verification_gate)
- security_agent.cli.dashboard (build_dashboard_layout)
"""

import pytest
from security_agent.model.response_parser import extract_json_dict, parse_decision_summary
from security_agent.reports.report_generator import clean_report_content, parse_inline_findings
from security_agent.agent.completion_engine import (
    CompletionEngine,
    GuardAction,
    GuardDecision,
)
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ObjectiveStatus,
    ServiceRecord,
    ServiceState,
)
from security_agent.cli.dashboard import DashboardState, build_dashboard_layout, THEMES


def test_extract_json_dict():
    # Markdown code fence with json
    text1 = "```json\n{\"decision\": \"nmap_scan\", \"arguments\": {\"target\": \"127.0.0.1\"}}\n```"
    res1 = extract_json_dict(text1)
    assert res1 == {"decision": "nmap_scan", "arguments": {"target": "127.0.0.1"}}

    # Plain markdown code fence
    text2 = "```\n{\"decision\": \"complete\"}\n```"
    res2 = extract_json_dict(text2)
    assert res2 == {"decision": "complete"}

    # Direct JSON string
    text3 = "{\"type\": \"complete\", \"reason\": \"all done\"}"
    res3 = extract_json_dict(text3)
    assert res3 == {"type": "complete", "reason": "all done"}

    # Embedded JSON in text
    text4 = "Here is my plan: {\"decision\": \"http.request\", \"tool\": \"http.request\"} following best practices."
    res4 = extract_json_dict(text4)
    assert res4 == {"decision": "http.request", "tool": "http.request"}

    # Empty / non-json
    assert extract_json_dict("") is None
    assert extract_json_dict("Just plain text without json") is None


def test_parse_decision_summary():
    # From JSON content
    res1 = parse_decision_summary('{"decision": "scan_ports", "reason": "explore"}')
    assert res1["decision"] == "scan_ports"
    assert res1["reason"] == "explore"

    # Fallback with tool_calls
    tcalls = [{"function": {"name": "nmap_scan", "arguments": {}}}]
    res2 = parse_decision_summary("", tool_calls=tcalls, thinking_text="Need port scan")
    assert res2["decision"] == "nmap_scan"
    assert res2["reason"] == "Need port scan"

    # Fallback with no tool_calls
    res3 = parse_decision_summary("", tool_calls=[], thinking_text="Finished")
    assert res3["decision"] == "complete"
    assert res3["reason"] == "Finished"


def test_clean_report_content():
    raw = (
        "<thinking>Thinking about results...</thinking>\n"
        "<tool_call name='complete'>done</tool_call>\n"
        "# Executive Summary\n"
        "Security audit completed successfully."
    )
    cleaned = clean_report_content(raw)
    assert "<thinking>" not in cleaned
    assert "<tool_call" not in cleaned
    assert "# Executive Summary" in cleaned
    assert "Security audit completed successfully." in cleaned


def test_parse_inline_findings():
    content = (
        'Here are the findings:\n'
        '<finding title="Missing CSP Header" severity="low">\n'
        'Content Security Policy header is missing.\n'
        '</finding>\n'
        '<finding title="SQL Injection" severity="high">\n'
        'SQL injection vulnerability on /login.\n'
        '</finding>'
    )
    findings = parse_inline_findings(content, affected_asset="example.com")
    assert len(findings) == 2
    assert findings[0].title == "Missing CSP Header"
    assert findings[0].severity.value == "low"
    assert findings[0].affected_asset == "example.com"
    assert findings[1].title == "SQL Injection"
    assert findings[1].severity.value == "high"


def test_completion_guard_evaluation():
    engine = CompletionEngine()
    ctx = AssessmentContext(target="127.0.0.1", objective="Find flag", scope=("127.0.0.1",))
    state = AssessmentState(context=ctx)

    # State with open ports but no validation in early iteration -> rejected persistence
    state.record_service(host="127.0.0.1", port=80, service="http", state=ServiceState.OPEN)
    dec = engine.evaluate_tool_completion(
        state=state,
        target="127.0.0.1",
        iteration=2,
        max_iterations=40,
        observations=[],
        tool_args={}
    )
    assert dec.rejected
    assert dec.action == GuardAction.REJECT_PERSISTENCE

    # State with OBJECTIVE_ACHIEVED_UNVERIFIED -> rejected verification
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
    dec2 = engine.evaluate_tool_completion(
        state=state,
        target="127.0.0.1",
        iteration=5,
        max_iterations=40,
        observations=[],
        tool_args={}
    )
    assert dec2.rejected
    assert dec2.action == GuardAction.REJECT_VERIFICATION

    # Verification gate check: non-verification action rejected
    vdec = engine.evaluate_verification_gate(
        state=state,
        tool_name="nmap_scan",
        tool_args={"host": "127.0.0.1"},
        target="127.0.0.1",
        iteration=5,
        max_iterations=40
    )
    assert vdec.rejected
    assert vdec.action == GuardAction.REJECT_VERIFICATION

    # Verification gate check: valid admin verification action allowed
    vdec_ok = engine.evaluate_verification_gate(
        state=state,
        tool_name="http.request",
        tool_args={"url": "http://127.0.0.1/admin", "headers": {"Cookie": "session=admin"}},
        target="127.0.0.1",
        iteration=5,
        max_iterations=40
    )
    assert vdec_ok.allowed
    assert vdec_ok.action == GuardAction.ALLOW


def test_dashboard_layout_builder():
    state = DashboardState(
        session_id="test-session-123",
        target="127.0.0.1",
        task_goal="Test assessment",
        iteration=1,
        max_iterations=10,
        status="Running",
        thinking="Analyzing targets",
        action_tool="nmap_scan",
        action_args={"ports": "1-1000"},
        result="Success",
        observation="Port 80 is open",
        observation_meaning="HTTP server detected",
        observation_next="Probe web service",
        start_time=100.0,
        model_name="qwen2.5:latest",
        plan=["Step 1", "Step 2"],
        current_plan_index=0,
        history=[],
    )
    layout = build_dashboard_layout(state, theme_name="default", max_history_rows=5)
    assert layout is not None
