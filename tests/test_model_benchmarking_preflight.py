"""
Unit and integration tests for Model Benchmarking, Preflight Validator,
Assessment Logger, Event Stream, and State Machine.
"""

import pytest
import os
import json
from unittest.mock import patch, MagicMock
from events.agent_event import AgentEvent, AgentEventType
from storage.assessment_logger import AssessmentLogger, summarize_tool_output
from sandbox.preflight import SandboxPreflightValidator, CheckResult
from sandbox.container import BlockedSandbox
from agent.assessment_state import AssessmentStateMachine, AssessmentPhase
from model.discovery import ModelDiscoverer, ModelCapabilities
from benchmark.runner import ModelBenchmarkRunner, ModelBenchmarkResult, BenchmarkScenario


def test_agent_event_formatting():
    event = AgentEvent(
        event_type=AgentEventType.TOOL_START,
        summary="Executing network scan",
        tool="network_recon"
    )
    formatted = event.format_cli()
    assert "TOOL" in formatted
    assert "Selected: network_recon" in formatted or "Executing network scan" in formatted

    res_event = AgentEvent(
        event_type=AgentEventType.TOOL_RESULT,
        summary="3 services discovered",
        tool="network_recon",
        duration_s=1.24,
        result_summary="3 services discovered"
    )
    res_formatted = res_event.format_cli()
    assert "RESULT" in res_formatted
    assert "1.2s" in res_formatted
    assert "3 services discovered" in res_formatted


def test_summarize_tool_output():
    out = "PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open https"
    summary = summarize_tool_output("network.enumerate", out)
    assert "3 lines returned" in summary or "80/tcp" in summary or "Status: OK" in summary

    error_out = "Connection refused to host"
    summary_err = summarize_tool_output("http_request", error_out, exit_code=1)
    assert "Connection refused" in summary_err or "exit 1" in summary_err


def test_assessment_logger(tmp_path):
    logger = AssessmentLogger(session_id="test-session-101", base_dir=str(tmp_path))
    logger.write_metadata({"target": "http://127.0.0.1:8080", "model": "k3-sec:latest"})
    
    event = AgentEvent(AgentEventType.TASK, "Security assessment initiated")
    logger.log_event(event)

    logger.log_tool_call(
        tool="http_request",
        arguments={"url": "http://127.0.0.1:8080"},
        raw_output="HTTP/1.1 200 OK\nServer: LabApp",
        duration_s=0.45,
        exit_code=0
    )

    logger.write_findings([{"id": "VULN-001", "title": "Missing Security Headers", "severity": "low"}])
    report_file = logger.write_final_report("# Test Report\nEverything verified.")

    assert os.path.exists(logger.metadata_file)
    assert os.path.exists(logger.timeline_file)
    assert os.path.exists(logger.tool_calls_file)
    assert os.path.exists(logger.findings_file)
    assert os.path.exists(report_file)


def test_preflight_validator_fail_closed():
    validator = SandboxPreflightValidator()
    with patch("shutil.which", return_value=None):
        all_passed, results = validator.run_all_checks()
        assert all_passed is False
        docker_installed = next(r for r in results if r.name == "Docker installed")
        assert docker_installed.passed is False


def test_blocked_sandbox_execution():
    sandbox = BlockedSandbox("Docker daemon is unreachable.")
    res = sandbox.execute("whoami")
    assert res["exit_code"] == 126
    assert "Sandbox unavailable — execution disabled" in res["stderr"]
    assert res["sandboxed"] is False


def test_assessment_state_machine_transitions_and_retry_limits():
    sm = AssessmentStateMachine()
    assert sm.current_phase == AssessmentPhase.INITIALIZE

    sm.transition(AssessmentPhase.SCOPE, "Define authorized targets")
    assert sm.current_phase == AssessmentPhase.SCOPE
    sm.transition(AssessmentPhase.RECON, "Begin network discovery")
    assert sm.current_phase == AssessmentPhase.RECON
    sm.transition(AssessmentPhase.ANALYZE, "Inspect open services")
    assert sm.current_phase == AssessmentPhase.ANALYZE
    sm.transition(AssessmentPhase.HYPOTHESIS, "Identify possible vulnerability")
    assert sm.current_phase == AssessmentPhase.HYPOTHESIS
    sm.transition(AssessmentPhase.TEST, "Execute proof of concept")
    assert sm.current_phase == AssessmentPhase.TEST

    # Test failure retry bounds
    tool_name = "nuclei_scan"
    action1, phase1 = sm.record_tool_failure(tool_name, "Timeout connecting to host")
    assert "Retry attempt 1" in action1
    assert phase1 == AssessmentPhase.TEST

    action2, phase2 = sm.record_tool_failure(tool_name, "Timeout connecting to host")
    assert "Retry attempt 2" in action2

    # Third failure exceeds max retries -> shifts to ANALYZE
    action3, phase3 = sm.record_tool_failure(tool_name, "Timeout connecting to host")
    assert "alternative" in action3.lower()
    assert sm.current_phase == AssessmentPhase.ANALYZE
    assert sm.should_retry_tool(tool_name) is False


def test_model_capabilities_and_benchmark():
    runner = ModelBenchmarkRunner()
    res = ModelBenchmarkResult(
        model_name="k3-sec:latest",
        tasks_attempted=3,
        tasks_completed=3,
        tool_calls_total=4,
        tool_calls_valid=4,
        tool_selection_matches=3,
        tool_selection_opportunities=3,
        recoveries_attempted=0,
        recoveries_succeeded=0,
        total_runtime_s=12.5
    )
    assert res.completion_pct == 100.0
    assert res.tool_accuracy_pct == 100.0
    assert res.validity_pct == 100.0
    assert res.recovery_pct == 100.0
