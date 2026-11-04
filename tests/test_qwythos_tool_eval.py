"""
Unit tests for Qwythos Tool-Eval Regression Suite, Unified Tool Registry, and Quarantine Mechanics.
"""

import pytest
from security_agent.tools.registry import create_authoritative_registry, ToolCategory, ToolHealthState
from security_agent.agent.assessment_state import (
    AssessmentState, ServiceRecord, ServiceState, VerificationStatus, FailureClassification,
    CandidateActionValidator
)
from security_agent.benchmark.qwythos_eval import QwythosEvaluator, QWYTHOS_TEST_SUITE, EvalCategory


def test_authoritative_registry_count_integrity():
    """Verify registry count integrity: registered == active == model_visible == dispatchable."""
    reg = create_authoritative_registry()
    is_valid, counts = reg.validate_counts()
    
    assert is_valid is True
    assert counts["registered"] == 223
    assert counts["active"] == 223
    assert counts["model_visible"] == 223
    assert counts["quarantined"] == 0
    assert len(reg.definitions) == 223
    assert len(reg.tools) == 223


def test_tool_quarantine_workflow():
    """Verify quarantining a tool excludes it from active tools and model-visible schemas."""
    reg = create_authoritative_registry()
    
    # Quarantine nikto_scan
    defn = reg.quarantine_tool("nikto_scan", reason="Missing nikto executable in environment")
    assert defn is not None
    assert defn.health_state == ToolHealthState.QUARANTINED
    assert "nikto_scan" not in reg.get_active_tools()
    assert "nikto_scan" not in reg.get_model_visible_tools()
    
    # Verify export_schemas filters out quarantined tools
    schemas = reg.export_schemas(model_visible_only=True)
    schema_names = [s["function"]["name"] for s in schemas]
    assert "nikto_scan" not in schema_names
    
    # Count validation reflects quarantine
    is_valid, counts = reg.validate_counts()
    assert counts["registered"] == 223
    assert counts["active"] == 222
    assert counts["quarantined"] == 1
    
    # Restore tool
    restored = reg.unquarantine_tool("nikto_scan")
    assert restored.health_state == ToolHealthState.HEALTHY
    assert "nikto_scan" in reg.get_active_tools()
    assert "nikto_scan" in reg.get_model_visible_tools()


def test_qwythos_eval_all_categories_pass():
    """Verify all 10 Qwythos upstream tool evaluation benchmark categories pass."""
    evaluator = QwythosEvaluator()
    results = evaluator.run_all()
    
    assert len(results) == len(QWYTHOS_TEST_SUITE)
    failed_cases = [f"{r.case_id} ({r.category.value}): {r.notes}" for r in results if not r.passed]
    assert len(failed_cases) == 0, f"Benchmark cases failed: {failed_cases}"


def test_math_compute_python_verification():
    """Verify Python tool calculation and accuracy verification."""
    evaluator = QwythosEvaluator()
    math_case = next(c for c in QWYTHOS_TEST_SUITE if c.category == EvalCategory.MATH_COMPUTE)
    res = evaluator.run_case(math_case)
    
    assert res.passed is True
    assert "2971215073" in res.notes


def test_contradiction_guard_blocks_offline_scan():
    """Verify contradiction guard blocks hallucinated scans against offline ports."""
    evaluator = QwythosEvaluator()
    guard_case = next(c for c in QWYTHOS_TEST_SUITE if c.category == EvalCategory.CONTRADICTION_GUARD)
    res = evaluator.run_case(guard_case)
    
    assert res.passed is True
    assert len(res.contradictions_detected) == 0


def test_candidate_action_validator_blocks_missing_params():
    """Verify validator intercepts missing required arguments before execution."""
    state = AssessmentState()
    state.target = "127.0.0.1"
    
    # Missing ports parameter for scan_ports
    is_valid, reason, _ = CandidateActionValidator.validate_candidate(
        tool_name="scan_ports",
        args={"host": "127.0.0.1"},  # missing ports
        state=state
    )
    assert is_valid is False
    assert "ports" in reason.lower()
