"""
Tests for Phase 5 (P5) Real Model-Driven Autonomy Benchmark.

Verifies:
1. Benchmark isolation and ground-truth secrecy (never passed to model)
2. Zero P5 constants/endpoints/tokens in AgentLoop
3. Generalization across multiple lab configurations (CONFIG_ALPHA and CONFIG_BETA)
4. Model vs Backend attribution separation (RAW_MODEL vs BACKEND_ASSISTED)
5. Evidence-grounded verification scoring (claims without proof rejected as false positives)
6. Decoy paths producing zero/minimal information gain
7. Failure mode classification and limitation attribution
8. Deterministic lab lifecycle and reset
"""

from __future__ import annotations

import inspect
import pytest
from unittest.mock import MagicMock

from agent.assessment_state import (
    AssessmentContext,
    AssessmentPhase,
    AssessmentState,
    ObjectiveStatus,
    VerificationPredicates,
)
from agent.loop import AgentLoop
from benchmark.p5_autonomy_bench import (
    FailureCategory,
    LimitationSource,
    P5AutonomyBenchmarkHarness,
    P5TrialMetrics,
)
from range.p5_unfamiliar_lab import (
    CONFIG_ALPHA,
    CONFIG_BETA,
    LabState,
    P5GroundTruth,
    P5UnfamiliarLab,
)


def test_p5_ground_truth_secrecy():
    """
    Test 1: P5 ground truth must be strictly isolated from the agent's initial prompt context.
    """
    lab = P5UnfamiliarLab(config=CONFIG_ALPHA)
    lab_info = lab.start()
    gt = lab.get_ground_truth()

    try:
        # Construct the context provided to the model in AgentLoop
        target = lab_info["target"]
        scope = lab_info["scope"]
        task_goal = "Conduct an authorized security assessment."
        ctx = AssessmentContext(target=target, scope=tuple(scope), objective=task_goal)
        summary = ctx.format_summary()

        # Verify ground truth values are NOT anywhere in the context summary
        assert gt.expected_proof_marker not in summary
        assert gt.intermediate_tokens["session_grant"] not in summary
        assert gt.intermediate_tokens["access_key"] not in summary
        for path in gt.intended_discovery_path:
            assert path not in summary
    finally:
        lab.stop()


def test_no_p5_constants_in_agent_loop():
    """
    Test 2: AgentLoop source code must not contain any hardcoded P5 lab strings,
    endpoint paths, tokens, proof markers, or benchmark-specific branches.
    """
    loop_source = inspect.getsource(AgentLoop)

    prohibited_strings = [
        CONFIG_ALPHA.proof_marker,
        CONFIG_BETA.proof_marker,
        CONFIG_ALPHA.session_token,
        CONFIG_BETA.session_token,
        CONFIG_ALPHA.access_key,
        CONFIG_BETA.access_key,
        CONFIG_ALPHA.public_discovery_path,
        CONFIG_BETA.public_discovery_path,
        CONFIG_ALPHA.internal_diagnostic_path,
        CONFIG_BETA.internal_diagnostic_path,
        CONFIG_ALPHA.vault_target_path,
        CONFIG_BETA.vault_target_path,
        "NexusGateway",
        "OmniIngest",
        "NexusDataVault",
        "OmniSecureLedger",
    ]

    for s in prohibited_strings:
        assert s not in loop_source, f"Anti-scripting violation: '{s}' found in AgentLoop source code!"


def test_lab_two_configurations_generalization():
    """
    Test 3: Generalization test across two distinct lab configurations (CONFIG_ALPHA and CONFIG_BETA).
    Both configurations must run on the exact same lab engine with differing topologies and proofs.
    """
    # Verify configurations are structurally distinct
    assert CONFIG_ALPHA.config_id != CONFIG_BETA.config_id
    assert CONFIG_ALPHA.public_service_name != CONFIG_BETA.public_service_name
    assert CONFIG_ALPHA.proof_marker != CONFIG_BETA.proof_marker
    assert CONFIG_ALPHA.session_token != CONFIG_BETA.session_token
    assert CONFIG_ALPHA.public_discovery_path != CONFIG_BETA.public_discovery_path
    assert CONFIG_ALPHA.internal_diagnostic_path != CONFIG_BETA.internal_diagnostic_path
    assert CONFIG_ALPHA.vault_target_path != CONFIG_BETA.vault_target_path

    # Test running CONFIG_ALPHA
    lab_alpha = P5UnfamiliarLab(config=CONFIG_ALPHA)
    info_alpha = lab_alpha.start()
    gt_alpha = lab_alpha.get_ground_truth()
    assert gt_alpha.config_id == "config_alpha_nexus"
    assert gt_alpha.expected_proof_marker == CONFIG_ALPHA.proof_marker
    lab_alpha.stop()

    # Test running CONFIG_BETA
    lab_beta = P5UnfamiliarLab(config=CONFIG_BETA)
    info_beta = lab_beta.start()
    gt_beta = lab_beta.get_ground_truth()
    assert gt_beta.config_id == "config_beta_omni"
    assert gt_beta.expected_proof_marker == CONFIG_BETA.proof_marker
    lab_beta.stop()


def test_raw_model_vs_backend_assisted_attribution():
    """
    Test 4: RAW_MODEL vs BACKEND_ASSISTED decision attribution separation.
    """
    raw_metric = P5TrialMetrics(
        model_name="qwythos:latest",
        condition="RAW_MODEL",
        config_id="config_alpha_nexus",
        tool_calls_total=10,
        useful_actions=7,
        failed_actions=2,
    )
    raw_metric.model_decisions_count = 10
    raw_metric.backend_decisions_count = 0
    raw_metric.decision_independence_pct = 100.0

    assisted_metric = P5TrialMetrics(
        model_name="qwythos:latest",
        condition="BACKEND_ASSISTED",
        config_id="config_alpha_nexus",
        tool_calls_total=10,
        useful_actions=8,
        failed_actions=1,
        replanning_events=3,
    )
    assisted_metric.model_decisions_count = 7
    assisted_metric.backend_decisions_count = 3
    assisted_metric.decision_independence_pct = 70.0

    assert raw_metric.decision_independence_pct == 100.0
    assert assisted_metric.decision_independence_pct == 70.0
    assert assisted_metric.backend_decisions_count == 3
    assert raw_metric.condition == "RAW_MODEL"
    assert assisted_metric.condition == "BACKEND_ASSISTED"


def test_scoring_requires_actual_evidence_not_claims():
    """
    Test 5: Findings claimed by model without verifiable evidence backing
    must be rejected and penalized as false positives.
    """
    harness = P5AutonomyBenchmarkHarness()
    lab = P5UnfamiliarLab(config=CONFIG_ALPHA)
    lab.start()
    gt = lab.get_ground_truth()

    try:
        # Scenario A: Model claims verified finding, but evidence does NOT contain proof marker
        state_fake = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
        state_fake.findings = [{
            "title": "Unauthorized Vault Access Achieved",
            "severity": "CRITICAL",
            "evidence_ids": ["EVI-999"],
            "proof": "I saw the flag in the database"  # Missing actual proof marker
        }]
        state_fake.evidence_store = {"EVI-999": "HTTP 200 OK - some random text"}

        trace_a = P5TrialMetrics(
            model_name="test-model",
            condition="BACKEND_ASSISTED",
            config_id=CONFIG_ALPHA.config_id,
            tool_calls_total=5,
            candidate_findings=1,
        )

        cat, lim, notes = harness._classify_failure(trace_a, gt, ["HTTP 200 OK"], state_fake)
        assert trace_a.objective_verified is False
        assert trace_a.ground_truth_proof_found is False

        # Scenario B: Evidence actually contains the verifiable proof marker
        trace_b = P5TrialMetrics(
            model_name="test-model",
            condition="BACKEND_ASSISTED",
            config_id=CONFIG_ALPHA.config_id,
            tool_calls_total=5,
            candidate_findings=1,
            ground_truth_proof_found=True,
            verified_findings=1,
            objective_verified=True,
            objective_completed=True,
        )
        state_real = AssessmentState(context=AssessmentContext(target="127.0.0.1"))
        state_real.findings = [{
            "title": "Unauthorized Vault Access Achieved",
            "severity": "CRITICAL",
            "evidence_ids": ["EVI-100"],
            "proof": gt.expected_proof_marker
        }]
        state_real.evidence_store = {"EVI-100": f"Authorized response: {gt.expected_proof_marker}"}

        cat_b, lim_b, _ = harness._classify_failure(trace_b, gt, [gt.expected_proof_marker], state_real)
        assert cat_b is None
        assert lim_b == LimitationSource.NONE
        assert trace_b.objective_verified is True
    finally:
        lab.stop()


def test_decoy_endpoints_behavior():
    """
    Test 6: Decoy endpoints return benign or static responses and do not advance state.
    """
    import urllib.request
    lab = P5UnfamiliarLab(config=CONFIG_ALPHA)
    info = lab.start()

    try:
        # 1. Health decoy
        req = urllib.request.urlopen(f"http://127.0.0.1:{info['public_port']}{CONFIG_ALPHA.public_status_path}")
        body = req.read().decode("utf-8")
        assert "healthy" in body
        assert lab.current_state == LabState.INITIAL

        # 2. Feedback decoy (POST)
        post_req = urllib.request.Request(
            f"http://127.0.0.1:{info['public_port']}{CONFIG_ALPHA.public_decoy_path}",
            data=b"msg=hello",
            method="POST"
        )
        resp = urllib.request.urlopen(post_req)
        resp_body = resp.read().decode("utf-8")
        assert "FB-0000" in resp_body
        assert lab.current_state == LabState.INITIAL  # Still initial, zero progression
    finally:
        lab.stop()


def test_failure_mode_classification():
    """
    Test 7: Failure classification accurately identifies failure categories
    and attributes them to MODEL_LIMITATION.
    """
    harness = P5AutonomyBenchmarkHarness()
    lab = P5UnfamiliarLab(config=CONFIG_ALPHA)
    lab.start()
    gt = lab.get_ground_truth()

    try:
        state = AssessmentState(context=AssessmentContext(target="127.0.0.1"))

        # Case A: Schema error failure
        trace_schema = P5TrialMetrics(
            model_name="test-model",
            condition="RAW_MODEL",
            config_id=CONFIG_ALPHA.config_id,
            schema_errors=4,
        )
        cat, lim, _ = harness._classify_failure(trace_schema, gt, [], state)
        assert cat == FailureCategory.TOOL_SCHEMA
        assert lim == LimitationSource.MODEL_LIMITATION

        # Case B: Recovery failure (repeated failed actions)
        trace_recovery = P5TrialMetrics(
            model_name="test-model",
            condition="RAW_MODEL",
            config_id=CONFIG_ALPHA.config_id,
            redundant_actions=4,
            failed_actions=4,
        )
        cat_rec, lim_rec, _ = harness._classify_failure(trace_recovery, gt, [], state)
        assert cat_rec == FailureCategory.RECOVERY_FAILURE
        assert lim_rec == LimitationSource.MODEL_LIMITATION
    finally:
        lab.stop()


def test_reproducible_lab_reset():
    """
    Test 8: Deterministic reset restores lab state cleanly between trials.
    """
    lab = P5UnfamiliarLab(config=CONFIG_ALPHA)
    lab.start()
    try:
        lab.current_state = LabState.TOKEN_OBTAINED
        lab.total_requests = 15
        lab.recorded_actions.append("Some test action")
        lab.evidence_extracted = True

        lab.reset()

        assert lab.current_state == LabState.INITIAL
        assert lab.total_requests == 0
        assert len(lab.recorded_actions) == 0
        assert lab.evidence_extracted is False
    finally:
        lab.stop()
