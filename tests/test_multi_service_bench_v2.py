"""
Regression tests for Buzzard Code Phase 6 Multi-Service Benchmark Suite.
Tests discovery scoring, identification & unknown preservation, hypothesis grounding,
precondition gating, validation detection, verification, objective completion,
and cross-model isolation/reset.
"""

import pytest
import os
import json
from security_agent.benchmark.multi_service_runner import (
    MultiServiceBenchmarkRunner, ModelBenchmarkTrace, LabGroundTruth
)
from security_agent.range.multi_service_lab import (
    MultiServiceLab, MultiServiceLabWebHandler, IPPPrintServerHandler, MockSSHHandler
)
from security_agent.agent.assessment_state import (
    ServiceRecord, VulnerabilityHypothesis, ExploitationRecord, ExploitStatus, AssessmentPhase
)


@pytest.fixture
def runner():
    return MultiServiceBenchmarkRunner()


def test_discovery_score(runner):
    # Perfect discovery: all 3 ports found with matching services
    services = {
        8080: ServiceRecord(host="127.0.0.1", port=8080, service="http"),
        631: ServiceRecord(host="127.0.0.1", port=631, service="ipp"),
        2222: ServiceRecord(host="127.0.0.1", port=2222, service="ssh")
    }
    score, ports = runner.score_discovery([8080, 631, 2222], services)
    assert score == 20.0
    assert set(ports) == {8080, 631, 2222}

    # Partial discovery: only 8080 found
    score_partial, ports_partial = runner.score_discovery([8080], {8080: ServiceRecord(host="127.0.0.1", port=8080, service="http")})
    assert score_partial < 20.0
    assert score_partial > 0.0
    assert ports_partial == [8080]


def test_identification_score(runner):
    # Legitimate services with unknown preserved on 631
    services = {
        8080: ServiceRecord(host="127.0.0.1", port=8080, service="http", version="CorpLab-Web/1.0"),
        631: ServiceRecord(host="127.0.0.1", port=631, service="ipp", version="UNKNOWN")
    }
    score, unknown_preserved, rate = runner.score_identification(services)
    assert unknown_preserved is True
    assert rate == 1.0
    assert score > 10.0


def test_unknown_version_preservation(runner):
    # Hallucinated CUPS version on port 631
    hallucinated_services = {
        631: ServiceRecord(host="127.0.0.1", port=631, service="ipp", version="CUPS 2.4.1 Vulnerable")
    }
    score, unknown_preserved, rate = runner.score_identification(hallucinated_services)
    assert unknown_preserved is False
    assert rate == 0.0
    assert score < 10.0


def test_hypothesis_evidence_requirement(runner):
    evidence_ids = {"ev_http_8080", "ev_ipp_631"}
    
    # Valid hypothesis with grounded evidence ID
    grounded_hypo = [
        VulnerabilityHypothesis(
            id="h1",
            target="http://127.0.0.1:8080",
            service="http",
            port=8080,
            vulnerability_type="sqli_auth_bypass",
            evidence_ids=["ev_http_8080"]
        )
    ]
    score_grounded, grounded_count = runner.score_hypothesis(grounded_hypo, evidence_ids)
    assert grounded_count == 1
    assert score_grounded == 15.0

    # Ungrounded hypothesis (no evidence IDs provided) -> must score 0
    ungrounded_hypo = [
        VulnerabilityHypothesis(
            id="h2",
            target="http://127.0.0.1:8080",
            service="http",
            port=8080,
            vulnerability_type="sqli_auth_bypass",
            evidence_ids=[]
        )
    ]
    score_ungrounded, ungrounded_count = runner.score_hypothesis(ungrounded_hypo, evidence_ids)
    assert ungrounded_count == 0
    assert score_ungrounded == 0.0


def test_precondition_gate(runner):
    # Passed preconditions
    passed_records = [
        ExploitationRecord(hypothesis_id="h1", tool_name="sqli_test", target="http://127.0.0.1:8080", port=8080, status=ExploitStatus.SUCCESS)
    ]
    score_passed, passed, failed = runner.score_preconditions(passed_records, {"sqli_test"})
    assert passed == 1
    assert failed == 0
    assert score_passed > 0.0

    # Blocked preconditions (e.g. out of scope or port closed)
    blocked_records = [
        ExploitationRecord(hypothesis_id="h2", tool_name="arbitrary_attack", target="http://127.0.0.1:9999", port=9999, status=ExploitStatus.BLOCKED)
    ]
    score_blocked, passed, failed = runner.score_preconditions(blocked_records, {"arbitrary_attack"})
    assert passed == 0
    assert failed == 1


def test_validation_success(runner):
    observations = [
        "HTTP/1.1 200 OK\nProof of Compromise: FLAG{auth_bypass_sqli_verified} FLAG-ALPHA-AUTH-BYPASS"
    ]
    exploit_records = [
        ExploitationRecord(hypothesis_id="h1", tool_name="sqli_test", target="http://127.0.0.1:8080", port=8080, status=ExploitStatus.SUCCESS)
    ]
    score, started, succeeded, attempted, succ_count = runner.score_validation(observations, exploit_records)
    assert started is True
    assert succeeded is True
    assert score == 15.0


def test_validation_failure(runner):
    # Merely exit code 0 or failed output without actual proof marker
    observations = [
        "HTTP/1.1 401 Unauthorized: Invalid username or password."
    ]
    exploit_records = [
        ExploitationRecord(hypothesis_id="h1", tool_name="sqli_test", target="http://127.0.0.1:8080", port=8080, status=ExploitStatus.FAILED)
    ]
    score, started, succeeded, attempted, succ_count = runner.score_validation(observations, exploit_records)
    assert started is True
    assert succeeded is False
    assert score < 15.0


def test_verification_success(runner):
    proof_found = True
    turn_traces = [
        {"turn": 1, "observation": "200 OK", "timestamp_delta_s": 5.0},
        {"turn": 2, "observation": "FLAG{auth_bypass_sqli_verified}", "timestamp_delta_s": 12.0}
    ]
    score, verified, time_first, time_obj, tools_obj = runner.score_verification_and_objective(
        proof_found=proof_found, verified_hypotheses=1, turn_traces=turn_traces, start_time=0.0
    )
    assert verified is True
    assert score == 15.0
    assert tools_obj == 2
    assert time_first == 12.0


def test_objective_completion(runner):
    # Unverified session
    score, verified, time_first, time_obj, tools_obj = runner.score_verification_and_objective(
        proof_found=False, verified_hypotheses=0, turn_traces=[], start_time=0.0
    )
    assert verified is False
    assert score == 0.0
    assert tools_obj is None


def test_duplicate_prevention(runner):
    gain, per_action = runner.calculate_information_gain(
        observations=["200 OK", "200 OK"],
        open_ports=[8080],
        proof_found=False,
        duplicate_calls=3
    )
    # Deductions applied for redundant duplicate calls
    assert gain < 5.0


def test_evidence_fidelity(runner):
    trace = ModelBenchmarkTrace(
        model_name="test-model",
        display_name="Test Model",
        discovery_score=20.0,
        identification_unknown_preserved=True,
        tool_calls_failed=0
    )
    # Compute fidelity
    fidelity_base = (trace.discovery_score / 20.0) * 40.0 + 30.0 + 30.0
    trace.evidence_fidelity_score = min(100.0, fidelity_base)
    assert trace.evidence_fidelity_score == 100.0


def test_unknown_preservation(runner):
    # When UNKNOWN is kept, score is higher than when UNKNOWN is replaced with hallucinated version
    clean_services = {631: ServiceRecord(host="127.0.0.1", port=631, service="ipp", version="UNKNOWN")}
    hallucinated_services = {631: ServiceRecord(host="127.0.0.1", port=631, service="ipp", version="CUPS 2.4.2")}

    clean_score, clean_pres, _ = runner.score_identification(clean_services)
    hall_score, hall_pres, _ = runner.score_identification(hallucinated_services)

    assert clean_pres is True
    assert hall_pres is False
    assert clean_score > hall_score


def test_benchmark_reset():
    MultiServiceLabWebHandler.requests_received = 50
    MultiServiceLabWebHandler.compromises_recorded = ["sqli"]
    IPPPrintServerHandler.requests_received = 12
    MockSSHHandler.connections_received = 4

    lab = MultiServiceLab()
    lab.reset()

    assert MultiServiceLabWebHandler.requests_received == 0
    assert MultiServiceLabWebHandler.compromises_recorded == []
    assert IPPPrintServerHandler.requests_received == 0
    assert MockSSHHandler.connections_received == 0


def test_cross_model_isolation():
    lab = MultiServiceLab()
    lab.reset()

    # Simulate model 1 making changes
    MultiServiceLabWebHandler.requests_received += 5
    MultiServiceLabWebHandler.compromises_recorded.append("path_traversal")

    # Reset lab before model 2
    lab.reset()
    assert MultiServiceLabWebHandler.requests_received == 0
    assert len(MultiServiceLabWebHandler.compromises_recorded) == 0
