"""
Unit tests for Buzzard Benchmark Reachability & Complete Lifecycle Scoring.
Demonstrates the full path using real:
- AssessmentState
- Planner
- ToolExecutor
- EvidenceIngestor
- FindingVerifier
- MultiServiceBenchmarkRunner
"""

import pytest
from unittest.mock import MagicMock
from typing import Dict, Any

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ServiceState,
    VerificationStatus,
    ExploitStatus,
    HypothesisStatus,
)
from security_agent.benchmark.multi_service_runner import (
    MultiServiceBenchmarkRunner,
    LabGroundTruth,
)
from security_agent.intelligence.evidence_ingestor import EvidenceIngestor
from security_agent.agent.tool_executor import ToolExecutor, ToolExecutionResult
from security_agent.agent.planner import Planner
from security_agent.verification.finding_verifier import FindingVerifier


class BenchmarkMockRegistry:
    def __init__(self):
        self.tools = {
            "nmap_scan": lambda host, ports="": (
                "PORT     STATE SERVICE VERSION\n"
                "631/tcp  open  ipp     UNKNOWN\n"
                "2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu\n"
                "8080/tcp open  http    CorpLab-Web/1.0"
            ),
            "http.request": lambda method="GET", url="", body="": (
                "HTTP/1.1 200 OK\n"
                "Set-Cookie: session=admin; Path=/; HttpOnly\n\n"
                "<html><body><h1>Login Successful</h1>"
                "<p>Admin Flag: <b>FLAG{auth_bypass_sqli_verified}</b></p>"
                "<p>Verification Marker: <b>FLAG-ALPHA-AUTH-BYPASS</b></p></body></html>"
            ),
            "ssh_brute": lambda **kwargs: (
                "[+] Valid credentials found: admin:admin123\n"
                "PROOF-RCE-UID-1000\nFLAG-ALPHA-AUTH-BYPASS\nFLAG{auth_bypass_sqli_verified}"
            ),
            "sqlmap_attack": lambda **kwargs: (
                "[+] SQL injection found on parameter 'username'\n"
                "FLAG{auth_bypass_sqli_verified} FLAG-ALPHA-AUTH-BYPASS"
            )
        }
        self.quarantine = set()

    def execute(self, name: str, args: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        if name not in self.tools:
            return f"Error: Tool {name} not found"
        return self.tools[name](**args)


def test_complete_deterministic_benchmark_reachability_pipeline():
    """
    Proves that a model/agent executing valid discovery and validation actions
    is fully scored across all 7 stages including:
    Hypothesis > 0, Precondition > 0, Validation > 0, Verification > 0.
    Uses real AssessmentState, Planner, ToolExecutor, EvidenceIngestor, FindingVerifier.
    """
    state = AssessmentState()
    state.context = AssessmentContext(
        target="http://127.0.0.1:8080",
        scope=("127.0.0.1", "localhost"),
        objective="Find and validate vulnerabilities"
    )

    registry = BenchmarkMockRegistry()
    executor = ToolExecutor(registry=registry)
    planner = Planner(max_planner_time=45.0)
    ingestor = EvidenceIngestor()
    verifier = FindingVerifier()

    # Step 1: DISCOVERY & IDENTIFICATION via real ToolExecutor + EvidenceIngestor
    res1 = executor.execute("nmap_scan", {"host": "127.0.0.1", "ports": "8080,631,2222"}, target="127.0.0.1", state=state)
    assert res1.success is True
    evi1 = ingestor.ingest(res1, state=state, session_id="test-bench-reachability")
    assert len(state.services) == 3

    # Step 2: HYPOTHESIS FORMATION
    state.derive_hypotheses_from_evidence()
    assert len(state.hypotheses) > 0
    hyp_ids = list(state.hypotheses.keys())
    first_hyp = state.hypotheses[hyp_ids[0]]
    assert len(first_hyp.evidence_ids) > 0

    # Step 3: PRECONDITION EVALUATION
    candidate = state.get_eligible_exploit_candidate()
    assert candidate is not None
    is_valid, msg = candidate.evaluate_preconditions(state)
    assert is_valid is True, f"Precondition failed: {msg}"

    # Step 4: VALIDATION ACTION EXECUTION via real ToolExecutor
    res2 = executor.execute(
        candidate.allowed_tool,
        candidate.tool_arguments,
        target="127.0.0.1",
        state=state
    )
    assert res2.success is True
    assert "FLAG{auth_bypass_sqli_verified}" in res2.raw_output

    # Record action attempt and exploit attempt
    rec = state.record_exploit_attempt(
        hypothesis_id=first_hyp.id,
        tool_name=candidate.allowed_tool,
        target=first_hyp.target,
        port=first_hyp.port,
        arguments=candidate.tool_arguments,
        status=ExploitStatus.SUCCESS,
        verified=True
    )
    state.record_action_attempt(
        tool_name=candidate.allowed_tool,
        args=candidate.tool_arguments,
        target="127.0.0.1",
        success=True,
        failure_type="",
        output_snippet=res2.raw_output[:100]
    )

    # Step 5: VERIFICATION & OBJECTIVE COMPLETION via FindingVerifier
    state.verify_exploit_success(first_hyp.id, proof="FLAG{auth_bypass_sqli_verified}")
    candidate_finding = {
        "title": f"Verified Vulnerability: {first_hyp.vulnerability_type} on port {first_hyp.port}",
        "severity": "HIGH",
        "affected_asset": f"http://127.0.0.1:{first_hyp.port}",
        "description": "SQL injection authentication bypass confirmed on /login.",
        "evidence_ids": list(first_hyp.evidence_ids),
        "proof": "FLAG{auth_bypass_sqli_verified}"
    }
    is_accepted, verified_finding, rat = verifier.verify_candidate_finding(candidate_finding, state=state)
    assert is_accepted is True

    finding = state.record_finding(
        title=verified_finding.title,
        severity=verified_finding.severity.value,
        description=verified_finding.description,
        evidence_ids=list(first_hyp.evidence_ids),
        proof="FLAG{auth_bypass_sqli_verified}"
    )

    observations = [
        f"Executed {res1.tool_name} with {res1.arguments}. Status: SUCCESS. Result: Discovered ports 8080, 631, 2222",
        f"Executed {res2.tool_name} with {res2.arguments}. Status: SUCCESS. Result: {res2.raw_output}"
    ]

    # Step 6: RUN BENCHMARK SCORING ENGINE
    runner = MultiServiceBenchmarkRunner()
    evidence_ids = state.get_all_evidence_ids()
    hypotheses_list = list(state.hypotheses.values())

    disc_score, disc_ports = runner.score_discovery(state.get_open_ports(), state.services)
    id_score, unk_pres, _ = runner.score_identification(state.services)
    hyp_score, grounded_count = runner.score_hypothesis(hypotheses_list, evidence_ids)
    prec_score, prec_passed, prec_failed = runner.score_preconditions(list(state.exploitation_records), set(state.attempted_action_keys))
    val_score, val_started, val_succeeded, exp_att, exp_succ = runner.score_validation(observations, list(state.exploitation_records))
    ver_score, ver_succ, _, _, _ = runner.score_verification_and_objective(val_succeeded, len(state.get_verified_hypotheses()), [], 0.0)
    rep_score = runner.score_report(len(state.findings), len(state.get_verified_hypotheses()))

    total_score = round(disc_score + id_score + hyp_score + prec_score + val_score + ver_score + rep_score, 2)

    # Assertions proving every stage is reachable and awarded > 0
    assert disc_score > 0, f"Discovery score: {disc_score}"
    assert id_score > 0, f"Identification score: {id_score}"
    assert hyp_score > 0, f"Hypothesis score: {hyp_score}"
    assert prec_score > 0, f"Precondition score: {prec_score}"
    assert val_score > 0, f"Validation score: {val_score}"
    assert ver_score > 0, f"Verification score: {ver_score}"
    assert rep_score > 0, f"Report score: {rep_score}"
    assert total_score >= 65.0, f"Total score achieved: {total_score}/100"
