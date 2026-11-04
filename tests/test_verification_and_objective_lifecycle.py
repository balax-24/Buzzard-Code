"""
Deterministic End-to-End Lifecycle and Objective Verification Test.

Covers the full 7-stage Buzzard assessment lifecycle:
1. DISCOVERY (multi-port discovery without scope drift)
2. IDENTIFICATION (banner parsing with UNKNOWN preserved for uncorroborated services)
3. HYPOTHESIS (grounded hypothesis formation backed by immutable evidence IDs)
4. PRECONDITION (exploit candidate generation and precondition evaluation)
5. VALIDATION (exploit execution with session/credential extraction)
6. VERIFICATION (independent verification observation path confirming objective achievement)
7. REPORT (evidence-grounded final reporting with claim verification)
"""

import pytest
from typing import Dict, Any

from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ObjectiveStatus,
    ServiceState,
    VerificationStatus,
    ExploitStatus,
    HypothesisStatus,
)
from intelligence.evidence_ingestor import EvidenceIngestor
from agent.tool_executor import ToolExecutor
from agent.planner import Planner
from verification.finding_verifier import FindingVerifier
from reports.report_generator import ReportGenerator


class LifecycleMockRegistry:
    def __init__(self):
        self.tools = {
            "nmap_scan": lambda host, ports="": (
                "PORT     STATE SERVICE VERSION\n"
                "631/tcp  open  ipp     UNKNOWN\n"
                "2222/tcp open  ssh     OpenSSH 8.9p1\n"
                "8080/tcp open  http    CorpLab-Web/1.0"
            ),
            "whatweb_scan": lambda url="": (
                "http://127.0.0.1:8080/ [200 OK] CorpLab-Web/1.0, Python/3.11, "
                "Title[CorpLab Internal Portal], PasswordField[password], Form[/login]"
            ),
            "grab_banner": lambda host, port=631: (
                "IPP/2.1 CUPS/2.4.2" if port == 631 else "SSH-2.0-OpenSSH_8.9p1"
            ),
            "http.request": self._http_request,
            "ssh_brute": lambda **kwargs: "SSH connection failed",
            "sqlmap_attack": lambda **kwargs: (
                "[+] Parameter 'username' vulnerable to SQL Injection auth bypass\n"
                "FLAG{auth_bypass_sqli_verified}\nFLAG-ALPHA-AUTH-BYPASS"
            )
        }
        self.quarantine = set()

    def _http_request(self, method="GET", url="", headers=None, body=None) -> str:
        headers = headers or {}
        if "/login" in url:
            return (
                "HTTP/1.1 200 OK\n"
                "Set-Cookie: session=admin; Path=/; HttpOnly\n\n"
                "<html><body><h1>Login Successful</h1>"
                "<p>Admin Flag: <b>FLAG{auth_bypass_sqli_verified}</b></p>"
                "<p>Verification Marker: <b>FLAG-ALPHA-AUTH-BYPASS</b></p>"
                "<a href=\"/admin\">Go to Admin Dashboard</a></body></html>"
            )
        elif "/admin" in url or "/flag" in url:
            cookie = headers.get("Cookie", "") if isinstance(headers, dict) else str(headers)
            if "session=admin" in cookie:
                return (
                    "HTTP/1.1 200 OK\n\n"
                    "<html><body><h1>Admin Dashboard</h1>"
                    "<p>Proof: FLAG{auth_bypass_sqli_verified} FLAG-ALPHA-AUTH-BYPASS</p></body></html>"
                )
            return "HTTP/1.1 403 Forbidden: Administrator session required."
        elif "/view" in url:
            return "root:x:0:0:root:/root:/bin/bash\nPROOF-PATH-TRAVERSAL-PASSWD-ROOT"
        return "HTTP/1.1 200 OK\nCorpLab Portal"

    def execute(self, name: str, args: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        if name not in self.tools:
            return f"Error: Tool {name} not found"
        return self.tools[name](**args)


def test_full_seven_stage_lifecycle_and_objective_verification():
    """
    Proves deterministic 7-stage end-to-end execution:
    1. Discovery: Open ports 8080, 631, 2222 discovered
    2. Identification: 8080 fingerprinted, 631 unverified preserved
    3. Hypothesis: Grounded hypotheses formed with evidence IDs
    4. Precondition: Preconditions evaluated for candidate exploit
    5. Validation: Exploit candidate executes and captures session credentials
    6. Verification: Independent verification query against /admin or /flag extracts verified proof
    7. Report: Final report generated with 100% evidence-grounded findings
    """
    # Initialize State & Components
    state = AssessmentState()
    state.context = AssessmentContext(
        target="http://127.0.0.1:8080",
        scope=("127.0.0.1", "127.0.0.1:8080", "localhost"),
        objective="Validate security posture, verify exploitability, and report grounded findings"
    )

    registry = LifecycleMockRegistry()
    executor = ToolExecutor(registry=registry)
    planner = Planner(max_planner_time=45.0)
    ingestor = EvidenceIngestor()
    verifier = FindingVerifier()
    report_gen = ReportGenerator()

    # =========================================================================
    # STAGE 1: DISCOVERY
    # =========================================================================
    state.transition(AssessmentPhase.DISCOVERY, "Running multi-port discovery scan")
    disc_res = executor.execute("nmap_scan", {"host": "127.0.0.1", "ports": "8080,631,2222"}, target="127.0.0.1", state=state)
    assert disc_res.success is True
    ingestor.ingest(disc_res, state=state, session_id="test-e2e")
    
    open_ports = state.get_open_ports()
    assert 8080 in open_ports
    assert 631 in open_ports
    assert 2222 in open_ports
    assert len(state.services) == 3

    # =========================================================================
    # STAGE 2: IDENTIFICATION
    # =========================================================================
    state.transition(AssessmentPhase.IDENTIFICATION, "Fingerprinting web service on port 8080")
    whatweb_res = executor.execute("whatweb_scan", {"url": "http://127.0.0.1:8080/"}, target="http://127.0.0.1:8080", state=state)
    assert whatweb_res.success is True
    ingestor.ingest(whatweb_res, state=state, session_id="test-e2e")

    s8080 = state.get_service("127.0.0.1", 8080)
    assert s8080 is not None
    assert s8080.investigated is True
    assert s8080.verification_status == VerificationStatus.VERIFIED

    # Check 631 is still UNKNOWN/unverified (no banner hallucination)
    s631 = state.get_service("127.0.0.1", 631)
    assert s631 is not None
    assert s631.version == "UNKNOWN"

    # =========================================================================
    # STAGE 3: HYPOTHESIS
    # =========================================================================
    state.transition(AssessmentPhase.HYPOTHESIS, "Deriving vulnerability hypotheses from technical evidence")
    state.derive_hypotheses_from_evidence()
    active_hyps = state.get_active_hypotheses()
    assert len(active_hyps) > 0
    target_hyp = active_hyps[0]
    assert len(target_hyp.evidence_ids) > 0

    # =========================================================================
    # STAGE 4: PRECONDITION
    # =========================================================================
    state.transition(AssessmentPhase.PRECONDITION, "Evaluating exploit preconditions")
    state._update_action_queues()
    candidates = state.generate_exploit_candidates()
    assert len(candidates) > 0
    eligible_candidates = [c for c in candidates if c.evaluate_preconditions(state)[0]]
    assert len(eligible_candidates) > 0
    candidate = [c for c in eligible_candidates if c.port == 8080][0]

    # Verify candidate visibility in Planner context
    planner_context = state.format_planner_status()
    assert "ELIGIBLE EXPLOIT CANDIDATES" in planner_context
    assert candidate.allowed_tool in planner_context

    # =========================================================================
    # STAGE 5: VALIDATION
    # =========================================================================
    state.transition(AssessmentPhase.EXPLOITATION, "Executing validation candidate")
    state.validation_attempted = True
    val_res = executor.execute(
        candidate.allowed_tool,
        candidate.tool_arguments,
        target=state.context.target,
        state=state
    )
    assert val_res.success is True
    state.validation_tool_success = True
    assert "FLAG{auth_bypass_sqli_verified}" in val_res.raw_output
    assert "session=admin" in val_res.raw_output

    # State transitions to unverified objective / verification phase
    state.objective_status = ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # =========================================================================
    # STAGE 6: VERIFICATION
    # =========================================================================
    state.transition(AssessmentPhase.VERIFICATION, "Independently verifying admin access via separate observation path")
    state._update_action_queues()
    
    # Check that verification actions are queued
    pending_tools = [pa["tool"] for pa in state.pending_actions]
    assert "http.request" in pending_tools
    
    # Execute independent verification action against /admin with session cookie
    verify_action = {
        "tool": "http.request",
        "args": {
            "method": "GET",
            "url": "http://127.0.0.1:8080/admin",
            "headers": {"Cookie": "session=admin"}
        }
    }
    state.verification_started = True
    verify_res = executor.execute(
        verify_action["tool"],
        verify_action["args"],
        target=state.context.target,
        state=state
    )
    assert verify_res.success is True
    assert "Admin Dashboard" in verify_res.raw_output
    assert "FLAG-ALPHA-AUTH-BYPASS" in verify_res.raw_output

    # Mark verified and record finding
    state.verification_success = True
    state.objective_achieved = True
    state.objective_status = ObjectiveStatus.OBJECTIVE_VERIFIED
    target_hyp.verified = True
    target_hyp.status = HypothesisStatus.VERIFIED

    state.record_exploit_attempt(
        hypothesis_id=target_hyp.id,
        tool_name=verify_action["tool"],
        target=target_hyp.target,
        port=target_hyp.port,
        arguments=verify_action["args"],
        status=ExploitStatus.SUCCESS,
        verified=True
    )

    state.record_finding(
        title=f"Verified SQL Injection Authentication Bypass on port {target_hyp.port}",
        severity="HIGH",
        description="SQL injection vulnerability allows complete authentication bypass to administrative dashboard.",
        evidence_ids=list(target_hyp.evidence_ids),
        proof=verify_res.raw_output[:300]
    )

    assert len(state.findings) == 1
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED

    # =========================================================================
    # STAGE 7: REPORT
    # =========================================================================
    state.transition(AssessmentPhase.REPORT, "Compiling final evidence-grounded report")
    state.report_generated = True

    # Validate finding with FindingVerifier
    finding_dict = state.findings[0]
    is_valid, verified_finding, rationale = verifier.verify_candidate_finding(finding_dict, state=state)
    assert is_valid is True
    assert len(verified_finding.evidence) > 0

    # Generate full report data & markdown
    report_data = report_gen.generate_report_data(
        state=state,
        session_id="test-e2e",
        target=state.context.target,
        findings=state.findings
    )
    assert len(report_data["findings"]) == 1
    assert len(report_data["services"]) == 3
    
    report_md = report_gen.render_markdown(report_data)
    assert "Verified Security Vulnerabilities" in report_md or "### 1." in report_md
    assert "FLAG-ALPHA-AUTH-BYPASS" in report_md or "FLAG{auth_bypass_sqli_verified}" in report_md
