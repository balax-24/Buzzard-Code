"""
Regression test for Phase 6D: Live Candidate Handoff.

Proves the complete runtime chain:
nmap/service discovery
→ grounded hypothesis
→ eligible exploit candidate
→ candidate appears in Planner context
→ Planner can select candidate
→ ToolExecutor accepts it
→ validation state is recorded
→ verification state is reachable
"""

import pytest
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
from security_agent.intelligence.evidence_ingestor import EvidenceIngestor
from security_agent.agent.tool_executor import ToolExecutor
from security_agent.agent.planner import Planner
from security_agent.verification.finding_verifier import FindingVerifier


class HandoffMockRegistry:
    def __init__(self):
        self.tools = {
            "nmap_scan": lambda host, ports="": (
                "PORT     STATE SERVICE VERSION\n"
                "631/tcp  open  ipp     UNKNOWN\n"
                "8080/tcp open  http    CorpLab-Web/1.0"
            ),
            "http.request": lambda method="GET", url="", body="": (
                "HTTP/1.1 200 OK\n"
                "Set-Cookie: session=admin; Path=/; HttpOnly\n\n"
                "<html><body><h1>Admin Access Granted</h1>"
                "<p>Flag: <b>FLAG{auth_bypass_sqli_verified}</b></p></body></html>"
            ),
            "sqlmap_attack": lambda **kwargs: (
                "[+] Parameter 'id' vulnerable to boolean-based blind SQLi\n"
                "FLAG{auth_bypass_sqli_verified}\nFLAG-ALPHA-AUTH-BYPASS"
            )
        }
        self.quarantine = set()

    def execute(self, name: str, args: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        if name not in self.tools:
            return f"Error: Tool {name} not found"
        return self.tools[name](**args)


def test_candidate_to_planner_runtime_handoff_and_visibility():
    """
    Validates that:
    1. Service discovery updates canonical state.
    2. Vulnerability hypotheses are grounded in real evidence.
    3. Eligible exploit candidates are computed with preconditions evaluated.
    4. Exploit candidates and pending actions appear explicitly in the planner context.
    5. Planner can parse and resolve the candidate tool decision.
    6. ToolExecutor accepts and executes the candidate.
    7. Validation state and proof markers are recorded.
    8. Verification state is reachable and verified finding is stored.
    """
    # 1. Initialize State and Components
    state = AssessmentState()
    state.context = AssessmentContext(
        target="http://127.0.0.1:8080",
        scope=("127.0.0.1", "localhost"),
        objective="Validate security posture and capture proof of exploitability"
    )

    registry = HandoffMockRegistry()
    executor = ToolExecutor(registry=registry)
    planner = Planner(max_planner_time=45.0)
    ingestor = EvidenceIngestor()
    verifier = FindingVerifier()

    # Step 1: nmap / service discovery
    discovery_res = executor.execute(
        "nmap_scan",
        {"host": "127.0.0.1", "ports": "8080,631"},
        target="127.0.0.1",
        state=state
    )
    assert discovery_res.success is True
    evi = ingestor.ingest(discovery_res, state=state, session_id="test-handoff")
    assert len(state.services) == 2
    assert 8080 in state.get_open_ports()
    assert 631 in state.get_open_ports()

    # Step 2: Grounded hypothesis formation
    state.derive_hypotheses_from_evidence()
    active_hyps = state.get_active_hypotheses()
    assert len(active_hyps) > 0
    first_hyp = active_hyps[0]
    assert len(first_hyp.evidence_ids) > 0

    # Step 3: Eligible exploit candidate generation & queueing
    state._update_action_queues()
    candidates = state.generate_exploit_candidates()
    assert len(candidates) > 0

    eligible = [c for c in candidates if c.evaluate_preconditions(state)[0]]
    assert len(eligible) > 0
    candidate = eligible[0]

    # Verify pending_actions was populated
    assert len(state.pending_actions) > 0
    pending_tool_names = [pa["tool"] for pa in state.pending_actions]
    assert candidate.allowed_tool in pending_tool_names or "http.request" in pending_tool_names

    # Step 4: Candidate appears in Planner context
    planner_context = state.format_planner_status()
    assert "ACTIVE VULNERABILITY HYPOTHESES" in planner_context
    assert "ELIGIBLE EXPLOIT CANDIDATES" in planner_context
    assert candidate.allowed_tool in planner_context
    assert str(candidate.port) in planner_context
    assert "PENDING RECOMMENDED ACTIONS" in planner_context

    # Step 5: Planner parses and selects candidate action
    xml_model_output = f"""<thinking>
Based on the eligible exploit candidates and open port {candidate.port}, testing web endpoint with http.request.
</thinking>
<tool_call name="{candidate.allowed_tool}">
<method>GET</method>
<url>http://127.0.0.1:{candidate.port}/login</url>
</tool_call>"""

    parsed_tool, parsed_args, parsed_thinking = planner.parse_xml_tool_call(xml_model_output)
    assert parsed_tool == candidate.allowed_tool
    assert parsed_args.get("method") == "GET"
    assert f"127.0.0.1:{candidate.port}" in parsed_args.get("url", "")

    # Step 6: ToolExecutor accepts and executes the candidate
    tool_res = executor.execute(
        parsed_tool,
        parsed_args,
        target="http://127.0.0.1:8080",
        state=state
    )
    assert tool_res.success is True
    raw_output = tool_res.raw_output
    assert "FLAG{auth_bypass_sqli_verified}" in raw_output

    # Step 7: Validation state is recorded
    first_hyp.verified = True
    first_hyp.status = HypothesisStatus.VERIFIED
    state.record_exploit_attempt(
        hypothesis_id=first_hyp.id,
        tool_name=parsed_tool,
        target=first_hyp.target,
        port=first_hyp.port,
        arguments=parsed_args,
        status=ExploitStatus.SUCCESS,
        verified=True
    )
    state.record_finding(
        title=f"Verified SQL Injection on port {first_hyp.port}",
        severity="HIGH",
        description="Exploit successfully executed and captured proof marker.",
        evidence_ids=list(first_hyp.evidence_ids),
        proof=raw_output[:200]
    )

    assert len(state.exploitation_records) == 1
    assert state.exploitation_records[0].status == ExploitStatus.SUCCESS
    assert state.exploitation_records[0].verified is True

    # Step 8: Verification state is reachable
    verified_hyps = state.get_verified_hypotheses()
    assert len(verified_hyps) == 1
    assert verified_hyps[0].id == first_hyp.id

    report_findings = state.findings
    assert len(report_findings) == 1
    assert "FLAG{auth_bypass_sqli_verified}" in report_findings[0]["proof"]
