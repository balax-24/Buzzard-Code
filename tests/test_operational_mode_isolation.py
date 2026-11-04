"""
P2-2 Tests: Operational Mode Isolation (CHAT vs RESEARCH vs ASSESSMENT).

Verifies:
1. CHAT mode allows normal conversation and safe chat utilities.
2. CHAT mode strictly rejects security assessment state mutation (findings, evidence, capabilities, phase transitions).
3. CHAT mode rejects offensive security tool execution.
4. RESEARCH mode allows informational research context and research tools.
5. RESEARCH mode prevents silent mutation of active assessment state.
6. Ordinary research output cannot create confirmed assessment findings.
7. ASSESSMENT mode enables full tool execution and state mutation within authorized scope.
8. Mode transitions do not leak findings, state mutations, action history, or assessment context.
9. Checkpoint restore preserves operational mode boundaries.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    CapabilityType,
)
from agent.mode_isolation import (
    OperationalMode,
    OperationalModeManager,
    ModeIsolationViolation,
)


def _make_state(target: str = "127.0.0.1") -> AssessmentState:
    return AssessmentState(context=AssessmentContext(target=target, scope=[target]))


def test_chat_mode_allows_conversation_and_isolates_history():
    """CHAT mode facilitates conversation without touching assessment state."""
    mgr = OperationalModeManager(OperationalMode.CHAT)
    assert mgr.is_chat()
    assert not mgr.is_assessment()

    mgr.add_chat_message("user", "Hello, how does SQL injection work conceptually?")
    mgr.add_chat_message("assistant", "SQL injection occurs when untrusted input is concatenated into SQL queries.")

    assert len(mgr.chat_history) == 2
    assert mgr.chat_history[0]["content"].startswith("Hello")
    assert len(mgr.research_notes) == 0


def test_chat_mode_blocks_state_mutation():
    """CHAT mode prevents any mutation to AssessmentState."""
    state = _make_state()
    state.set_operational_mode("CHAT")
    assert state.operational_mode == "CHAT"

    # 1. Attempting phase transition in CHAT mode fails
    with pytest.raises(ModeIsolationViolation, match="CHAT"):
        state.transition(AssessmentPhase.DISCOVERY, "Attempted scan transition")

    # 2. Attempting to record finding in CHAT mode fails
    with pytest.raises(ModeIsolationViolation, match="CHAT"):
        state.record_finding("SQL Injection", severity="HIGH", proof="' OR '1'='1")

    # 3. Attempting to record evidence in CHAT mode fails
    with pytest.raises(ModeIsolationViolation, match="CHAT"):
        state.record_evidence(raw_data="HTTP 200 OK", source_tool="curl")

    # 4. Attempting to record capability in CHAT mode fails
    with pytest.raises(ModeIsolationViolation, match="CHAT"):
        state.record_capability(
            capability_type=CapabilityType.COMMAND_EXECUTION,
            source_evidence_ids=["EVI-01"],
            acquisition_action="cmd_exec",
            target_scope="127.0.0.1",
        )

    # Invariants: state remains clean
    assert len(state.findings) == 0
    assert len(state.evidence) == 0
    assert len(state.capabilities) == 0
    assert state.current_phase == AssessmentPhase.INITIALIZING


def test_chat_mode_blocks_offensive_tools():
    """CHAT mode rejects execution authorization for offensive security tools."""
    mgr = OperationalModeManager(OperationalMode.CHAT)

    # Safe chat tools allowed
    assert mgr.authorize_tool("calculator") is True
    assert mgr.authorize_tool("echo") is True

    # Offensive tools rejected
    for tool in ("nmap", "sqlmap", "nikto", "hydra", "metasploit", "verify_proof", "exploit"):
        with pytest.raises(ModeIsolationViolation, match="cannot be executed in CHAT mode"):
            mgr.authorize_tool(tool)


def test_research_mode_allows_intelligence_gathering():
    """RESEARCH mode authorizes information tools and structured research notes."""
    mgr = OperationalModeManager(OperationalMode.RESEARCH)
    assert mgr.is_research()
    assert not mgr.is_assessment()

    # Research tools allowed
    assert mgr.authorize_tool("cve_lookup") is True
    assert mgr.authorize_tool("web_search") is True
    assert mgr.authorize_tool("doc_fetch") is True

    # Offensive tools rejected in RESEARCH mode
    with pytest.raises(ModeIsolationViolation, match="RESEARCH mode"):
        mgr.authorize_tool("sqlmap")
    with pytest.raises(ModeIsolationViolation, match="RESEARCH mode"):
        mgr.authorize_tool("metasploit")

    # Research notes recorded safely without creating assessment findings
    mgr.add_research_note(
        title="CVE-2023-38606 Details",
        content="Kernel vulnerability in iOS/macOS WebKit sandbox.",
        source="NVD",
    )
    assert len(mgr.research_notes) == 1
    assert mgr.research_notes[0]["is_assessment_finding"] is False


def test_research_mode_blocks_finding_creation_in_state():
    """RESEARCH mode cannot inject findings or capabilities into active AssessmentState."""
    state = _make_state()
    state.set_operational_mode("RESEARCH")
    assert state.operational_mode == "RESEARCH"

    # Ordinary research output mentioning a vulnerability cannot become an assessment finding
    with pytest.raises(ModeIsolationViolation, match="RESEARCH"):
        state.record_finding(
            title="CVE-2021-44228 Log4Shell",
            severity="CRITICAL",
            description="Discussed during research session",
        )

    # Capability acquisition cannot be performed from research mode
    with pytest.raises(ModeIsolationViolation, match="RESEARCH"):
        state.record_capability(
            capability_type=CapabilityType.COMMAND_EXECUTION,
            source_evidence_ids=["DOC-01"],
            acquisition_action="read_whitepaper",
            target_scope="127.0.0.1",
        )

    assert len(state.findings) == 0
    assert len(state.capabilities) == 0


def test_assessment_mode_enables_full_security_pipeline():
    """ASSESSMENT mode authorizes full security testing and state lifecycle."""
    mgr = OperationalModeManager(OperationalMode.ASSESSMENT)
    assert mgr.is_assessment()

    # Security tools authorized
    assert mgr.authorize_tool("nmap") is True
    assert mgr.authorize_tool("sqlmap") is True
    assert mgr.authorize_tool("verify_proof") is True

    # AssessmentState operates normally in ASSESSMENT mode
    state = _make_state()
    state.set_operational_mode("ASSESSMENT")

    assert state.transition(AssessmentPhase.DISCOVERY, "Discovery started") is True
    eid = state.record_evidence("Discovered port 80/tcp", source_tool="nmap")
    finding = state.record_finding("Open HTTP Port", severity="LOW", evidence_ids=[eid])

    assert len(state.findings) == 1
    assert state.findings[0]["id"] == finding["id"]
    assert state.current_phase == AssessmentPhase.DISCOVERY


def test_mode_transitions_prevent_cross_context_leakage():
    """
    Mode transitions between CHAT -> RESEARCH -> ASSESSMENT maintain strict boundary isolation.
    Chat conversations and research notes cannot leak into assessment findings.
    """
    mgr = OperationalModeManager(OperationalMode.CHAT)
    state = _make_state()

    # Phase 1: User asks a conversational question
    mgr.add_chat_message("user", "Can you explain SSRF in cloud environments?")
    mgr.add_chat_message("assistant", "SSRF allows an attacker to query internal metadata services like 169.254.169.254.")

    # Phase 2: Switch to RESEARCH mode
    mgr.set_mode(OperationalMode.RESEARCH)
    state.set_operational_mode("RESEARCH")
    mgr.add_research_note("AWS IMDSv1 SSRF", "IMDSv1 lacks token headers, vulnerable if SSRF exists.")

    # Invariants during research: no assessment findings created
    assert len(state.findings) == 0

    # Phase 3: Switch to ASSESSMENT mode
    mgr.set_mode(OperationalMode.ASSESSMENT)
    state.set_operational_mode("ASSESSMENT")

    # In ASSESSMENT mode, findings require empirical observation and evidence
    eid = state.record_evidence("HTTP probe returned AWS IAM role credentials", source_tool="http_request")
    state.record_finding("SSRF on /proxy endpoint", severity="CRITICAL", evidence_ids=[eid], proof="Role: admin-role")

    # Check isolation invariants
    assert len(state.findings) == 1
    assert state.findings[0]["title"] == "SSRF on /proxy endpoint"
    # Neither chat message nor research note leaked into assessment findings
    for f in state.findings:
        assert "AWS IMDSv1 SSRF" != f["title"]
        assert "Can you explain" not in f["title"]

    # Phase 4: Switch back to CHAT mode
    mgr.set_mode(OperationalMode.CHAT)
    state.set_operational_mode("CHAT")
    mgr.add_chat_message("user", "What is the capital of France?")

    # Subsequent mutation attempts in CHAT mode are blocked
    with pytest.raises(ModeIsolationViolation):
        state.record_finding("Leaked Finding", severity="LOW")

    assert len(state.findings) == 1  # Unchanged
    assert len(mgr.transition_log) == 3
