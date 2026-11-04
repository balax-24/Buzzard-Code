"""
Tests for P4 Residual Hardening:
- R1: log_finding SSOT via AssessmentState, secret redaction, evidence requirements, storage mirroring
- R2: VerificationPipeline routing through AssessmentState SSOT
- R3: Configurable VerificationPredicates across distinct scenarios (Scenario A: Cloud API, Scenario B: IoT Gateway)
- R4: Canonical advance_objective() transitions, lifecycle enforcement, validation gates, history tracking
"""

import pytest
import uuid
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ObjectiveStatus,
    VerificationPredicates,
)
from security_agent.tools.evidence import log_finding
from security_agent.tools.registry import ToolRegistry
from security_agent.agent.tool_executor import ToolExecutor
from security_agent.storage.db import StorageManager
from security_agent.verification.pipeline import VerificationPipeline
from security_agent.intelligence.hypothesis import SecurityHypothesis, HypothesisStatus
from security_agent.model.schemas import Severity, Confidence
from tests.test_agent_loop import MockModelProvider
from security_agent.agent.loop import AgentLoop


# ==============================================================================
# R1: log_finding Single Source of Truth Tests
# ==============================================================================

def test_log_finding_routes_through_assessment_state(tmp_path):
    """Verifies that log_finding writes to AssessmentState as SSOT and mirrors to storage."""
    db_path = str(tmp_path / "test_ssot.db")
    storage = StorageManager(db_path=db_path)
    session_id = "sess-r1-test"
    storage.create_session(session_id, "https://test.local", ["test.local"], "SSOT Test")

    state = AssessmentState()
    # Add valid evidence to state
    ev_id = state.record_evidence(
        evidence_id="EV-TEST-001",
        target="https://test.local",
        description="Proof of SQL injection error",
        raw_data={"error": "syntax error in SQL statement"}
    )

    secret_key = "Bearer sk_" "live_1234567890abcdef1234567890abcdef"
    result = log_finding(
        session_id=session_id,
        title=f"SQL Injection with secret {secret_key}",
        severity="HIGH",
        confidence="CONFIRMED",
        affected_asset="https://test.local/login",
        description=f"Injected SQL flaw leaking {secret_key}",
        impact="Full database compromise",
        verification="PoC payload ' OR 1=1--",
        remediation="Use parameterized statements",
        evidence_ids=[ev_id],
        storage_manager=storage,
        state=state
    )

    # 1. Authoritative state contains the finding
    assert len(state.findings) == 1
    state_f = state.findings[0]
    assert state_f["verified"] is True
    assert state_f["verification_status"] == "VERIFIED"
    assert "sk_live" not in state_f["title"]  # Redacted
    assert "[REDACTED" in state_f["title"] or "REDACTED" in state_f["title"]
    assert state_f["evidence_ids"] == [ev_id]

    # 2. Storage contains mirrored finding with matching ID (no duplicate)
    stored = storage.get_findings(session_id)
    assert len(stored) == 1
    assert stored[0].id == state_f["id"]
    assert stored[0].affected_asset == "https://test.local/login"
    assert "sk_live" not in stored[0].title


def test_log_finding_without_evidence_remains_unverified(tmp_path):
    """Verifies that empty evidence_ids prevents unverified findings from becoming verified."""
    state = AssessmentState()
    result = log_finding(
        session_id="sess-no-ev",
        title="Unverified finding without evidence",
        severity="HIGH",
        confidence="CONFIRMED",
        affected_asset="https://test.local/api",
        description="Hallucinated vulnerability without evidence",
        impact="None",
        verification="None",
        remediation="None",
        evidence_ids=[],  # Empty evidence!
        state=state
    )

    assert len(state.findings) == 1
    state_f = state.findings[0]
    assert state_f["verified"] is False
    assert state_f["verification_status"] == "UNVERIFIED"


def test_log_finding_via_tool_executor(tmp_path):
    """Verifies ToolExecutor automatically passes canonical state into log_finding."""
    db_path = str(tmp_path / "test_exec.db")
    storage = StorageManager(db_path=db_path)
    session_id = "sess-tool-exec"
    storage.create_session(session_id, "https://test.local", ["test.local"], "Exec Test")

    state = AssessmentState()
    registry = ToolRegistry()
    from security_agent.tools.evidence import register_evidence_tools
    register_evidence_tools(registry)
    executor = ToolExecutor(registry=registry, storage=storage)

    res = executor.execute(
        session_id=session_id,
        tool_name="log_finding",
        arguments={
            "title": "CSRF Token Missing",
            "severity": "medium",
            "confidence": "confirmed",
            "affected_asset": "https://test.local/profile",
            "description": "Profile form has no CSRF token",
            "impact": "Account state change",
            "verification": "Submitted without token",
            "remediation": "Add Anti-CSRF token",
            "evidence_ids": ["EV-01"],
        },
        state=state
    )

    assert res.exit_code == 0
    assert len(state.findings) == 1
    assert state.findings[0]["title"] == "CSRF Token Missing"
    # Storage should mirror
    stored = storage.get_findings(session_id)
    assert len(stored) == 1
    assert stored[0].id == state.findings[0]["id"]


# ==============================================================================
# R2: VerificationPipeline SSOT Tests
# ==============================================================================

def test_verification_pipeline_updates_assessment_state(tmp_path):
    """Verifies VerificationPipeline records to AssessmentState when state is provided."""
    db_path = str(tmp_path / "test_vpipe.db")
    storage = StorageManager(db_path=db_path)
    session_id = "session-vpipe-001"
    storage.create_session(session_id, "https://target.local", ["target.local"], "Verify Test")

    state = AssessmentState()
    pipeline = VerificationPipeline(storage_manager=storage, state=state)

    hypo = SecurityHypothesis(
        id="HYP-PIPE-01",
        target_asset="https://target.local/products",
        vulnerability_type="SQL Injection",
        description="Candidate SQL flaw on products API"
    )

    evidence_data = {
        "indicators_found": [{
            "probe": "' OR 1=1--",
            "matched_pattern": "sqlite3.OperationalError"
        }]
    }

    finding = pipeline.verify_hypothesis(
        session_id=session_id,
        hypothesis=hypo,
        raw_evidence_data=evidence_data,
        remediation_hint="Use parameterized queries"
    )

    assert finding is not None
    assert hypo.status == HypothesisStatus.VERIFIED

    # Authoritative state received finding and evidence
    assert len(state.findings) == 1
    assert state.findings[0]["id"] == finding.id
    assert state.findings[0]["verified"] is True
    assert len(state.evidence) == 1

    # Storage mirrored correctly
    stored = storage.get_findings(session_id)
    assert len(stored) == 1
    assert stored[0].id == finding.id


# ==============================================================================
# R3: Configurable VerificationPredicates across Distinct Scenarios
# ==============================================================================

def test_scenario_a_cloud_api_token_verification():
    """Scenario A: Verifies an API gateway target where proof is a cloud bearer token."""
    cloud_predicates = VerificationPredicates(
        proof_markers=["BEARER_ENTERPRISE_KEY_ACTIVE", "cloud_admin_token_extracted"],
        session_token_pattern=r"Bearer\s+([a-zA-Z0-9_\-\.]+)",
        default_session_cookie="Bearer default_cloud_token",
        fallback_finding_title="Cloud API Key Compromise",
        fallback_finding_description="Bearer token confirmed with administrative cloud privileges.",
        verification_endpoints=[
            {"path": "/api/v2/iam/keys", "reason": "Verify IAM keys extraction on {url}", "expected_proof": "BEARER_ENTERPRISE_KEY_ACTIVE"}
        ]
    )

    context = AssessmentContext(
        target="cloud-gw.internal",
        scope=("cloud-gw.internal",),
        objective="Extract administrative enterprise keys from Cloud Gateway",
        predicates=cloud_predicates
    )
    state = AssessmentState(context=context, predicates=cloud_predicates)

    # 1. Configured predicates work as expected
    raw_response = "HTTP/2 200 OK\nHeader: Bearer cloud_admin_token_extracted\nBody: BEARER_ENTERPRISE_KEY_ACTIVE"
    matched = state.predicates.matches_proof(raw_response)
    assert matched == "BEARER_ENTERPRISE_KEY_ACTIVE"

    # 2. Verification candidates generated from configured endpoints
    candidates = state.generate_verification_candidates()
    assert any("/api/v2/iam/keys" in c["target"] for c in candidates)
    assert candidates[0]["expected_proof"] == "BEARER_ENTERPRISE_KEY_ACTIVE"

    # 3. State advance_objective requires configured proof or verified finding
    res = state.advance_objective(ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED)
    assert res is True
    # Successfully transitions to VERIFIED with configured proof
    res2 = state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED, proof=matched)
    assert res2 is True
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED


def test_scenario_b_embedded_device_root_shell():
    """Scenario B: Verifies an IoT device target where proof is a busybox root prompt."""
    iot_predicates = VerificationPredicates(
        proof_markers=["busybox_v1.33_root_shell#", "Linux 4.9.224 armv7l"],
        session_token_pattern=r"auth_token=([0-9a-f]+)",
        default_session_cookie="auth_token=superadmin",
        fallback_finding_title="IoT Gateway Firmware Root Compromise",
        fallback_finding_description="Busybox root shell achieved via unauthenticated debug port.",
        verification_endpoints=[
            {"path": "/proc/version", "reason": "Verify kernel version on {url}", "expected_proof": "Linux 4.9.224 armv7l"}
        ]
    )

    context = AssessmentContext(
        target="192.168.10.1",
        scope=("192.168.10.1",),
        objective="Achieve root shell on IoT gateway device",
        predicates=iot_predicates
    )
    state = AssessmentState(context=context, predicates=iot_predicates)

    raw_response = "U-Boot 2020.04\nLinux 4.9.224 armv7l\nbusybox_v1.33_root_shell#"
    matched = state.predicates.matches_proof(raw_response)
    assert matched == "busybox_v1.33_root_shell#"

    candidates = state.generate_verification_candidates()
    assert any("/proc/version" in c["target"] for c in candidates)
    assert candidates[0]["expected_proof"] == "Linux 4.9.224 armv7l"

    state.advance_objective(ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED)
    res = state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED, proof=matched)
    assert res is True
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED


def test_agent_loop_accepts_custom_predicates():
    """Verifies that AgentLoop initializes and preserves custom VerificationPredicates."""
    custom_predicates = VerificationPredicates(
        proof_markers=["CUSTOM_PROOF_TOKEN_XYZ"],
        fallback_finding_title="Custom Target Achieved"
    )

    provider = MockModelProvider(responses=["I will inspect the system."])
    loop = AgentLoop(
        provider=provider,
        predicates=custom_predicates,
        quiet=True
    )

    assert loop.canonical_state is not None
    assert loop.canonical_state.predicates.proof_markers == ["CUSTOM_PROOF_TOKEN_XYZ"]
    assert loop.canonical_state.predicates.fallback_finding_title == "Custom Target Achieved"


# ==============================================================================
# R4: Canonical Objective Transitions and Verification Gate Tests
# ==============================================================================

def test_objective_transition_lifecycle_validation():
    """Verifies that advance_objective allows valid transitions and rejects invalid ones."""
    state = AssessmentState()
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED

    # 1. Invalid transition: directly leaping from UNREACHED to VERIFIED without evidence
    invalid = state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED)
    assert invalid is False
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED

    # 2. Valid transition to ACHIEVED_UNVERIFIED
    valid = state.advance_objective(ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED, reason="Exploit payload succeeded")
    assert valid is True
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # 3. Transition to VERIFIED fails if no proof/evidence is present
    failed_verif = state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED, reason="Claimed without proof")
    assert failed_verif is False
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED

    # 4. Transition to VERIFIED succeeds when valid proof is supplied
    success_verif = state.advance_objective(
        ObjectiveStatus.OBJECTIVE_VERIFIED,
        reason="Admin flag retrieved independently",
        proof="PROOF-CONFIRMED-KEY"
    )
    assert success_verif is True
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED

    # 5. Terminal state: cannot transition backwards
    backtrack = state.advance_objective(ObjectiveStatus.OBJECTIVE_UNREACHED)
    assert backtrack is False
    assert state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED

    # 6. History is tracked accurately
    assert len(state.objective_history) == 2
    assert state.objective_history[0]["from_status"] == "OBJECTIVE_UNREACHED"
    assert state.objective_history[0]["to_status"] == "OBJECTIVE_ACHIEVED_UNVERIFIED"
    assert state.objective_history[1]["from_status"] == "OBJECTIVE_ACHIEVED_UNVERIFIED"
    assert state.objective_history[1]["to_status"] == "OBJECTIVE_VERIFIED"


def test_objective_history_checkpoint_serialization_roundtrip():
    """Verifies objective_status and objective_history serialize and deserialize cleanly."""
    state = AssessmentState()
    state.advance_objective(ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED, reason="Phase 1 complete")
    state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED, reason="Phase 2 proof", proof="TEST_PROOF")

    data = state.to_dict()
    assert data["objective_status"] == "OBJECTIVE_VERIFIED"
    assert len(data["objective_history"]) == 2

    restored = AssessmentState.from_dict(data)
    assert restored.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED
    assert len(restored.objective_history) == 2
    assert restored.objective_history[0]["to_status"] == "OBJECTIVE_ACHIEVED_UNVERIFIED"
    assert restored.objective_history[1]["to_status"] == "OBJECTIVE_VERIFIED"
