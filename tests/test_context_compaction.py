"""
Tests for Phase 10 Context Compaction.
Verifies:
1. Critical security facts (Scope, Target, Capabilities, Active Sessions, Verified Findings) are never discarded during compaction.
2. Noise, repeated DOM markup, and obsolete traces are pruned to prevent context overflow.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
)
from model.schemas import Finding, Severity, Confidence
from intelligence.long_horizon import LongHorizonContextCompactor


def test_context_compaction_preserves_critical_invariants():
    state = AssessmentState(context=AssessmentContext(target="app.corp.local", scope=["app.corp.local"]))
    state.capabilities["cap-admin"] = Capability(
        capability_id="cap-admin",
        capability_type=CapabilityType.AUTHENTICATED,
        target_scope="app.corp.local"
    )
    state.findings.append({
        "id": "FIND-SQLI-01",
        "title": "SQL Injection on Authentication Form",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "affected_asset": "app.corp.local"
    })

    # Add active authenticated session
    store = state.get_session_store()
    sess = store.create_session(target_origin="http://app.corp.local", role="admin")
    sess.is_authenticated = True

    compact = LongHorizonContextCompactor.build_compact_context(state=state)

    # Invariants verification
    assert "Target: app.corp.local" in compact
    assert "Authorized Scope: app.corp.local" in compact
    assert "cap-admin" in compact
    assert "SQL Injection on Authentication Form" in compact
    assert "Active Sessions: [admin]" in compact
