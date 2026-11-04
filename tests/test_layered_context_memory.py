"""
Tests for Phase 12 Layered Context Memory (L0-L8) & Memory Promotion.
Verifies:
1. Structured memory layers.
2. Promotion of failed strategies when new evidence arrives.
3. Compact rehydration context generation without token loss.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
)
from intelligence.memory import LayeredMemoryManager
from persistence.models import BudgetSnapshot


def test_layered_memory_recording_and_rehydration():
    mem = LayeredMemoryManager()
    state = AssessmentState(context=AssessmentContext(target="app.corp.local", scope=["app.corp.local"]))
    state.capabilities["cap-admin"] = Capability(
        capability_id="cap-admin",
        capability_type=CapabilityType.ADMIN_ACCESS,
        target_scope="app.corp.local",
        source_evidence_ids=["EVI-001"]
    )
    state.findings.append({"title": "Remote Code Execution via Upload", "severity": "CRITICAL"})

    # Record failure
    mem.record_failure(
        target="http://app.corp.local/admin",
        tool_or_strategy="sqlmap_attack",
        failure_class="WAF_BLOCKED",
        notes="WAF signature 403"
    )

    budget = BudgetSnapshot(
        elapsed_seconds=300,
        max_seconds=3600,
        tool_calls_used=22,
        max_tool_calls=100,
        iterations_used=8,
        max_iterations=40
    )

    rehydrated = mem.build_rehydration_context(
        state=state,
        budget=budget,
        resumed_checkpoint_id="chk-abc123"
    )

    assert "INVESTIGATION RESUMED FROM CHECKPOINT [chk-abc123]" in rehydrated
    assert "Target: app.corp.local" in rehydrated
    assert "ADMIN_ACCESS" in rehydrated
    assert "Remote Code Execution" in rehydrated
    assert "WAF_BLOCKED" in rehydrated
    assert "Remaining Budget: 22/100" in rehydrated


def test_memory_promotion_on_new_evidence():
    mem = LayeredMemoryManager()
    mem.record_failure(
        target="http://app.corp.local/login",
        tool_or_strategy="http.request",
        failure_class="AUTH_REQUIRED"
    )
    rec = mem.failure_records["http://app.corp.local/login:http.request:AUTH_REQUIRED"]
    assert not rec.new_evidence_since_failure
    assert "Avoid repetition" in rec.to_summary()

    # New evidence discovered for this target
    mem.mark_new_evidence_for_target("http://app.corp.local/login")
    assert rec.new_evidence_since_failure
    assert "Retest allowed" in rec.to_summary()
