"""
Tests for Phase 11 Planner Prompt Hierarchy and Invariant Preservation.
Verifies:
1. System prompt contains canonical tool schemas and JSON formatting contract.
2. User prompt preserves Target, Scope, Capabilities, Sessions, and Findings across long horizons.
3. Structured validation error feedback is rendered cleanly.
"""

import pytest
from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    Capability,
    CapabilityType,
)
from security_agent.intelligence.planner_prompt import PlannerPromptBuilder


def test_system_prompt_structure():
    sys_prompt = PlannerPromptBuilder.build_system_prompt()
    assert "CANONICAL AVAILABLE TOOLS" in sys_prompt
    assert "`http.request`" in sys_prompt
    assert "`browser.snapshot`" in sys_prompt
    assert "DECISION RULES" in sys_prompt
    assert "```json" in sys_prompt


def test_user_prompt_preserves_invariants_and_error_feedback():
    state = AssessmentState(context=AssessmentContext(target="target.local", scope=["target.local"]))
    state.capabilities["cap-admin"] = Capability(
        capability_id="cap-admin",
        capability_type=CapabilityType.ADMIN_ACCESS,
        target_scope="target.local",
        source_evidence_ids=["EVI-001"]
    )
    store = state.get_session_store()
    sess = store.create_session(target_origin="http://target.local", role="admin")
    sess.is_authenticated = True

    user_prompt = PlannerPromptBuilder.build_user_prompt(
        state=state,
        last_information_gain=0.0,
        last_action_note="Identical response body",
        validation_error="TOOL_ARGUMENT_ERROR: Missing required parameter 'url'"
    )

    assert "Target: target.local" in user_prompt
    assert "ADMIN_ACCESS" in user_prompt
    assert "[admin] target.local" in user_prompt
    assert "PIVOT ADVICE" in user_prompt
    assert "TOOL_ARGUMENT_ERROR" in user_prompt
