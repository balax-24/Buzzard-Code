"""Tests for the AssessmentState machine."""

import pytest
from agent.state import AssessmentPhase, AssessmentState


class TestAssessmentState:
    def test_initial_state(self):
        state = AssessmentState()
        assert state.phase == AssessmentPhase.INITIALIZING
        assert state.previous_phase is None

    def test_valid_forward_transition(self):
        state = AssessmentState()
        assert state.transition(AssessmentPhase.AUTHORIZATION_CHECK) is True
        assert state.phase == AssessmentPhase.AUTHORIZATION_CHECK
        assert state.previous_phase == AssessmentPhase.INITIALIZING

    def test_invalid_transition(self):
        state = AssessmentState()
        # Cannot skip directly to ACTIVE_TESTING
        assert state.transition(AssessmentPhase.ACTIVE_TESTING) is False
        assert state.phase == AssessmentPhase.INITIALIZING  # unchanged

    def test_full_happy_path(self):
        state = AssessmentState()
        phases = [
            AssessmentPhase.AUTHORIZATION_CHECK,
            AssessmentPhase.SCOPE_VALIDATION,
            AssessmentPhase.ASSET_DISCOVERY,
            AssessmentPhase.PASSIVE_RECON,
            AssessmentPhase.APPLICATION_MODELING,
            AssessmentPhase.THREAT_MODELING,
            AssessmentPhase.ATTACK_SURFACE_MAPPING,
            AssessmentPhase.HYPOTHESIS_GENERATION,
            AssessmentPhase.ACTIVE_TESTING,
            AssessmentPhase.VERIFICATION,
            AssessmentPhase.ATTACK_PATH_ANALYSIS,
            AssessmentPhase.RISK_ASSESSMENT,
            AssessmentPhase.REPORTING,
            AssessmentPhase.COMPLETED,
        ]
        for phase in phases:
            assert state.transition(phase) is True
        assert state.phase == AssessmentPhase.COMPLETED

    def test_iterative_loop(self):
        """Active testing can loop back to hypothesis generation."""
        state = AssessmentState()
        # Fast-forward to ACTIVE_TESTING
        for p in [
            AssessmentPhase.AUTHORIZATION_CHECK,
            AssessmentPhase.SCOPE_VALIDATION,
            AssessmentPhase.ASSET_DISCOVERY,
            AssessmentPhase.PASSIVE_RECON,
            AssessmentPhase.APPLICATION_MODELING,
            AssessmentPhase.THREAT_MODELING,
            AssessmentPhase.ATTACK_SURFACE_MAPPING,
            AssessmentPhase.HYPOTHESIS_GENERATION,
            AssessmentPhase.ACTIVE_TESTING,
        ]:
            state.transition(p)
        
        # Loop back
        assert state.transition(AssessmentPhase.HYPOTHESIS_GENERATION) is True
        assert state.transition(AssessmentPhase.ACTIVE_TESTING) is True

    def test_pause_and_resume(self):
        state = AssessmentState()
        state.transition(AssessmentPhase.AUTHORIZATION_CHECK)
        state.transition(AssessmentPhase.SCOPE_VALIDATION)
        
        assert state.pause() is True
        assert state.phase == AssessmentPhase.PAUSED
        assert state.previous_phase == AssessmentPhase.SCOPE_VALIDATION
        
        assert state.resume() is True
        assert state.phase == AssessmentPhase.SCOPE_VALIDATION

    def test_cannot_pause_completed(self):
        state = AssessmentState()
        state.phase = AssessmentPhase.COMPLETED
        assert state.pause() is False

    def test_cannot_resume_non_paused(self):
        state = AssessmentState()
        assert state.resume() is False

    def test_any_phase_can_fail(self):
        state = AssessmentState()
        state.transition(AssessmentPhase.AUTHORIZATION_CHECK)
        assert state.transition(AssessmentPhase.FAILED) is True

    def test_serialization_roundtrip(self):
        state = AssessmentState()
        state.transition(AssessmentPhase.AUTHORIZATION_CHECK)
        state.transition(AssessmentPhase.SCOPE_VALIDATION)
        state.hypothesis_count = 5
        state.verified_count = 2
        
        d = state.to_dict()
        restored = AssessmentState.from_dict(d)
        
        assert restored.phase == AssessmentPhase.SCOPE_VALIDATION
        assert restored.hypothesis_count == 5
        assert restored.verified_count == 2

    def test_same_phase_noop(self):
        state = AssessmentState()
        assert state.transition(AssessmentPhase.INITIALIZING, "Updated objective") is True
        assert state.current_objective == "Updated objective"

    def test_phase_history_tracking(self):
        state = AssessmentState()
        state.transition(AssessmentPhase.AUTHORIZATION_CHECK)
        state.transition(AssessmentPhase.SCOPE_VALIDATION)
        assert len(state.phase_history) == 2
        assert state.phase_history[0] == "AUTHORIZATION_CHECK"
