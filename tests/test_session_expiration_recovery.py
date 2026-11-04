"""
Tests for Phase 12 Session Expiration Recovery.
Verifies:
1. Expired session detection upon restore.
2. Rehydration prompt rendering [EXPIRED] notification requiring reauthentication.
"""

import pytest
import tempfile
from pathlib import Path

from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.state.session_store import Cookie
from security_agent.persistence.checkpoint_manager import CheckpointManager
from security_agent.intelligence.memory import LayeredMemoryManager


def test_session_expiration_across_checkpoint_resume():
    with tempfile.TemporaryDirectory() as tmpdir:
        from security_agent.state.session_store import AuthenticationState
        manager = CheckpointManager(storage_dir=tmpdir)
        state = AssessmentState(context=AssessmentContext(target="app.local"))
        store = state.get_session_store()
        sess = store.create_session(target_origin="http://app.local", role="admin")
        sess.authentication_state = AuthenticationState.AUTHENTICATED
        sess.add_cookie(Cookie(name="session_id", value="token_123", domain="app.local"))

        # Checkpoint while authenticated
        chk = manager.create_checkpoint("INV-SESS-01", state=state)

        # Restore
        r_state, _, _, r_store, _, _ = manager.restore_checkpoint(chk.checkpoint_id)
        r_sess = list(r_store.sessions.values())[0]

        # Simulate expiration
        r_sess.authentication_state = AuthenticationState.EXPIRED

        mem = LayeredMemoryManager()
        rehydrated = mem.build_rehydration_context(state=r_state)

        assert "[EXPIRED]" in rehydrated
        assert "app.local" in rehydrated
        assert "Reauthentication required" in rehydrated
