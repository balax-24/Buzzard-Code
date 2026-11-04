"""
Tests for multi-session support and role-based credential separation.
"""

import pytest
from security_agent.state.session_store import (
    SessionStore,
    Cookie,
    BearerToken,
    AuthenticationState,
)


def test_concurrent_multi_role_sessions():
    store = SessionStore()

    # Create anonymous session
    anon_sess = store.create_session(
        target_origin="http://127.0.0.1:8000",
        role="anonymous",
        session_id="SESS-ANON"
    )

    # Create user session
    user_sess = store.create_session(
        target_origin="http://127.0.0.1:8000",
        role="user",
        session_id="SESS-USER"
    )
    user_sess.add_cookie(Cookie("user_cookie", "uid_456", "127.0.0.1"))

    # Create admin session
    admin_sess = store.create_session(
        target_origin="http://127.0.0.1:8000",
        role="admin",
        session_id="SESS-ADMIN"
    )
    admin_sess.add_cookie(Cookie("admin_cookie", "adm_root_789", "127.0.0.1"))

    # Verify requests by role
    ctx_anon = store.get_request_auth_context("http://127.0.0.1:8000/api", role="anonymous")
    assert "Cookie" not in ctx_anon["headers"]

    ctx_user = store.get_request_auth_context("http://127.0.0.1:8000/api", role="user")
    assert "user_cookie=uid_456" in ctx_user["headers"]["Cookie"]
    assert "admin_cookie" not in ctx_user["headers"]["Cookie"]

    ctx_admin = store.get_request_auth_context("http://127.0.0.1:8000/api", role="admin")
    assert "admin_cookie=adm_root_789" in ctx_admin["headers"]["Cookie"]
    assert "user_cookie" not in ctx_admin["headers"]["Cookie"]


def test_merge_session_capabilities():
    store = SessionStore()
    s1 = store.create_session("http://localhost", role="temp", session_id="S1")
    s1.add_cookie(Cookie("sess", "123", "localhost"))
    s1.source_evidence_ids.append("EVID-001")

    s2 = store.create_session("http://localhost", role="admin", session_id="S2")

    assert store.merge_session("S1", "S2")
    assert "sess" in s2.cookies
    assert "EVID-001" in s2.source_evidence_ids
