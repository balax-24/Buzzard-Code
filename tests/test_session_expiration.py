"""
Tests for session expiration, 401 handling, and invalidation.
"""

import time
import pytest
from state.session_store import (
    SessionStore,
    Cookie,
    BearerToken,
    AuthenticationState,
)


def test_session_expiration_omits_expired_credentials():
    store = SessionStore()
    session = store.create_session("http://127.0.0.1:8080")

    # Add expired cookie
    session.add_cookie(Cookie(
        name="session",
        value="exp_val",
        domain="127.0.0.1",
        expiry=time.time() - 5.0
    ))

    # Add expired bearer token
    session.add_bearer_token(BearerToken(
        token="exp_tok",
        origin="127.0.0.1:8080",
        expires_at=time.time() - 5.0
    ))

    ctx = store.get_request_auth_context("http://127.0.0.1:8080/dashboard")
    assert "Cookie" not in ctx["headers"]
    assert "Authorization" not in ctx["headers"]


def test_http_401_marks_session_expired():
    store = SessionStore()
    session = store.create_session("http://127.0.0.1:8080")
    session.add_cookie(Cookie(name="session", value="old_val", domain="127.0.0.1"))
    assert session.is_authenticated()

    # Receive 401 response
    store.update_from_http_response(
        target_url="http://127.0.0.1:8080/admin",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
        body="Unauthorized"
    )

    assert session.authentication_state == AuthenticationState.EXPIRED
    # Context resolution should now recognize expired session
    assert not session.is_valid()


def test_invalidate_session():
    store = SessionStore()
    sess = store.create_session("http://127.0.0.1", session_id="S-INV")
    assert store.invalidate_session("S-INV", reason="logout")
    assert sess.authentication_state == AuthenticationState.REVOKED
    assert sess.metadata.get("invalidation_reason") == "logout"
