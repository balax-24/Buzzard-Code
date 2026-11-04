"""
Unit and integration tests for SessionStore and session management.
"""

import time
import pytest
from state.session_store import (
    SessionStore,
    Session,
    Cookie,
    BearerToken,
    CSRFToken,
    AuthenticationState,
    SessionVerificationStatus,
)


def test_cookie_domain_and_path_matching():
    c1 = Cookie(
        name="sessionid",
        value="secret123",
        domain="example.com",
        path="/admin",
        secure=True,
    )

    # Path mismatch
    assert not c1.matches_request("example.com", "/public", is_https=True)
    # HTTPS mismatch
    assert not c1.matches_request("example.com", "/admin", is_https=False)
    # Host mismatch
    assert not c1.matches_request("other.com", "/admin", is_https=True)
    # Correct matching
    assert c1.matches_request("example.com", "/admin/dashboard", is_https=True)
    assert c1.matches_request("sub.example.com", "/admin", is_https=True)


def test_cookie_expiry():
    c_expired = Cookie(
        name="sess",
        value="val",
        domain="localhost",
        path="/",
        expiry=time.time() - 10,
    )
    assert c_expired.is_expired()
    assert not c_expired.matches_request("localhost", "/")

    c_valid = Cookie(
        name="sess",
        value="val",
        domain="localhost",
        path="/",
        expiry=time.time() + 100,
    )
    assert not c_valid.is_expired()
    assert c_valid.matches_request("localhost", "/")


def test_session_store_create_and_get():
    store = SessionStore(default_scope=["localhost", "127.0.0.1"])
    session = store.create_session(
        target_origin="http://127.0.0.1:8080",
        role="admin",
        session_id="SESS-TEST-001"
    )

    assert session.session_id == "SESS-TEST-001"
    assert session.target_origin == "127.0.0.1:8080"
    assert session.role == "admin"
    assert store.get_session("SESS-TEST-001") == session


def test_session_store_update_from_http_response_set_cookie():
    store = SessionStore()
    headers = {
        "Set-Cookie": "session=auth_token_999; Domain=127.0.0.1; Path=/; HttpOnly; Max-Age=3600",
        "Location": "/dashboard"
    }
    body = "<html><body><a href='/admin/users'>Users</a><form action='/admin/delete' method='POST'></form></body></html>"

    session, endpoints = store.update_from_http_response(
        target_url="http://127.0.0.1:8080/login",
        status_code=302,
        headers=headers,
        body=body,
        evidence_id="EVID-HTTP-001"
    )

    assert session.is_authenticated()
    assert "session" in session.cookies
    assert session.cookies["session"].value == "auth_token_999"
    assert "EVID-HTTP-001" in session.source_evidence_ids

    # Check discovered endpoints
    paths = [ep["path"] for ep in endpoints]
    assert "/dashboard" in paths
    assert "/admin/users" in paths
    assert "/admin/delete" in paths


def test_csrf_token_extraction_from_html():
    store = SessionStore()
    body = """
    <form action="/transfer" method="POST">
        <input type="hidden" name="csrf_token" value="csrf_secret_abc123" />
        <input type="text" name="amount" />
    </form>
    """
    session, _ = store.update_from_http_response(
        target_url="http://localhost:5000/profile",
        status_code=200,
        headers={},
        body=body
    )

    assert "csrf_token" in session.csrf_tokens
    assert session.csrf_tokens["csrf_token"].csrf_token == "csrf_secret_abc123"

    # Context resolution should include CSRF token
    ctx = store.get_request_auth_context("http://localhost:5000/transfer")
    assert ctx["headers"]["X-CSRF-Token"] == "csrf_secret_abc123"


def test_safe_summary_masking():
    store = SessionStore()
    session = store.create_session("http://127.0.0.1:8080")
    session.add_cookie(Cookie("sensitive_session", "super_secret_cookie_value_12345", "127.0.0.1"))
    session.add_bearer_token(BearerToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "127.0.0.1:8080"))

    summary = store.export_safe_summary()
    assert len(summary) == 1
    safe_cookie = summary[0]["cookies"][0]
    assert safe_cookie["name"] == "sensitive_session"
    assert "***" in safe_cookie["value"]
    assert "super_secret_cookie_value_12345" not in safe_cookie["value"]

    safe_token = summary[0]["bearer_tokens"][0]
    assert "***" in safe_token["token"]
