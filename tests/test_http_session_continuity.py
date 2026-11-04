"""
Tests for HTTP session continuity and automatic credential attachment.
"""

import pytest
from unittest.mock import MagicMock
from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.agent.tool_executor import ToolExecutor
from security_agent.tools.registry import ToolRegistry
from security_agent.events.bus import EventBus


def test_tool_executor_injects_session_cookies():
    # 1. Setup mock registry with http.request tool
    registry = ToolRegistry()
    last_received_headers = {}

    def mock_http_request(method, url, headers=None, body=None, timeout=10):
        nonlocal last_received_headers
        last_received_headers = headers or {}
        if "/login" in url:
            return "STATUS: 200\nHEADERS:\nSet-Cookie: session=adm_tok_888\n\nBODY:\nLogin OK\n\nDURATION: 0.050s"
        elif "/admin" in url:
            if headers and "session=adm_tok_888" in headers.get("Cookie", ""):
                return "STATUS: 200\nHEADERS:\n\nBODY:\nWelcome, Administrator!\n\nDURATION: 0.050s"
            return "STATUS: 403\nHEADERS:\n\nBODY:\nForbidden\n\nDURATION: 0.050s"
        return "STATUS: 200\nHEADERS:\n\nBODY:\nHome\n\nDURATION: 0.050s"

    registry.register(name="http.request", description="HTTP probe", func=mock_http_request)

    # 2. Setup state & executor
    ctx = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=ctx)
    executor = ToolExecutor(registry=registry, event_bus=EventBus(), config={"allow_all_targets": True})

    # 3. Call login without cookie
    res1 = executor.execute("http.request", {"method": "POST", "url": "http://127.0.0.1:8080/login", "body": "admin=1"}, state=state)
    assert res1.success
    assert "Login OK" in res1.raw_output

    # Check that session store captured cookie
    auth_ctx = state.get_request_auth_context("http://127.0.0.1:8080/admin")
    assert "Cookie" in auth_ctx["headers"]
    assert "session=adm_tok_888" in auth_ctx["headers"]["Cookie"]

    # 4. Call /admin without specifying Cookie argument -> Executor automatically attaches session cookie!
    res2 = executor.execute("http.request", {"method": "GET", "url": "http://127.0.0.1:8080/admin"}, state=state)
    assert res2.success
    assert "Welcome, Administrator!" in res2.raw_output
    assert "session=adm_tok_888" in last_received_headers.get("Cookie", "")


def test_explicit_headers_override_session_store_defaults():
    registry = ToolRegistry()
    received_headers = {}

    def mock_http_req(method, url, headers=None, body=None, timeout=10):
        nonlocal received_headers
        received_headers = headers or {}
        return "STATUS: 200\nHEADERS:\n\nBODY:\nOK\n\nDURATION: 0.010s"

    registry.register(name="http.request", description="HTTP probe", func=mock_http_req)

    ctx = AssessmentContext(target="http://127.0.0.1:8080", scope=["127.0.0.1"])
    state = AssessmentState(context=ctx)
    session = state.get_session_store().create_session("http://127.0.0.1:8080")
    from security_agent.state.session_store import Cookie
    session.add_cookie(Cookie(name="session", value="default_cookie", domain="127.0.0.1"))

    executor = ToolExecutor(registry=registry, event_bus=EventBus(), config={"allow_all_targets": True})

    # Call with explicit override cookie
    executor.execute(
        "http.request",
        {"method": "GET", "url": "http://127.0.0.1:8080/admin", "headers": {"Cookie": "session=explicit_model_override"}},
        state=state
    )

    assert received_headers.get("Cookie") == "session=explicit_model_override"
