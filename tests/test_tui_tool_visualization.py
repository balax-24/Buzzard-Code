"""
Tests for Tool Call Visualization and Sensitive Data Redaction.
Verifies:
1. ToolCallCard rendering.
2. Sensitive redaction of passwords, tokens, and cookies.
"""

import pytest
from tui.models import ToolCallCardData, redact_sensitive_data
from tui.widgets.tool_card import ToolCallCard


def test_sensitive_data_redaction():
    raw_payload = {
        "url": "http://127.0.0.1:8080/auth/login",
        "password": "supersecretpassword123",
        "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "cookie": "session_id=987654321; admin=true",
        "safe_param": "search_query"
    }

    redacted = redact_sensitive_data(raw_payload)

    assert redacted["password"] == "su***23"
    assert redacted["safe_param"] == "search_query"
    assert "***" in redacted["bearer_token"]
    assert "***" in redacted["cookie"]


def test_tool_card_creation():
    data = ToolCallCardData(
        tool_name="http.request",
        target="http://127.0.0.1:8080/login",
        arguments={"url": "http://127.0.0.1:8080/login", "method": "POST"},
        status="SUCCESS",
        duration_seconds=0.45,
        output_summary="Status: 200 OK, form rendered."
    )
    card = ToolCallCard(data)
    assert card.data.tool_name == "http.request"
    assert card.data.status == "SUCCESS"
