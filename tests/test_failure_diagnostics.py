"""
Unit tests for Failure Diagnostics and Structured Feedback Engine.

Verifies:
- Accurate classification of failure categories (CONNECTION_REFUSED, 404, 401, 403, SCHEMA, TIMEOUT, GENERAL).
- Retryability logic: non-retryable for closed ports; retryable for 404 with alternative paths.
- Information extraction: failure produces actionable negative intelligence.
- Warning generation when repeated failures occur to force model pivot.
- Formatting of structured feedback blocks suitable for model context.
"""

import pytest
from intelligence.failure_diagnostics import (
    FailureDiagnosticsEngine,
    FailureCategory,
    StructuredFailureFeedback,
)


def test_connection_refused_diagnostic():
    feedback = FailureDiagnosticsEngine.diagnose_failure(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:9999"},
        raw_output="Failed to connect to 127.0.0.1 port 9999: Connection refused",
        exit_code=1,
    )

    assert feedback.failure_category == FailureCategory.CONNECTION_REFUSED
    assert feedback.is_retryable is False
    assert feedback.produced_information is True
    assert "closed" in feedback.information_gained_summary.lower() or "unreachable" in feedback.information_gained_summary.lower()
    assert len(feedback.alternative_action_classes) > 0

    block = feedback.format_feedback_block()
    assert "CONNECTION_REFUSED" in block
    assert "NO (do not repeat identical action)" in block


def test_404_not_found_diagnostic():
    feedback = FailureDiagnosticsEngine.diagnose_failure(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080/nonexistent"},
        raw_output="HTTP/1.1 404 Not Found - The requested resource was not located",
        exit_code=0,
    )

    assert feedback.failure_category == FailureCategory.ENDPOINT_NOT_FOUND
    assert feedback.is_retryable is True  # Can retry with another endpoint
    assert "Directory / route discovery" in feedback.alternative_action_classes or len(feedback.alternative_action_classes) > 0


def test_401_unauthorized_high_value_diagnostic():
    feedback = FailureDiagnosticsEngine.diagnose_failure(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080/admin"},
        raw_output="HTTP/1.1 401 Unauthorized - Authentication credentials missing or invalid",
        exit_code=0,
    )

    assert feedback.failure_category == FailureCategory.AUTHENTICATION_REQUIRED
    assert feedback.is_retryable is True
    assert "EXISTS" in feedback.information_gained_summary
    assert "authentication" in feedback.information_gained_summary.lower()


def test_parameter_schema_error_diagnostic():
    feedback = FailureDiagnosticsEngine.diagnose_failure(
        tool_name="scan_ports",
        arguments={"invalid_param": 123},
        raw_output="ValidationError: Missing required parameter 'target'",
        exit_code=2,
        error_type="invalid_argument",
    )

    assert feedback.failure_category == FailureCategory.PARAMETER_SCHEMA_ERROR
    assert feedback.is_retryable is True
    assert "schema" in feedback.information_gained_summary.lower()


def test_repeated_failure_pivot_warning():
    feedback = FailureDiagnosticsEngine.diagnose_failure(
        tool_name="auth_bypass_test",
        arguments={"url": "http://127.0.0.1:8080/login"},
        raw_output="HTTP/1.1 403 Forbidden",
        exit_code=1,
        previous_failure_count=3,
    )

    assert feedback.previous_similar_failures == 3
    block = feedback.format_feedback_block()
    assert "PIVOT STRATEGY REQUIRED" in block
    assert "3 similar failure(s) recorded" in block
