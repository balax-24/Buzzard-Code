"""
Tests for Phase 11 Tool-Call Reliability Subsystem.
Verifies:
1. Parsing of JSON fenced blocks, raw JSON, XML <tool_call>, and Hermes formats.
2. Canonical schema validation and synonym error detection.
3. Enum constraint validation and structured error feedback.
"""

import pytest
from intelligence.tool_reliability import (
    ToolCallParser,
    ToolCallValidator,
    CANONICAL_TOOL_REGISTRY,
    ParsedToolCall,
)


def test_parse_json_fenced_block():
    text = """
    Let me analyze the attack surface. The login endpoint is available.
    ```json
    {
      "thought": "HYP-SQLI-01 has high confidence",
      "tool": "sqlmap_attack",
      "arguments": {"url": "http://127.0.0.1:8080/login", "data": "user=admin"}
    }
    ```
    """
    parsed = ToolCallParser.parse(text)
    assert parsed is not None
    assert parsed.tool_name == "sqlmap_attack"
    assert parsed.arguments["url"] == "http://127.0.0.1:8080/login"
    assert "high confidence" in parsed.thought


def test_parse_xml_tool_call():
    text = """
    <tool_call>
        <name>browser.snapshot</name>
        <arguments>
            <url>http://127.0.0.1:8080/dashboard</url>
        </arguments>
    </tool_call>
    """
    parsed = ToolCallParser.parse(text)
    assert parsed is not None
    assert parsed.tool_name == "browser.snapshot"
    assert parsed.arguments["url"] == "http://127.0.0.1:8080/dashboard"


def test_validator_detects_synonym_and_gives_structured_feedback():
    parsed = ParsedToolCall(
        tool_name="sqlmap_attack",
        arguments={"target_url": "http://127.0.0.1:8080/login"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "TOOL_ARGUMENT_ERROR" in error
    assert "target_url" in error
    assert "Expected canonical parameter name 'url'" in error


def test_validator_checks_enum_constraints():
    parsed = ParsedToolCall(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080/", "method": "INVALID_METHOD"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "invalid value 'INVALID_METHOD'" in error
    assert "Allowed values" in error


def test_validation_missing_required_field():
    """1. Missing required field triggers repairable schema error with expected schema."""
    parsed = ParsedToolCall(
        tool_name="http.request",
        arguments={"method": "GET"}  # missing 'url'
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "missing required parameter 'url'" in error
    assert parsed.structured_error["SCHEMA_ERROR"] is True
    assert parsed.structured_error["REPAIRABLE"] is True
    assert parsed.structured_error["RETRY_ALLOWED"] is True
    assert "url" in parsed.structured_error["EXPECTED_SCHEMA"]
    assert parsed.structured_error["RECEIVED_FIELDS"] == ["method"]


def test_validation_unknown_field():
    """2. Unknown field triggers schema error specifying allowed parameters."""
    parsed = ParsedToolCall(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1:8080", "unsupported_extra_param": "foo"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "received unknown field(s)" in error
    assert parsed.structured_error["SCHEMA_ERROR"] is True
    assert parsed.structured_error["REPAIRABLE"] is True
    assert parsed.structured_error["RETRY_ALLOWED"] is True
    assert "unsupported_extra_param" in parsed.structured_error["unknown_fields"]


def test_validation_wrong_type():
    """3. Wrong argument type triggers schema error with expected vs received types."""
    parsed = ParsedToolCall(
        tool_name="http.request",
        arguments={"url": 12345, "headers": "not-a-dict"}  # headers must be dict
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "expected type 'object'" in error
    assert parsed.structured_error["SCHEMA_ERROR"] is True
    assert parsed.structured_error["expected_type"] == "object"
    assert parsed.structured_error["received_type"] == "str"
    assert parsed.structured_error["REPAIRABLE"] is True


def test_validation_malformed_structured_call():
    """4. Non-dict arguments or missing tool name triggers non-repairable schema error."""
    # Missing tool name
    parsed_no_tool = ParsedToolCall(tool_name="", arguments={"url": "http://127.0.0.1"})
    valid_a, err_a = ToolCallValidator.validate(parsed_no_tool)
    assert not valid_a
    assert "missing tool name" in err_a
    assert parsed_no_tool.structured_error["REPAIRABLE"] is False
    assert parsed_no_tool.structured_error["RETRY_ALLOWED"] is False

    # Non-dict arguments
    parsed_bad_args = ParsedToolCall(tool_name="http.request", arguments="url=http://127.0.0.1")  # type: ignore
    valid_b, err_b = ToolCallValidator.validate(parsed_bad_args)
    assert not valid_b
    assert "must be a dictionary" in err_b
    assert parsed_bad_args.structured_error["REPAIRABLE"] is False
    assert parsed_bad_args.structured_error["RETRY_ALLOWED"] is False


def test_validation_repairable_schema_error():
    """5. Recoverable errors like wrong param name or enum violation are marked repairable."""
    parsed = ParsedToolCall(
        tool_name="nmap_scan",
        arguments={"host": "127.0.0.1"}  # 'host' is canonical alias for 'target'
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert parsed.structured_error["REPAIRABLE"] is True
    assert parsed.structured_error["RETRY_ALLOWED"] is True


def test_validation_non_repairable_schema_error():
    """6. Unregistered tools cannot be repaired by modifying arguments."""
    parsed = ParsedToolCall(
        tool_name="completely_imaginary_tool",
        arguments={"some": "arg"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "not registered" in error
    assert parsed.structured_error["REPAIRABLE"] is False
    assert parsed.structured_error["RETRY_ALLOWED"] is False


def test_validation_canonical_alias():
    """7. Authorized canonical alias is recognized and directs model to canonical name."""
    parsed = ParsedToolCall(
        tool_name="browser.snapshot",
        arguments={"target_url": "http://127.0.0.1:8080"}  # 'target_url' is alias for 'url'
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert parsed.structured_error["synonym_detected"] == "target_url"
    assert parsed.structured_error["canonical_field"] == "url"
    assert "Expected canonical parameter name 'url'" in error


def test_validation_invalid_alias():
    """8. Unauthorized alias is treated as an unknown field rather than silently normalized."""
    parsed = ParsedToolCall(
        tool_name="nmap_scan",
        arguments={"target": "127.0.0.1", "unauthorized_flag": "-sV"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert "unauthorized_flag" in parsed.structured_error["unknown_fields"]


def test_validation_retry_allowed_flag():
    """9. Temporary or repairable argument mistakes flag retry_allowed=True."""
    parsed = ParsedToolCall(
        tool_name="http.request",
        arguments={"url": "http://127.0.0.1", "method": "INVALID"}
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert parsed.structured_error["RETRY_ALLOWED"] is True


def test_validation_retry_prohibited_flag():
    """10. Fatal errors such as completely missing tool name flag retry_allowed=False."""
    parsed = ParsedToolCall(tool_name="", arguments={})
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    assert parsed.structured_error["RETRY_ALLOWED"] is False


def test_validation_error_feedback_contains_expected_schema():
    """11. Structured error includes complete EXPECTED_SCHEMA with field types and descriptions."""
    parsed = ParsedToolCall(
        tool_name="sqlmap_attack",
        arguments={}  # Missing required 'url'
    )
    is_valid, error = ToolCallValidator.validate(parsed)
    assert not is_valid
    schema = parsed.structured_error["EXPECTED_SCHEMA"]
    assert "url" in schema
    assert schema["url"]["param_type"] == "string"
    assert schema["url"]["required"] is True
    assert "description" in schema["url"]


def test_validation_error_feedback_does_not_leak_secrets():
    """12. Sensitive values like bearer tokens or passwords in malformed calls are redacted."""
    # Test secret bearer token in enum field
    parsed_enum_secret = ParsedToolCall(
        tool_name="http.request",
        arguments={
            "url": "http://127.0.0.1",
            "method": "Bearer secret_jwt_token_abcdef123456",
        }
    )
    is_valid, error = ToolCallValidator.validate(parsed_enum_secret)
    assert not is_valid
    assert "secret_jwt_token_abcdef123456" not in error
    assert "secret_jwt_token_abcdef123456" not in str(parsed_enum_secret.structured_error)
    assert "[REDACTED]" in error
    assert parsed_enum_secret.structured_error["invalid_value"] == "[REDACTED]"

    # Test unknown parameter with sensitive key and value
    parsed_key_secret = ParsedToolCall(
        tool_name="http.request",
        arguments={
            "url": "http://127.0.0.1",
            "password": "SUPER_SECRET_PLAINTEXT_PASSWORD",
        }
    )
    valid_key, error_key = ToolCallValidator.validate(parsed_key_secret)
    assert not valid_key
    assert "SUPER_SECRET_PLAINTEXT_PASSWORD" not in error_key
    assert "SUPER_SECRET_PLAINTEXT_PASSWORD" not in str(parsed_key_secret.structured_error)
