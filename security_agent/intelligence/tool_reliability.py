"""
Phase 11 Tool-Call Reliability Subsystem.

Provides:
1. Canonical compact tool schemas optimized for LLM consumption.
2. Multi-format tool call parsing (JSON blocks, raw JSON, XML <tool_call>, Hermes <function_call>).
3. Strict schema and type validation without silent semantic modification.
4. Actionable structured error feedback for model self-repair.
5. Telemetry metrics for measuring raw model tool reliability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple


@dataclass
class ToolParameterSchema:
    name: str
    param_type: str
    required: bool = True
    description: str = ""
    enum_values: Optional[List[str]] = None
    example: Any = None


@dataclass
class CanonicalToolSchema:
    name: str
    description: str
    parameters: Dict[str, ToolParameterSchema]
    category: str = "general"
    aliases: Dict[str, str] = field(default_factory=dict)

    def to_compact_prompt(self) -> str:
        """Renders a compact schema representation for LLM prompt context."""
        params_str = []
        for p_name, p in self.parameters.items():
            req = "required" if p.required else "optional"
            enum_str = f", enum: {p.enum_values}" if p.enum_values else ""
            ex_str = f", e.g. {json.dumps(p.example)}" if p.example is not None else ""
            params_str.append(f"    - {p_name} ({p.param_type}, {req}{enum_str}{ex_str}): {p.description}")
        return f"• `{self.name}`: {self.description}\n" + "\n".join(params_str)


# ---------------------------------------------------------------------------
# Canonical Core Tool Schema Registry
# ---------------------------------------------------------------------------

CANONICAL_TOOL_REGISTRY: Dict[str, CanonicalToolSchema] = {
    "http.request": CanonicalToolSchema(
        name="http.request",
        description="Execute HTTP/HTTPS request with precise method, headers, query, or body.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "Full URL to request", example="http://127.0.0.1:8080/login"),
            "method": ToolParameterSchema("method", "string", False, "HTTP method", enum_values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], example="POST"),
            "headers": ToolParameterSchema("headers", "object", False, "HTTP request headers dict", example={"Content-Type": "application/json"}),
            "data": ToolParameterSchema("data", "string", False, "Raw body string or encoded form data", example="username=admin&password=secret"),
            "json": ToolParameterSchema("json", "object", False, "JSON body payload", example={"username": "admin"}),
        },
        category="network",
        aliases={"target_url": "url", "endpoint": "url", "uri": "url", "target": "url"}
    ),
    "browser.snapshot": CanonicalToolSchema(
        name="browser.snapshot",
        description="Navigate browser to target URL, render DOM, extract forms, interactive controls, and network events.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "URL to navigate and snapshot", example="http://127.0.0.1:8080/dashboard"),
            "wait_for_selector": ToolParameterSchema("wait_for_selector", "string", False, "CSS selector to wait for before snapshot", example="#main-content"),
        },
        category="browser",
        aliases={"target_url": "url", "endpoint": "url", "target": "url"}
    ),
    "browser.interact": CanonicalToolSchema(
        name="browser.interact",
        description="Perform UI action in browser (click, fill, submit form).",
        parameters={
            "action": ToolParameterSchema("action", "string", True, "Interaction type", enum_values=["click", "fill", "select", "press"], example="click"),
            "selector": ToolParameterSchema("selector", "string", True, "CSS selector of target element", example="button#submit"),
            "value": ToolParameterSchema("value", "string", False, "Input value for fill action", example="admin"),
        },
        category="browser",
        aliases={"type": "action", "interaction": "action"}
    ),
    "sqlmap_attack": CanonicalToolSchema(
        name="sqlmap_attack",
        description="Execute automated SQL injection detection and extraction.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "Target URL containing injection parameter or form action", example="http://127.0.0.1:8080/login"),
            "data": ToolParameterSchema("data", "string", False, "POST data string", example="username=admin&password=123"),
            "level": ToolParameterSchema("level", "string", False, "Scan depth level 1-5", example="2"),
        },
        category="exploitation",
        aliases={"target_url": "url", "endpoint": "url", "target": "url"}
    ),
    "nmap_scan": CanonicalToolSchema(
        name="nmap_scan",
        description="Scan network target for open TCP/UDP ports and service banners.",
        parameters={
            "target": ToolParameterSchema("target", "string", True, "Target IP or hostname", example="127.0.0.1"),
            "ports": ToolParameterSchema("ports", "string", False, "Port specification", example="80,443,8080"),
        },
        category="recon",
        aliases={"host": "target", "ip": "target", "target_host": "target"}
    ),
    "lfi_scan": CanonicalToolSchema(
        name="lfi_scan",
        description="Test target URL parameter for Local File Inclusion and directory traversal.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "Target URL with file parameter", example="http://127.0.0.1:8080/view?file=test"),
            "param": ToolParameterSchema("param", "string", False, "Specific parameter name to test", example="file"),
        },
        category="exploitation",
        aliases={"target_url": "url", "endpoint": "url", "target": "url", "file_param": "param"}
    ),
    "xss_scan": CanonicalToolSchema(
        name="xss_scan",
        description="Test target input fields for Reflected/DOM Cross-Site Scripting.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "Target URL", example="http://127.0.0.1:8080/search?q=test"),
        },
        category="exploitation",
        aliases={"target_url": "url", "endpoint": "url", "target": "url"}
    ),
    "web_fetch": CanonicalToolSchema(
        name="web_fetch",
        description="Fetch single HTTP web resource body.",
        parameters={
            "url": ToolParameterSchema("url", "string", True, "URL to retrieve", example="http://127.0.0.1:8080/robots.txt"),
        },
        category="recon",
        aliases={"target_url": "url", "endpoint": "url", "target": "url"}
    ),
}


@dataclass
class ParsedToolCall:
    tool_name: str
    arguments: Dict[str, Any]
    thought: str = ""
    raw_source: str = ""
    is_valid: bool = False
    validation_error: Optional[str] = None
    structured_error: Optional[Dict[str, Any]] = None


class ToolCallParser:
    """
    Robust multi-format tool call extractor supporting:
    - Markdown fenced JSON blocks (```json ... ```)
    - Raw JSON objects ({"tool": "...", "arguments": {...}})
    - XML style tool calls (<tool_call><name>...</name><arguments>...</arguments></tool_call>)
    - Hermes function calls (<function_call>...)
    """

    @classmethod
    def parse(cls, raw_text: str) -> Optional[ParsedToolCall]:
        if not raw_text or not raw_text.strip():
            return None

        # 1. Look for markdown fenced json block
        json_fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", raw_text, re.IGNORECASE)
        if json_fenced:
            try:
                data = json.loads(json_fenced.group(1))
                tool = data.get("tool") or data.get("name") or data.get("tool_name")
                args = data.get("arguments") or data.get("parameters") or data.get("args") or {}
                thought = data.get("thought") or data.get("reasoning") or ""
                if tool:
                    return ParsedToolCall(tool_name=str(tool).strip(), arguments=args if isinstance(args, dict) else {}, thought=str(thought), raw_source=raw_text)
            except Exception:
                pass

        # 2. Look for XML <tool_call> block
        xml_match = re.search(r"<tool_call>\s*(?:<name>(.*?)</name>)?\s*(?:<arguments>(.*?)</arguments>)?\s*(\{[\s\S]*?\})?\s*</tool_call>", raw_text, re.DOTALL)
        if xml_match:
            name = xml_match.group(1)
            raw_args = xml_match.group(2)
            raw_json = xml_match.group(3)

            if raw_json:
                try:
                    data = json.loads(raw_json)
                    return ParsedToolCall(
                        tool_name=data.get("name", name or "unknown"),
                        arguments=data.get("arguments", {}),
                        raw_source=raw_text
                    )
                except Exception:
                    pass
            elif name:
                args = {}
                if raw_args:
                    # Check if arguments contains XML tags or JSON
                    try:
                        args = json.loads(raw_args)
                    except Exception:
                        for m in re.finditer(r"<([^>]+)>(.*?)</\1>", raw_args):
                            args[m.group(1)] = m.group(2).strip()
                return ParsedToolCall(tool_name=name.strip(), arguments=args, raw_source=raw_text)

        # 3. Look for raw top-level JSON with "tool" or "name"
        json_obj = re.search(r"(\{\s*\"(?:thought|tool|name|action)\"[\s\S]*?\})", raw_text)
        if json_obj:
            try:
                data = json.loads(json_obj.group(1))
                tool = data.get("tool") or data.get("name") or data.get("tool_name") or data.get("action")
                args = data.get("arguments") or data.get("parameters") or data.get("args") or {}
                thought = data.get("thought") or data.get("reasoning") or ""
                if tool:
                    return ParsedToolCall(tool_name=str(tool).strip(), arguments=args if isinstance(args, dict) else {}, thought=str(thought), raw_source=raw_text)
            except Exception:
                pass

        return None


SECRET_KEYWORDS = {"password", "token", "secret", "auth", "credential", "api_key", "cookie", "private_key"}

def sanitize_value(key: str, val: Any) -> Any:
    """Sanitizes sensitive values in error logs and feedback to prevent secret leakage."""
    key_lower = str(key).lower()
    if any(sk in key_lower for sk in SECRET_KEYWORDS):
        return "[REDACTED]"
    if isinstance(val, str) and any(sk in val.lower() for sk in ["bearer ", "secret_", "token=", "pass="]):
        return "[REDACTED]"
    return val


class ToolCallValidator:
    """
    Validates tool calls against canonical schemas and generates standardized structured repair feedback.
    """

    @classmethod
    def _build_expected_schema(cls, schema: CanonicalToolSchema) -> Dict[str, Any]:
        return {
            p_name: {
                "param_type": p.param_type,
                "required": p.required,
                "description": p.description,
                "enum_values": p.enum_values,
                "example": p.example,
            }
            for p_name, p in schema.parameters.items()
        }

    @classmethod
    def validate(cls, parsed: Optional[ParsedToolCall]) -> Tuple[bool, Optional[str]]:
        if parsed is None or not isinstance(parsed, ParsedToolCall):
            err = "TOOL_ARGUMENT_ERROR: Malformed or missing tool call object."
            return False, err

        if not parsed.tool_name or not parsed.tool_name.strip():
            err = "TOOL_SCHEMA_ERROR: Tool call is missing tool name."
            parsed.is_valid = False
            parsed.validation_error = err
            parsed.structured_error = {
                "SCHEMA_ERROR": True,
                "error_type": "SCHEMA_ERROR",
                "tool_name": "",
                "EXPECTED_SCHEMA": {},
                "RECEIVED_FIELDS": [],
                "REPAIRABLE": False,
                "RETRY_ALLOWED": False,
                "message": err,
            }
            return False, err

        schema = CANONICAL_TOOL_REGISTRY.get(parsed.tool_name)
        if not schema:
            # Check if tool exists in wider system registry
            from security_agent.tools.registry import create_authoritative_registry
            try:
                wider = create_authoritative_registry()
                if parsed.tool_name in wider.tools:
                    parsed.is_valid = True
                    parsed.validation_error = None
                    parsed.structured_error = None
                    return True, None
            except Exception:
                pass
            err = f"TOOL_UNKNOWN_ERROR: Tool '{parsed.tool_name}' is not registered in canonical or system tool registries."
            parsed.is_valid = False
            parsed.validation_error = err
            parsed.structured_error = {
                "SCHEMA_ERROR": True,
                "error_type": "SCHEMA_ERROR",
                "tool_name": parsed.tool_name,
                "EXPECTED_SCHEMA": {},
                "RECEIVED_FIELDS": list(parsed.arguments.keys()) if isinstance(parsed.arguments, dict) else [],
                "REPAIRABLE": False,
                "RETRY_ALLOWED": False,
                "message": err,
            }
            return False, err

        if not isinstance(parsed.arguments, dict):
            err = f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' arguments must be a dictionary, got {type(parsed.arguments).__name__}."
            parsed.is_valid = False
            parsed.validation_error = err
            parsed.structured_error = {
                "SCHEMA_ERROR": True,
                "error_type": "SCHEMA_ERROR",
                "tool_name": parsed.tool_name,
                "EXPECTED_SCHEMA": cls._build_expected_schema(schema),
                "RECEIVED_FIELDS": [],
                "REPAIRABLE": False,
                "RETRY_ALLOWED": False,
                "message": err,
            }
            return False, err

        args = parsed.arguments or {}
        expected_schema = cls._build_expected_schema(schema)
        aliases = getattr(schema, "aliases", {})

        # 1. Check for unknown fields (not defined in parameters and not an authorized canonical alias)
        unknown_fields = [k for k in args.keys() if k not in schema.parameters and k not in aliases]
        if unknown_fields:
            err = (
                f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' received unknown field(s): {unknown_fields}. "
                f"Allowed parameters: {list(schema.parameters.keys())}."
            )
            parsed.is_valid = False
            parsed.validation_error = err
            parsed.structured_error = {
                "SCHEMA_ERROR": True,
                "error_type": "SCHEMA_ERROR",
                "tool_name": parsed.tool_name,
                "EXPECTED_SCHEMA": expected_schema,
                "RECEIVED_FIELDS": list(args.keys()),
                "REPAIRABLE": True,
                "RETRY_ALLOWED": True,
                "unknown_fields": unknown_fields,
                "message": err,
            }
            return False, err

        # 2. Check required parameters and canonical aliases
        for p_name, param in schema.parameters.items():
            if param.required and p_name not in args:
                # Check for explicit canonical alias first
                found_alias = next((a for a, c in aliases.items() if c == p_name and a in args), None)
                if not found_alias:
                    fallback_synonyms = {
                        "url": ["target_url", "endpoint", "uri", "target"],
                        "target": ["host", "ip", "url", "target_host"],
                        "action": ["type", "interaction"],
                    }.get(p_name, [])
                    found_alias = next((s for s in fallback_synonyms if s in args), None)

                if found_alias:
                    err = (
                        f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' received parameter '{found_alias}'. "
                        f"Expected canonical parameter name '{p_name}'. "
                        f"Correct parameter name to '{p_name}' and retry."
                    )
                    repairable = True
                else:
                    err = (
                        f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' missing required parameter '{p_name}'. "
                        f"Description: {param.description}. Example: {param.example}."
                    )
                    repairable = True

                parsed.is_valid = False
                parsed.validation_error = err
                parsed.structured_error = {
                    "SCHEMA_ERROR": True,
                    "error_type": "SCHEMA_ERROR",
                    "tool_name": parsed.tool_name,
                    "EXPECTED_SCHEMA": expected_schema,
                    "RECEIVED_FIELDS": list(args.keys()),
                    "REPAIRABLE": repairable,
                    "RETRY_ALLOWED": True,
                    "missing_parameter": p_name,
                    "synonym_detected": found_alias,
                    "canonical_field": p_name,
                    "message": err,
                }
                return False, err

        # 3. Check parameter types
        for p_name, val in args.items():
            if p_name in schema.parameters:
                param = schema.parameters[p_name]
                type_mismatch = False
                if param.param_type == "string" and isinstance(val, (dict, list)):
                    type_mismatch = True
                elif param.param_type in ("object", "dict") and not isinstance(val, dict):
                    type_mismatch = True
                elif param.param_type in ("array", "list") and not isinstance(val, list):
                    type_mismatch = True
                elif param.param_type == "integer" and not isinstance(val, int) and not (isinstance(val, str) and val.isdigit()):
                    type_mismatch = True

                if type_mismatch:
                    err = (
                        f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' parameter '{p_name}' expected type '{param.param_type}', "
                        f"got {type(val).__name__}."
                    )
                    parsed.is_valid = False
                    parsed.validation_error = err
                    parsed.structured_error = {
                        "SCHEMA_ERROR": True,
                        "error_type": "SCHEMA_ERROR",
                        "tool_name": parsed.tool_name,
                        "EXPECTED_SCHEMA": expected_schema,
                        "RECEIVED_FIELDS": list(args.keys()),
                        "REPAIRABLE": True,
                        "RETRY_ALLOWED": True,
                        "parameter": p_name,
                        "expected_type": param.param_type,
                        "received_type": type(val).__name__,
                        "message": err,
                    }
                    return False, err

        # 4. Check enum constraints with secret redaction
        for p_name, val in args.items():
            if p_name in schema.parameters:
                param = schema.parameters[p_name]
                if param.enum_values and str(val).upper() not in [e.upper() for e in param.enum_values]:
                    safe_val = sanitize_value(p_name, val)
                    err = (
                        f"TOOL_ARGUMENT_ERROR: Tool '{parsed.tool_name}' parameter '{p_name}' has invalid value '{safe_val}'. "
                        f"Allowed values: {param.enum_values}."
                    )
                    parsed.is_valid = False
                    parsed.validation_error = err
                    parsed.structured_error = {
                        "SCHEMA_ERROR": True,
                        "error_type": "SCHEMA_ERROR",
                        "tool_name": parsed.tool_name,
                        "EXPECTED_SCHEMA": expected_schema,
                        "RECEIVED_FIELDS": list(args.keys()),
                        "REPAIRABLE": True,
                        "RETRY_ALLOWED": True,
                        "invalid_parameter": p_name,
                        "invalid_value": safe_val,
                        "allowed_values": param.enum_values,
                        "message": err,
                    }
                    return False, err

        parsed.is_valid = True
        parsed.validation_error = None
        parsed.structured_error = None
        return True, None

    @classmethod
    def get_structured_repair_feedback(cls, parsed: ParsedToolCall) -> Optional[Dict[str, Any]]:
        """Returns structured error feedback dict for tool call self-repair."""
        if parsed.is_valid or parsed.structured_error is None:
            return None
        return parsed.structured_error

    @classmethod
    def validate_structured(cls, parsed: ParsedToolCall) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Validates tool call and returns (is_valid, error_string, structured_error_dict)."""
        is_valid, err = cls.validate(parsed)
        return is_valid, err, parsed.structured_error



@dataclass
class ToolReliabilityMetrics:
    total_calls_attempted: int = 0
    raw_tool_call_success: int = 0
    schema_errors: int = 0
    argument_repairs: int = 0
    retry_successes: int = 0

    @property
    def raw_tool_call_success_rate(self) -> float:
        if self.total_calls_attempted == 0:
            return 100.0
        return (self.raw_tool_call_success / self.total_calls_attempted) * 100.0

    @property
    def schema_error_rate(self) -> float:
        if self.total_calls_attempted == 0:
            return 0.0
        return (self.schema_errors / self.total_calls_attempted) * 100.0
