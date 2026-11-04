"""
Tool-call conversion between provider wire formats and the agent loop's format.

The agent loop represents a call as
{"id": ..., "type": "function", "function": {"name": ..., "arguments": <dict>}}.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Cloud APIs reject "." in function names, while registry names such as terminal.execute use it.
# The mapping is applied only at the provider boundary; policy and dispatch see registry names.
_WIRE_DOT = "__"


def to_wire_name(name: Any) -> Any:
    """Encodes a registry tool name for a cloud provider API."""
    return name.replace(".", _WIRE_DOT) if isinstance(name, str) else name


def from_wire_name(name: Any) -> Any:
    """Decodes a provider tool name back to its registry name."""
    return name.replace(_WIRE_DOT, ".") if isinstance(name, str) else name


def to_openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Returns OpenAI function schemas with wire-safe names."""
    return [
        {**tool, "function": {**(tool.get("function") or {}), "name": to_wire_name((tool.get("function") or {}).get("name"))}}
        for tool in tools
    ]


def parse_tool_arguments(raw_arguments: Any, tool_name: Optional[str]) -> Dict[str, Any]:
    """Converts wire-format JSON arguments to the dict the agent loop dispatches on."""
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if not raw_arguments:
        return {}
    try:
        parsed = json.loads(raw_arguments)
    except (TypeError, ValueError):
        logger.warning("Discarding malformed arguments for tool call '%s'", tool_name)
        return {}
    if not isinstance(parsed, dict):
        logger.warning("Discarding non-object arguments for tool call '%s'", tool_name)
        return {}
    return parsed


def normalize_openai_tool_calls(raw_tool_calls: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Converts OpenAI-format tool calls from a response into the agent loop's format."""
    normalized = []
    for call in raw_tool_calls or []:
        function = call.get("function") or {}
        name = from_wire_name(function.get("name"))
        normalized.append({
            "id": call.get("id"),
            "type": "function",
            "function": {"name": name, "arguments": parse_tool_arguments(function.get("arguments"), name)},
        })
    return normalized


def serialize_openai_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Re-encodes dict tool arguments as the JSON strings Chat Completions requires."""
    serialized = []
    for message in messages:
        if not message.get("tool_calls"):
            serialized.append(message)
            continue
        wire_calls = []
        for call in message["tool_calls"]:
            function = call.get("function") or {}
            arguments = function.get("arguments") or {}
            wire_calls.append({
                **call,
                "type": "function",
                "function": {
                    **function,
                    "name": to_wire_name(function.get("name")),
                    "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments),
                },
            })
        serialized.append({**message, "tool_calls": wire_calls})
    return serialized


def merge_openai_tool_fragments(pending: Dict[int, Dict[str, Any]], fragments: Optional[List[Dict[str, Any]]]) -> None:
    """Accumulates streamed tool-call fragments, which arrive keyed by index across chunks."""
    for fragment in fragments or []:
        call = pending.setdefault(
            fragment.get("index", 0),
            {"id": None, "function": {"name": None, "arguments": ""}},
        )
        call["id"] = fragment.get("id") or call["id"]
        function = fragment.get("function") or {}
        call["function"]["name"] = function.get("name") or call["function"]["name"]
        call["function"]["arguments"] += function.get("arguments") or ""


def finish_openai_tool_fragments(pending: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Returns accumulated streamed tool calls in index order, in the agent loop's format."""
    return normalize_openai_tool_calls([pending[index] for index in sorted(pending)])


def repair_tool_call_pairs(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Makes history valid for native tool APIs, which require each call to be answered before
    any other message. Compaction and early loop exits can break that pairing. Results whose
    call is gone are dropped; calls with no result get an explicit no-result message.
    """
    repaired: List[Dict[str, Any]] = []
    unanswered: List[str] = []

    def answer_remaining() -> None:
        for call_id in unanswered:
            repaired.append({"role": "tool", "content": "[No result recorded for this call.]", "tool_call_id": call_id})
        unanswered.clear()

    for message in messages:
        if message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if call_id in unanswered:
                unanswered.remove(call_id)
                repaired.append(message)
            continue
        answer_remaining()
        repaired.append(message)
        unanswered.extend(call.get("id") for call in message.get("tool_calls") or [] if call.get("id"))
    answer_remaining()
    return repaired


# JSON Schema keywords the Gemini function declaration schema accepts
_GEMINI_SCHEMA_KEYS = frozenset({
    "type", "format", "description", "nullable", "enum", "items", "properties", "required",
    "minimum", "maximum", "minItems", "maxItems", "anyOf",
})


def _to_gemini_schema(schema: Any) -> Any:
    """Removes JSON Schema keywords that Gemini rejects, such as additionalProperties and default."""
    if not isinstance(schema, dict):
        return schema
    cleaned: Dict[str, Any] = {}
    for key, value in schema.items():
        if key not in _GEMINI_SCHEMA_KEYS:
            continue
        if key == "properties" and isinstance(value, dict):
            cleaned[key] = {name: _to_gemini_schema(prop) for name, prop in value.items()}
        elif key == "items":
            cleaned[key] = _to_gemini_schema(value)
        elif key == "anyOf" and isinstance(value, list):
            cleaned[key] = [_to_gemini_schema(option) for option in value]
        else:
            cleaned[key] = value
    return cleaned


def to_gemini_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Converts OpenAI function schemas to a Gemini functionDeclarations tool."""
    declarations = []
    for tool in tools:
        function = tool.get("function") or {}
        declaration: Dict[str, Any] = {
            "name": to_wire_name(function.get("name")),
            "description": function.get("description", ""),
        }
        parameters = _to_gemini_schema(function.get("parameters") or {})
        if parameters.get("properties"):
            declaration["parameters"] = parameters
        declarations.append(declaration)
    return [{"functionDeclarations": declarations}]


def to_gemini_contents(messages: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Converts agent-loop history to Gemini contents, returning (system_instruction, contents).
    Thought signatures return in their original parts, as Gemini 3 rejects calls without them.
    Consecutive same-role turns merge, so parallel function responses share one turn.
    """
    system_instruction: Optional[Dict[str, Any]] = None
    contents: List[Dict[str, Any]] = []
    call_names: Dict[Any, Any] = {}

    def add(role: str, parts: List[Dict[str, Any]]) -> None:
        if contents and contents[-1]["role"] == role:
            contents[-1]["parts"].extend(parts)
        else:
            contents.append({"role": role, "parts": parts})

    for message in messages:
        role = message.get("role", "user")
        content = message.get("content") or ""
        if role == "system":
            system_instruction = {"parts": [{"text": content}]}
        elif role == "tool":
            name = call_names.get(message.get("tool_call_id"), "unknown_tool")
            add("user", [{"functionResponse": {"name": name, "response": {"result": content}}}])
        elif role in ("assistant", "model"):
            parts: List[Dict[str, Any]] = [{"text": content}] if content else []
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                wire_name = to_wire_name(function.get("name"))
                call_names[call.get("id")] = wire_name
                part: Dict[str, Any] = {"functionCall": {
                    "name": wire_name,
                    "args": parse_tool_arguments(function.get("arguments"), function.get("name")),
                }}
                if call.get("thought_signature"):
                    part["thoughtSignature"] = call["thought_signature"]
                parts.append(part)
            if parts:
                add("model", parts)
        else:
            add("user", [{"text": content}])
    return system_instruction, contents


def from_gemini_parts(parts: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Splits Gemini response parts into (visible text, tool calls), skipping thought summaries."""
    text = "".join(part.get("text", "") for part in parts if not part.get("thought"))
    tool_calls = []
    for part in parts:
        function_call = part.get("functionCall")
        if not function_call:
            continue
        call: Dict[str, Any] = {
            "id": function_call.get("id") or f"gemini_{uuid.uuid4().hex[:12]}",
            "type": "function",
            "function": {
                "name": from_wire_name(function_call.get("name")),
                "arguments": function_call.get("args") or {},
            },
        }
        if part.get("thoughtSignature"):
            call["thought_signature"] = part["thoughtSignature"]
        tool_calls.append(call)
    return text, tool_calls


def to_anthropic_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Converts OpenAI function schemas to Anthropic tool definitions."""
    converted = []
    for tool in tools:
        function = tool.get("function") or {}
        converted.append({
            "name": to_wire_name(function.get("name")),
            "description": function.get("description", ""),
            "input_schema": function.get("parameters") or {"type": "object", "properties": {}},
        })
    return converted


def to_anthropic_messages(messages: List[Dict[str, Any]]) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """
    Converts agent-loop history to Anthropic messages, returning (system_prompt, messages).
    Consecutive tool results merge into one user turn, as the Messages API requires
    results for parallel calls to share a turn.
    """
    system_prompt: Optional[str] = None
    converted: List[Dict[str, Any]] = []
    for message in messages:
        role = message.get("role", "user")
        content = message.get("content") or ""
        if role == "system":
            system_prompt = content
        elif role == "tool" and message.get("tool_call_id"):
            block = {"type": "tool_result", "tool_use_id": message["tool_call_id"], "content": content}
            previous = converted[-1] if converted else None
            if previous and previous["role"] == "user" and isinstance(previous["content"], list):
                previous["content"].append(block)
            else:
                converted.append({"role": "user", "content": [block]})
        elif role == "assistant" and message.get("tool_calls"):
            blocks: List[Dict[str, Any]] = [{"type": "text", "text": content}] if content else []
            for call in message["tool_calls"]:
                function = call.get("function") or {}
                blocks.append({
                    "type": "tool_use",
                    "id": call.get("id"),
                    "name": to_wire_name(function.get("name")),
                    "input": parse_tool_arguments(function.get("arguments"), function.get("name")),
                })
            converted.append({"role": "assistant", "content": blocks})
        else:
            converted.append({"role": "assistant" if role == "assistant" else "user", "content": content})
    return system_prompt, converted


def from_anthropic_blocks(blocks: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Splits Anthropic response content blocks into (text, tool calls)."""
    text = "".join(block.get("text", "") for block in blocks if block.get("type") == "text")
    tool_calls = [
        {
            "id": block.get("id"),
            "type": "function",
            "function": {"name": from_wire_name(block.get("name")), "arguments": block.get("input") or {}},
        }
        for block in blocks
        if block.get("type") == "tool_use"
    ]
    return text, tool_calls
