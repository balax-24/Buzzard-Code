"""Wire-format tests for native tool calling. These use mocked HTTP, not live provider APIs."""

import json
import re
from unittest.mock import MagicMock, patch

import httpx
import pytest

from model.anthropic_provider import AnthropicProvider
from model.factory import get_model_provider
from model.gemini_provider import GeminiProvider
from model.openai_compatible import OpenAICompatibleProvider
from model.openai_provider import OpenAIProvider
from model.tool_calls import from_wire_name, repair_tool_call_pairs, to_anthropic_messages, to_wire_name
from tools.registry import create_authoritative_registry

TOOLS = [{"type": "function", "function": {
    "name": "file_read",
    "description": "Reads a file",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
}}]
HISTORY = [
    {"role": "system", "content": "sys"},
    {"role": "user", "content": "read two files"},
    {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "function": {"name": "file_read", "arguments": {"path": "a"}}},
        {"id": "c2", "function": {"name": "file_read", "arguments": {"path": "b"}}},
    ]},
    {"role": "tool", "content": "A", "tool_call_id": "c1"},
    {"role": "tool", "content": "B", "tool_call_id": "c2"},
]


def _response(url: str, body: dict) -> httpx.Response:
    return httpx.Response(200, json=body, request=httpx.Request("POST", url))


def _stream(provider, lines):
    stream_response = MagicMock(status_code=200)
    stream_response.iter_lines.return_value = lines
    patcher = patch.object(provider.client, "stream")
    stream = patcher.start()
    stream.return_value.__enter__.return_value = stream_response
    try:
        return list(provider.stream_chat([{"role": "user", "content": "x"}], tools=TOOLS)), stream
    finally:
        patcher.stop()


@pytest.mark.parametrize("provider_class", [OpenAIProvider, OpenAICompatibleProvider])
def test_openai_chat_round_trip(provider_class):
    provider = provider_class(model_name="m", api_key="k", base_url="https://example.test/v1")
    body = {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c3", "type": "function", "function": {"name": "file_read", "arguments": "{\"path\": \"c\"}"}},
    ]}}]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        message = provider.chat(HISTORY, tools=TOOLS)["message"]
    sent = post.call_args.kwargs["json"]
    assert sent["tools"] == TOOLS
    assert json.loads(sent["messages"][2]["tool_calls"][0]["function"]["arguments"]) == {"path": "a"}
    assert message["content"] == ""
    assert message["tool_calls"][0]["function"] == {"name": "file_read", "arguments": {"path": "c"}}


def test_openai_omits_tools_when_none_given():
    provider = OpenAIProvider(model_name="m", api_key="k")
    body = {"choices": [{"message": {"content": "hi"}}]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        message = provider.chat([{"role": "user", "content": "x"}])["message"]
    assert "tools" not in post.call_args.kwargs["json"]
    assert message["tool_calls"] == []


def test_openai_stream_assembles_tool_call():
    def sse(delta):
        return "data: " + json.dumps({"choices": [{"delta": delta}]})

    provider = OpenAIProvider(model_name="m", api_key="k")
    chunks, stream = _stream(provider, [
        sse({"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "file_read", "arguments": "{\"pa"}}]}),
        sse({"tool_calls": [{"index": 0, "function": {"arguments": "th\": \"a\"}"}}]}),
        "data: [DONE]",
    ])
    assert stream.call_args.kwargs["json"]["tools"] == TOOLS
    assert chunks[-1]["message"]["tool_calls"][0]["function"]["arguments"] == {"path": "a"}


def test_anthropic_history_merges_parallel_tool_results():
    system, converted = to_anthropic_messages(HISTORY)
    assert system == "sys"
    assert [block["id"] for block in converted[1]["content"]] == ["c1", "c2"]
    assert converted[1]["content"][0]["input"] == {"path": "a"}
    assert converted[2]["role"] == "user"
    assert [block["tool_use_id"] for block in converted[2]["content"]] == ["c1", "c2"]


def test_anthropic_chat_sends_input_schema_and_returns_tool_use():
    provider = AnthropicProvider(model_name="m", api_key="k")
    body = {"content": [
        {"type": "text", "text": "reading"},
        {"type": "tool_use", "id": "t1", "name": "file_read", "input": {"path": "a"}},
    ]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        message = provider.chat(HISTORY, tools=TOOLS)["message"]
    assert post.call_args.kwargs["json"]["tools"][0]["input_schema"] == TOOLS[0]["function"]["parameters"]
    assert message["content"] == "reading"
    assert message["tool_calls"][0]["id"] == "t1"
    assert message["tool_calls"][0]["function"] == {"name": "file_read", "arguments": {"path": "a"}}


def test_anthropic_stream_assembles_tool_use():
    def sse(event):
        return "data: " + json.dumps(event)

    provider = AnthropicProvider(model_name="m", api_key="k")
    chunks, _ = _stream(provider, [
        sse({"type": "content_block_start", "index": 1,
             "content_block": {"type": "tool_use", "id": "t1", "name": "file_read"}}),
        sse({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"pa"}}),
        sse({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "th\": \"a\"}"}}),
        sse({"type": "message_stop"}),
    ])
    assert chunks[-1]["message"]["tool_calls"][0]["id"] == "t1"
    assert chunks[-1]["message"]["tool_calls"][0]["function"]["arguments"] == {"path": "a"}


DOTTED_TOOLS = [{"type": "function", "function": {"name": "terminal.execute", "description": "", "parameters": {}}}]
DOTTED_HISTORY = [
    {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "function": {"name": "terminal.execute", "arguments": {"command": "ls"}}},
    ]},
    {"role": "tool", "content": "ok", "tool_call_id": "c1"},
]


def test_every_registry_tool_name_is_valid_on_the_wire_and_round_trips():
    for schema in create_authoritative_registry().export_schemas():
        name = schema["function"]["name"]
        wire_name = to_wire_name(name)
        assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", wire_name), name
        assert from_wire_name(wire_name) == name


def test_openai_encodes_dotted_names_and_decodes_replies():
    provider = OpenAIProvider(model_name="m", api_key="k")
    body = {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c2", "function": {"name": "terminal__execute", "arguments": "{}"}},
    ]}}]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        message = provider.chat(DOTTED_HISTORY, tools=DOTTED_TOOLS)["message"]
    sent = post.call_args.kwargs["json"]
    assert sent["tools"][0]["function"]["name"] == "terminal__execute"
    assert sent["messages"][0]["tool_calls"][0]["function"]["name"] == "terminal__execute"
    assert message["tool_calls"][0]["function"]["name"] == "terminal.execute"
    assert DOTTED_TOOLS[0]["function"]["name"] == "terminal.execute"


def test_anthropic_encodes_dotted_names_and_decodes_replies():
    provider = AnthropicProvider(model_name="m", api_key="k")
    body = {"content": [{"type": "tool_use", "id": "t1", "name": "terminal__execute", "input": {}}]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        message = provider.chat(DOTTED_HISTORY, tools=DOTTED_TOOLS)["message"]
    sent = post.call_args.kwargs["json"]
    assert sent["tools"][0]["name"] == "terminal__execute"
    assert sent["messages"][0]["content"][0]["name"] == "terminal__execute"
    assert message["tool_calls"][0]["function"]["name"] == "terminal.execute"


def test_streamed_dotted_name_is_decoded():
    def sse(delta):
        return "data: " + json.dumps({"choices": [{"delta": delta}]})

    provider = OpenAIProvider(model_name="m", api_key="k")
    chunks, _ = _stream(provider, [
        sse({"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "terminal__execute", "arguments": "{}"}}]}),
        "data: [DONE]",
    ])
    assert chunks[-1]["message"]["tool_calls"][0]["function"]["name"] == "terminal.execute"


def test_repair_drops_orphan_results_and_answers_unanswered_calls():
    call = {"id": "c1", "function": {"name": "file_read", "arguments": {}}}
    repaired = repair_tool_call_pairs([
        {"role": "tool", "content": "orphan", "tool_call_id": "gone"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "user", "content": "next"},
    ])
    assert [message["role"] for message in repaired] == ["assistant", "tool", "user"]
    assert "No result recorded" in repaired[1]["content"]


def test_repair_keeps_valid_history_unchanged():
    assert repair_tool_call_pairs(HISTORY) == HISTORY


GEMINI_REPLY = {"candidates": [{"content": {"parts": [
    {"text": "thinking out loud", "thought": True},
    {"functionCall": {"name": "terminal__execute", "args": {"command": "ls"}}, "thoughtSignature": "sig-1"},
    {"functionCall": {"name": "file_read", "args": {"path": "a"}}},
]}}]}


def _gemini():
    return GeminiProvider(model_name="m", api_key="secret-key-value")


def test_gemini_sends_key_in_header_never_url_and_cleans_schema():
    provider = _gemini()
    tools = [{"type": "function", "function": {"name": "terminal.execute", "description": "d", "parameters": {
        "type": "object", "additionalProperties": False, "$schema": "x",
        "properties": {"command": {"type": "string", "default": "ls"}},
    }}}]
    with patch.object(provider.client, "post", return_value=_response("https://example.test", GEMINI_REPLY)) as post:
        provider.chat([{"role": "user", "content": "x"}], tools=tools)
    assert "secret-key-value" not in post.call_args.args[0]
    assert post.call_args.kwargs["headers"]["x-goog-api-key"] == "secret-key-value"
    declaration = post.call_args.kwargs["json"]["tools"][0]["functionDeclarations"][0]
    assert declaration["name"] == "terminal__execute"
    assert declaration["parameters"] == {"type": "object", "properties": {"command": {"type": "string"}}}


def test_gemini_round_trip_preserves_signature_and_groups_responses():
    provider = _gemini()
    with patch.object(provider.client, "post", return_value=_response("https://example.test", GEMINI_REPLY)):
        message = provider.chat([{"role": "user", "content": "x"}])["message"]
    assert message["content"] == ""
    first, second = message["tool_calls"]
    assert first["function"] == {"name": "terminal.execute", "arguments": {"command": "ls"}}
    assert first["id"] != second["id"]
    history = [
        {"role": "user", "content": "x"},
        {"role": "assistant", "content": "", "tool_calls": message["tool_calls"]},
        {"role": "tool", "content": "out1", "tool_call_id": first["id"]},
        {"role": "tool", "content": "out2", "tool_call_id": second["id"]},
    ]
    _, contents = provider._convert_messages(history)
    assert contents[1]["parts"][0]["thoughtSignature"] == "sig-1"
    assert contents[1]["parts"][0]["functionCall"]["name"] == "terminal__execute"
    assert [part["functionResponse"]["name"] for part in contents[2]["parts"]] == ["terminal__execute", "file_read"]


def test_gemini_retries_429_using_requested_delay():
    provider = _gemini()
    limited = httpx.Response(429, text='{"retryDelay": "7s"}', request=httpx.Request("POST", "https://example.test"))
    success = _response("https://example.test", {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]})
    with patch.object(provider.client, "post", side_effect=[limited, success]), patch("time.sleep") as sleep:
        assert provider.chat([{"role": "user", "content": "x"}])["message"]["content"] == "ok"
    sleep.assert_called_once_with(8.0)


def test_gemini_error_never_contains_key():
    provider = _gemini()
    failure = httpx.Response(400, text="bad secret-key-value", request=httpx.Request("POST", "https://example.test"))
    with patch.object(provider.client, "post", return_value=failure):
        with pytest.raises(RuntimeError) as error:
            provider.chat([{"role": "user", "content": "x"}])
    assert "secret-key-value" not in str(error.value)


def test_configured_endpoint_is_not_reused_for_another_provider():
    config = {"model": {"provider": "ollama", "name": "local", "endpoint": "http://attacker.example:11434"}}
    for provider_name in ("gemini", "openai", "anthropic", "meta"):
        provider = get_model_provider(provider_name=provider_name, model_name="m", config=config, api_key="k")
        assert "attacker.example" not in provider.base_url, provider_name


def test_configured_endpoint_applies_to_its_own_provider():
    config = {"model": {"provider": "gemini", "name": "m", "endpoint": "https://proxy.example/v1beta"}}
    provider = get_model_provider(provider_name="gemini", model_name="m", config=config, api_key="k")
    assert provider.base_url == "https://proxy.example/v1beta"


def test_output_token_limit_is_configurable(monkeypatch):
    provider = OpenAIProvider(model_name="m", api_key="k")
    body = {"choices": [{"message": {"content": "hi"}}]}
    with patch.object(provider.client, "post", return_value=_response("https://example.test", body)) as post:
        provider.chat([{"role": "user", "content": "x"}])
        assert "max_tokens" not in post.call_args.kwargs["json"]
        monkeypatch.setenv("BUZZARD_MAX_OUTPUT_TOKENS", "1024")
        provider.chat([{"role": "user", "content": "x"}])
        assert post.call_args.kwargs["json"]["max_tokens"] == 1024
