"""Tests for prompt caching and cache reporting (roadmap A4)."""

import json
from typing import Any, Dict, List

import pytest

from core.usage import SessionUsage, usage_to_metrics
from model import anthropic_provider
from model.anthropic_provider import AnthropicProvider

TOOLS = [
    {"type": "function", "function": {"name": "file_read", "description": "Read", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "file_edit", "description": "Edit", "parameters": {"type": "object", "properties": {}}}},
]


# -- usage reporting ---------------------------------------------------------------------------

def test_anthropic_usage_counts_cache_reads_and_writes_as_prompt_tokens():
    metrics = usage_to_metrics({"input_tokens": 50, "cache_read_input_tokens": 900,
                                "cache_creation_input_tokens": 100, "output_tokens": 20})
    assert metrics == {"prompt_eval_count": 1050, "eval_count": 20,
                       "cached_prompt_tokens": 900, "cache_write_tokens": 100}


def test_openai_usage_reads_cached_tokens_from_details():
    metrics = usage_to_metrics({"prompt_tokens": 1200, "completion_tokens": 30,
                                "prompt_tokens_details": {"cached_tokens": 1024}})
    assert metrics == {"prompt_eval_count": 1200, "eval_count": 30, "cached_prompt_tokens": 1024}


@pytest.mark.parametrize("usage", [None, {}, {"prompt_tokens": 10, "completion_tokens": 2, "prompt_tokens_details": None}])
def test_usage_without_cache_figures_reports_none(usage):
    assert "cached_prompt_tokens" not in usage_to_metrics(usage)


def test_session_hit_rate_and_bad_figures_are_clamped():
    usage = SessionUsage()
    assert usage.cache_hit_percent is None
    usage.record(1000, 10)
    usage.record(1000, 10, cached_tokens=900)
    usage.record(100, 10, cached_tokens=5000)  # a cached figure larger than the prompt is impossible
    assert usage.cached_input_tokens == 1000
    assert usage.cache_hit_percent == 48  # 1000 of 2100


# -- Anthropic request payloads ----------------------------------------------------------------

class Response:
    status_code = 200

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


@pytest.fixture
def sent(monkeypatch):
    payloads: List[Dict[str, Any]] = []

    def fake_post(client, url, headers, payload):
        payloads.append(json.loads(json.dumps(payload)))
        return Response({"content": [{"type": "text", "text": "ok"}],
                         "usage": {"input_tokens": 5, "cache_read_input_tokens": 700, "output_tokens": 2}})

    monkeypatch.setattr(anthropic_provider, "post_with_retries", fake_post)
    return payloads


def provider(caching=True):
    return AnthropicProvider(model_name="claude-test", api_key="test-key", prompt_caching=caching)


def test_system_prompt_is_the_cache_breakpoint(sent):
    result = provider().chat([{"role": "system", "content": "You are Buzzard."}, {"role": "user", "content": "hi"}], tools=TOOLS)
    system = sent[0]["system"]
    assert system == [{"type": "text", "text": "You are Buzzard.", "cache_control": {"type": "ephemeral"}}]
    assert all("cache_control" not in tool for tool in sent[0]["tools"])  # the system breakpoint covers the tools
    assert all("cache_control" not in json.dumps(message) for message in sent[0]["messages"])
    assert usage_to_metrics(result["raw"]["usage"])["cached_prompt_tokens"] == 700


def test_without_a_system_prompt_the_last_tool_is_marked(sent):
    provider().chat([{"role": "user", "content": "hi"}], tools=TOOLS)
    tools = sent[0]["tools"]
    assert tools[-1]["cache_control"] == {"type": "ephemeral"} and "cache_control" not in tools[0]
    assert "system" not in sent[0]


def test_caching_can_be_turned_off(sent):
    provider(caching=False).chat([{"role": "system", "content": "rules"}, {"role": "user", "content": "hi"}], tools=TOOLS)
    assert sent[0]["system"] == "rules"
    assert "cache_control" not in json.dumps(sent[0])


def test_the_prefix_is_identical_across_turns(sent):
    """Only an unchanged prefix can be served from the cache, so two turns must send the same one."""
    first = [{"role": "system", "content": "rules"}, {"role": "user", "content": "fix add"}]
    later = first + [{"role": "assistant", "content": "reading"}, {"role": "user", "content": "result"}]
    p = provider()
    p.chat(first, tools=TOOLS)
    p.chat(later, tools=TOOLS)
    assert sent[0]["system"] == sent[1]["system"] and sent[0]["tools"] == sent[1]["tools"]


def test_factory_reads_the_setting(monkeypatch):
    from model.factory import get_model_provider

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    on = get_model_provider("anthropic", "claude-test", config={"model": {"provider": "anthropic"}})
    off = get_model_provider("anthropic", "claude-test", config={"model": {"provider": "anthropic", "prompt_caching": False}})
    assert on.prompt_caching is True and off.prompt_caching is False


# -- streaming usage ---------------------------------------------------------------------------

class Stream:
    status_code = 200

    def __init__(self, events):
        self.lines = [f"data: {json.dumps(event)}" for event in events]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_lines(self):
        return iter(self.lines)


def test_stream_reports_usage_including_cache_reads(monkeypatch):
    p = provider()
    captured = {}

    def fake_stream(method, url, headers=None, json=None):
        captured["payload"] = json
        return Stream([
            {"type": "message_start", "message": {"usage": {"input_tokens": 12, "cache_read_input_tokens": 800, "output_tokens": 1}}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}},
            {"type": "message_delta", "usage": {"output_tokens": 9}},
            {"type": "message_stop"},
        ])

    monkeypatch.setattr(p.client, "stream", fake_stream)
    chunks = list(p.stream_chat([{"role": "system", "content": "rules"}, {"role": "user", "content": "hi"}]))
    assert captured["payload"]["system"][0]["cache_control"] == {"type": "ephemeral"}
    final = chunks[-1]
    assert final["done"] and chunks[0]["message"]["content"] == "Hello"
    assert usage_to_metrics(final["usage"]) == {"prompt_eval_count": 812, "eval_count": 9, "cached_prompt_tokens": 800}
