"""
Tests for Model Providers: Ollama, OpenAI, Gemini, Anthropic, OpenAI-Compatible, and Factory.
"""

import pytest
import json
import httpx
from unittest.mock import MagicMock, patch
from security_agent.model.provider import ModelProvider
from security_agent.model.ollama import OllamaProvider
from security_agent.model.openai_provider import OpenAIProvider
from security_agent.model.gemini_provider import GeminiProvider
from security_agent.model.anthropic_provider import AnthropicProvider
from security_agent.model.openai_compatible import OpenAICompatibleProvider
from security_agent.model.factory import (
    resolve_provider_and_model,
    get_model_provider,
    list_supported_providers,
)

def test_resolve_provider_and_model():
    p, m = resolve_provider_and_model("ollama/qwen3:8b")
    assert p == "ollama"
    assert m == "qwen3:8b"

    p, m = resolve_provider_and_model("openai/gpt-4o")
    assert p == "openai"
    assert m == "gpt-4o"

    p, m = resolve_provider_and_model("gpt-4o")
    assert p == "openai"
    assert m == "gpt-4o"

    p, m = resolve_provider_and_model("claude-3-5-sonnet")
    assert p == "anthropic"
    assert m == "claude-3-5-sonnet"

    p, m = resolve_provider_and_model("gemini-2.0-flash")
    assert p == "gemini"
    assert m == "gemini-2.0-flash"

    p, m = resolve_provider_and_model("custom/my-llama")
    assert p == "openai-compatible"
    assert m == "my-llama"

def test_list_supported_providers():
    providers = list_supported_providers()
    ids = [p["id"] for p in providers]
    assert "ollama" in ids
    assert "openai" in ids
    assert "gemini" in ids
    assert "anthropic" in ids
    assert "openai-compatible" in ids

def test_openai_provider_mocked():
    provider = OpenAIProvider(model_name="gpt-4o", api_key="sk-proj-mocktestkey12345678901234567890")
    assert "sk-proj-mocktestkey" not in repr(provider)
    assert "..." in repr(provider)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "TEST_OPENAI_RESPONSE"
            }
        }]
    }

    with patch.object(provider.client, "post", return_value=mock_resp):
        res = provider.chat([{"role": "user", "content": "hi"}])
        assert res["message"]["content"] == "TEST_OPENAI_RESPONSE"

def test_openai_missing_key():
    provider = OpenAIProvider(model_name="gpt-4o", api_key=None)
    with pytest.raises(ValueError, match="OpenAI API key is missing"):
        provider.chat([{"role": "user", "content": "hi"}])

def test_gemini_provider_mocked():
    provider = GeminiProvider(model_name="gemini-2.0-flash", api_key="mock-gemini-key-12345")
    assert "mock-gemini" not in repr(provider)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{
            "content": {
                "parts": [{"text": "TEST_GEMINI_RESPONSE"}]
            }
        }]
    }

    with patch.object(provider.client, "post", return_value=mock_resp):
        res = provider.chat([{"role": "user", "content": "hi"}])
        assert res["message"]["content"] == "TEST_GEMINI_RESPONSE"

def test_anthropic_provider_mocked():
    provider = AnthropicProvider(model_name="claude-3-5-sonnet", api_key="sk-ant-mocktestkey1234567890")
    assert "sk-ant-mock" not in repr(provider)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{
            "type": "text",
            "text": "TEST_ANTHROPIC_RESPONSE"
        }]
    }

    with patch.object(provider.client, "post", return_value=mock_resp):
        res = provider.chat([{"role": "user", "content": "hi"}])
        assert res["message"]["content"] == "TEST_ANTHROPIC_RESPONSE"

def test_openai_compatible_provider():
    provider = OpenAICompatibleProvider(
        model_name="mistral-7b",
        base_url="http://localhost:8000/v1",
        api_key="token"
    )
    caps = provider.capabilities()
    assert caps["provider"] == "openai-compatible"
    assert caps["local"] is True
