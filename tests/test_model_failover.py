"""Failover behaviour, using real provider objects where the wire format matters."""

from unittest.mock import patch

import httpx
import pytest

from model.factory import get_model_provider
from model.failover import AllProvidersFailedError, FailoverProvider
from model.gemini_provider import GeminiProvider
from model.openai_provider import OpenAIProvider
from model.provider import ModelProvider


class Fake(ModelProvider):
    def __init__(self, name, fail=False, native=True, stream_failure_after=None):
        self.model_name = name
        self.fail = fail
        self.native = native
        self.stream_failure_after = stream_failure_after
        self.calls = 0

    def chat(self, messages, tools=None, options=None):
        self.calls += 1
        if self.fail:
            raise RuntimeError(f"{self.model_name} is down")
        return {"message": {"role": "assistant", "content": self.model_name}}

    def stream_chat(self, messages, tools=None, options=None):
        self.calls += 1
        if self.fail:
            raise RuntimeError(f"{self.model_name} is down")
        yield {"message": {"content": self.model_name}}
        if self.stream_failure_after:
            raise RuntimeError("connection lost")

    def generate(self, prompt, system_prompt=None, options=None):
        return self.model_name

    def is_available(self):
        return not self.fail

    def get_available_models(self):
        return [self.model_name]

    def capabilities(self):
        return {"native_tools": self.native}


MESSAGES = [{"role": "user", "content": "hi"}]


def test_moves_to_next_model_and_reports_which_is_active():
    chain = FailoverProvider([Fake("a", fail=True), Fake("b")])
    assert chain.chat(MESSAGES)["message"]["content"] == "b"
    assert chain.model_name == "b"


def test_failed_model_is_skipped_during_cooldown_then_retried():
    first, second = Fake("a", fail=True), Fake("b")
    chain = FailoverProvider([first, second], cooldown_seconds=1000)
    chain.chat(MESSAGES)
    chain.chat(MESSAGES)
    assert first.calls == 1
    chain = FailoverProvider([first, second], cooldown_seconds=0)
    first.fail = False
    chain.chat(MESSAGES)
    assert chain.model_name == "a"


def test_cooling_model_is_a_last_resort_rather_than_giving_up():
    first, second = Fake("a", fail=True), Fake("b", fail=True)
    chain = FailoverProvider([first, second], cooldown_seconds=1000)
    with pytest.raises(AllProvidersFailedError):
        chain.chat(MESSAGES)
    first.fail = False
    assert chain.chat(MESSAGES)["message"]["content"] == "a"


def test_all_failed_error_names_each_model():
    chain = FailoverProvider([Fake("a", fail=True), Fake("b", fail=True)])
    with pytest.raises(AllProvidersFailedError, match="a is down.*b is down"):
        chain.chat(MESSAGES)


def test_stream_fails_over_before_any_output():
    chain = FailoverProvider([Fake("a", fail=True), Fake("b")])
    assert [chunk["message"]["content"] for chunk in chain.stream_chat(MESSAGES)] == ["b"]


def test_stream_failure_after_output_is_not_silently_retried():
    second = Fake("b")
    chain = FailoverProvider([Fake("a", stream_failure_after=True), second])
    with pytest.raises(RuntimeError, match="connection lost"):
        list(chain.stream_chat(MESSAGES))
    assert second.calls == 0


def test_native_tools_claimed_only_if_all_support_them():
    assert FailoverProvider([Fake("a"), Fake("b")]).capabilities()["native_tools"] is True
    assert FailoverProvider([Fake("a"), Fake("b", native=False)]).capabilities()["native_tools"] is False


def test_real_providers_fail_over_on_http_errors():
    down = OpenAIProvider(model_name="primary", api_key="k", base_url="https://down.example/v1")
    up = GeminiProvider(model_name="backup", api_key="k")
    failure = httpx.Response(401, text="bad key", request=httpx.Request("POST", "https://down.example"))
    success = httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": [{"text": "from backup"}]}}]},
        request=httpx.Request("POST", "https://up.example"),
    )
    chain = FailoverProvider([down, up])
    with patch.object(down.client, "post", return_value=failure), patch.object(up.client, "post", return_value=success):
        assert chain.chat(MESSAGES)["message"]["content"] == "from backup"


def test_no_fallbacks_means_no_wrapper(monkeypatch):
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)
    config = {"model": {"provider": "openai", "name": "m"}}
    assert isinstance(get_model_provider(config=config, api_key="k"), OpenAIProvider)


def test_fallbacks_come_only_from_explicit_configuration(monkeypatch):
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)
    config = {"model": {"provider": "openai", "name": "m", "fallbacks": ["gemini/backup"]}}
    chain = get_model_provider(config=config, api_key="k")
    assert [provider.model_name for provider in chain.providers] == ["m", "backup"]

    monkeypatch.setenv("BUZZARD_FALLBACK_MODELS", "anthropic/other")
    chain = get_model_provider(config={"model": {"provider": "openai", "name": "m"}}, api_key="k")
    assert [provider.model_name for provider in chain.providers] == ["m", "other"]


def test_primary_api_key_is_not_given_to_fallback(monkeypatch):
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    config = {"model": {"provider": "openai", "name": "m", "fallbacks": ["gemini/backup"]}}
    with patch("model.gemini_provider.get_credential", return_value=None):
        chain = get_model_provider(config=config, api_key="primary-secret")
    assert chain.providers[1].api_key != "primary-secret"


def test_primary_is_not_repeated_as_its_own_fallback(monkeypatch):
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)
    config = {"model": {"provider": "openai", "name": "m", "fallbacks": ["openai/m"]}}
    assert isinstance(get_model_provider(config=config, api_key="k"), OpenAIProvider)


@pytest.mark.parametrize("provider_name", ["gemini", "openai", "anthropic", "meta"])
def test_default_ollama_address_never_reaches_a_cloud_provider(monkeypatch, provider_name):
    """Found on camera: setup saved Gemini with the default endpoint still in the config."""
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)
    for name in ("GEMINI_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "META_API_ENDPOINT", "META_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    config = {"model": {"provider": provider_name, "name": "m", "endpoint": "http://localhost:11434"}}
    assert "11434" not in get_model_provider(config=config, api_key="k").base_url
