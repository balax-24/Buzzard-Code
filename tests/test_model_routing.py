"""Tests for model routing of subagents (roadmap F5)."""

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from agent import subagents
from agent.subagents import subagent_model_spec, subagent_provider


@pytest.fixture(autouse=True)
def clear_cache():
    subagents._routed_providers.clear()
    yield
    subagents._routed_providers.clear()


def parent_with(config):
    return SimpleNamespace(provider=SimpleNamespace(model_name="main-model"), config=config)


def test_spec_from_model_section_or_top_level():
    assert subagent_model_spec({}) is None
    assert subagent_model_spec({"model": {"subagent": "gemini/gemini-2.5-flash"}}) == "gemini/gemini-2.5-flash"
    assert subagent_model_spec({"subagent_model": " qwen3:8b "}) == "qwen3:8b"
    assert subagent_model_spec({"model": "plain-string"}) is None


def test_no_setting_uses_the_main_model():
    parent = parent_with({"model": {"provider": "gemini", "name": "gemini-2.5-pro"}})
    assert subagent_provider(parent) is parent.provider


def test_routed_provider_never_inherits_another_providers_endpoint(monkeypatch):
    calls: List[Dict[str, Any]] = []

    def fake_factory(provider_name=None, model_name=None, config=None, **kwargs):
        calls.append({"provider": provider_name, "model": model_name, "model_config": config["model"]})
        return SimpleNamespace(model_name=model_name)

    monkeypatch.setattr("model.factory.get_model_provider", fake_factory)
    main = {"provider": "ollama", "name": "qwen3:32b", "endpoint": "http://localhost:11434"}
    cloud = subagent_provider(parent_with({"model": {**main, "subagent": "gemini/gemini-2.5-flash"}}))
    assert cloud.model_name == "gemini-2.5-flash"
    assert calls[-1]["model_config"] == {"provider": "gemini", "name": "gemini-2.5-flash"}  # no Ollama endpoint
    local = subagent_provider(parent_with({"model": {**main, "subagent": "ollama/qwen3:8b"}}))
    assert local.model_name == "qwen3:8b" and calls[-1]["model_config"]["endpoint"] == "http://localhost:11434"
    again = subagent_provider(parent_with({"model": {**main, "subagent": "ollama/qwen3:8b"}}))
    assert again is local and len(calls) == 2  # cached per spec


def test_a_broken_setting_falls_back_to_the_main_model(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("no API key for that provider")

    monkeypatch.setattr("model.factory.get_model_provider", broken)
    parent = parent_with({"model": {"provider": "gemini", "name": "pro", "subagent": "openai/gpt-x"}})
    assert subagent_provider(parent) is parent.provider


def test_subagent_run_uses_the_routed_model_and_reports_it(monkeypatch):
    used = []

    class Routed:
        model_name = "cheap-model"

        def chat(self, messages, tools=None, options=None):
            used.append("routed")
            return {"message": {"role": "assistant", "content": "Found it.", "tool_calls": []}, "done": True, "metrics": {}}

    child_providers = []

    class FakeLoop:
        def __init__(self, provider, **kwargs):
            child_providers.append(provider)
            self.provider = provider
            self.last_error = None

        def run(self, **kwargs):
            reply = self.provider.chat([])
            return {"status": "completed", "messages": [{"role": "assistant", "content": reply["message"]["content"]}]}

    monkeypatch.setattr("agent.loop.AgentLoop", FakeLoop)
    monkeypatch.setattr(subagents, "subagent_provider", lambda parent: Routed())
    parent = SimpleNamespace(provider=SimpleNamespace(model_name="main"), registry=SimpleNamespace(TOOL_ALIASES={}, definitions={}),
                             storage=None, config={}, approval_callback=None,
                             stop_event=SimpleNamespace(is_set=lambda: False), ui_active=False, embedded_ui=False,
                             run_target="localhost", run_scope=["localhost"])
    subagents.set_parent_loop(parent)
    try:
        report = subagents.delegate_task("explore", "where is price defined")
    finally:
        subagents.set_parent_loop(None)
    assert used == ["routed"] and isinstance(child_providers[0], Routed)
    assert "Model: cheap-model." in report and "Found it." in report
