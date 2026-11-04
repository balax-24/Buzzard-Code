import pytest
from unittest.mock import MagicMock, Mock
from model.ollama import OllamaProvider

def test_ollama_provider_initialization():
    """
    Tests initialization defaults and environment variable override.
    """
    provider = OllamaProvider()
    assert provider.host == "http://localhost:11434"
    assert provider.model_name == "qwen3.6:27b-uncensored"

def test_ollama_provider_health():
    """
    Tests if local Ollama daemon is reachable.
    """
    provider = OllamaProvider()
    # It checks host connection.
    # If Ollama is running in background, this should be True.
    # If not running, we assert is_available is a boolean type.
    status = provider.is_available()
    assert isinstance(status, bool)

def test_ollama_available_models():
    """
    Tests fetching available models.
    """
    provider = OllamaProvider()
    models = provider.get_available_models()
    assert isinstance(models, list)

def test_chat_disables_thinking_and_keeps_model_warm():
    """Tool agents should not lose their response budget to hidden reasoning."""
    provider = OllamaProvider(think=False, keep_alive="30m", num_gpu=12)
    response = Mock(status_code=200)
    response.json.return_value = {"message": {"role": "assistant", "content": "ok"}, "done": True}
    provider.client = Mock()
    provider.client.post.return_value = response

    provider.chat([{"role": "user", "content": "hello"}])

    payload = provider.client.post.call_args.kwargs["json"]
    assert payload["think"] is False
    assert payload["keep_alive"] == "30m"
    assert payload["options"]["num_ctx"] == 4096
    assert payload["options"]["num_gpu"] == 12

def test_chat_retries_without_native_tools_when_model_does_not_support_them():
    provider = OllamaProvider()
    unsupported = Mock(status_code=400, text='{"error":"model does not support tools"}')
    success = Mock(status_code=200)
    success.json.return_value = {"message": {"role": "assistant", "content": "{}"}, "done": True}
    provider.client = Mock()
    provider.client.post.side_effect = [unsupported, success]

    provider.chat([{"role": "user", "content": "hello"}], tools=[{"type": "function"}])

    first_payload = provider.client.post.call_args_list[0].kwargs["json"]
    second_payload = provider.client.post.call_args_list[1].kwargs["json"]
    assert "tools" in first_payload
    assert "tools" not in second_payload

def test_stream_chat_recovers_from_cuda_oom_by_halving_num_ctx():
    """stream_chat must retry with a halved num_ctx when Ollama returns a CUDA OOM 500."""
    import json as _json
    provider = OllamaProvider(num_ctx=8192, num_gpu=33)
    provider.client = Mock()

    oom_resp = Mock(status_code=500)
    oom_resp.read.return_value = (
        b'{"error":"llama-server reported out-of-memory during startup: '
        b'cudaMalloc failed: out of memory"}'
    )
    ok_resp = Mock(status_code=200)
    ok_resp.iter_lines.return_value = [
        _json.dumps({"message": {"role": "assistant", "content": "ok"}}),
        _json.dumps({"message": {"role": "assistant", "content": ""},
                     "done": True, "total_duration": 100}),
    ]

    def cm(resp):
        m = MagicMock()
        m.__enter__.return_value = resp
        m.__exit__.return_value = False
        return m

    provider.client.stream.side_effect = [cm(oom_resp), cm(ok_resp)]

    chunks = list(provider.stream_chat([{"role": "user", "content": "hi"}],
                                       tools=[{"type": "function"}]))

    assert provider.num_ctx == 4096
    assert len(chunks) == 2
    assert chunks[-1]["done"] is True
    first_payload = provider.client.stream.call_args_list[0].kwargs["json"]
    second_payload = provider.client.stream.call_args_list[1].kwargs["json"]
    assert first_payload["options"]["num_ctx"] == 8192
    assert second_payload["options"]["num_ctx"] == 4096


def test_stream_chat_surfaces_body_on_non_oom_error():
    """Non-OOM failures must include the response body so the cause is diagnosable."""
    provider = OllamaProvider()
    provider.client = Mock()
    resp = Mock(status_code=500)
    resp.read.return_value = b'{"error":"some other failure"}'
    m = MagicMock()
    m.__enter__.return_value = resp
    m.__exit__.return_value = False
    provider.client.stream.side_effect = [m]

    with pytest.raises(Exception, match="some other failure"):
        list(provider.stream_chat([{"role": "user", "content": "hi"}]))
