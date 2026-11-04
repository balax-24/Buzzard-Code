import os
import json
import pytest
import httpx
from unittest.mock import MagicMock, patch

from model.meta_muse import MetaMuseProvider
from model.factory import (
    resolve_provider_and_model,
    get_model_provider,
    list_supported_providers,
)


def test_meta_muse_initialization():
    provider = MetaMuseProvider(
        model_name="muse-spark",
        api_key="meta_test_secret_key_12345",
        base_url="https://api.meta.ai/v1"
    )
    assert provider.model_name == "muse-spark"
    assert provider.base_url == "https://api.meta.ai/v1"
    assert "meta_test_secret_key_12345" not in repr(provider)
    assert "meta...2345" in repr(provider)


def test_meta_muse_missing_api_key_raises():
    provider = MetaMuseProvider(api_key=None)
    # Ensure env var is cleared for this test
    with patch.dict(os.environ, {}, clear=True):
        provider.api_key = None
        with pytest.raises(ValueError) as exc:
            provider._get_headers()
        assert "META_API_KEY" in str(exc.value)


def test_meta_muse_chat_completion():
    provider = MetaMuseProvider(
        model_name="muse-spark",
        api_key="meta_test_secret_key"
    )

    mock_resp_data = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "def add(a, b):\n    return a + b\n"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 10,
            "total_tokens": 22
        }
    }

    mock_resp = httpx.Response(
        status_code=200,
        json=mock_resp_data,
        request=httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    )

    with patch.object(provider.client, "post", return_value=mock_resp) as mock_post:
        res = provider.chat([{"role": "user", "content": "Write add function"}])

        assert res["message"]["content"] == "def add(a, b):\n    return a + b\n"
        assert res["usage"]["total_tokens"] == 22
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer meta_test_secret_key"
        assert kwargs["json"]["model"] == "muse-spark"


def test_meta_muse_http_error_redaction():
    provider = MetaMuseProvider(
        model_name="muse-spark",
        api_key="secret_token_to_redact"
    )

    mock_resp = httpx.Response(
        status_code=401,
        text="Unauthorized request for secret_token_to_redact",
        request=httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    )

    with patch.object(provider.client, "post", return_value=mock_resp):
        with pytest.raises(RuntimeError) as exc:
            provider.chat([{"role": "user", "content": "hi"}])
        err_msg = str(exc.value)
        assert "401" in err_msg
        assert "secret_token_to_redact" not in err_msg


def test_meta_muse_retry_on_429():
    provider = MetaMuseProvider(
        model_name="muse-spark",
        api_key="meta_key",
        max_retries=2
    )

    resp_429 = httpx.Response(
        status_code=429,
        text="Rate limited",
        request=httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    )

    resp_200 = httpx.Response(
        status_code=200,
        json={
            "choices": [{"message": {"role": "assistant", "content": "Success after retry"}}],
            "usage": {"total_tokens": 5}
        },
        request=httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    )

    with patch.object(provider.client, "post", side_effect=[resp_429, resp_200]):
        with patch("time.sleep", return_value=None):
            res = provider.chat([{"role": "user", "content": "test"}])
            assert res["message"]["content"] == "Success after retry"


def test_meta_muse_factory_resolution():
    p, m = resolve_provider_and_model("muse-spark")
    assert p == "meta"
    assert m == "muse-spark"

    p2, m2 = resolve_provider_and_model("meta/muse-wonder")
    assert p2 == "meta"
    assert m2 == "muse-wonder"

    p3, m3 = resolve_provider_and_model("muse/muse-spark-1.3")
    assert p3 == "meta"
    assert m3 == "muse-spark-1.3"

    prov = get_model_provider(provider_name="meta", model_name="muse-spark", api_key="test_key")
    assert isinstance(prov, MetaMuseProvider)
    assert prov.model_name == "muse-spark"

    providers = list_supported_providers()
    meta_entry = next((p for p in providers if p["id"] == "meta"), None)
    assert meta_entry is not None
    assert "Meta Muse" in meta_entry["name"]
