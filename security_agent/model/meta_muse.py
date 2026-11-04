"""
Meta Muse Model Provider for Buzzard Code.

Supports Meta Muse models (muse-spark, muse-spark-1.3, muse-wonder) and Meta Llama
via the Meta Model API.
API keys are loaded securely from credentials store or META_API_KEY environment variable.
"""

from __future__ import annotations

import os
import json
import time
import httpx
from typing import List, Dict, Any, Generator, Optional
from security_agent.model.provider import ModelProvider
from security_agent.model.tool_calls import (
    finish_openai_tool_fragments,
    merge_openai_tool_fragments,
    normalize_openai_tool_calls,
    serialize_openai_messages,
    to_openai_tools,
)
from security_agent.core.credentials import get_credential, mask_secret


class MetaMuseProvider(ModelProvider):
    """
    Meta Muse Model API Provider for Buzzard Code.
    Integrates with Meta's developer API for frontier coding intelligence.
    """
    DEFAULT_MODEL = "muse-spark-1.1"
    DEFAULT_BASE_URL = "https://api.meta.ai/v1"
    # "-contributor" IDs are deliberately excluded: they permit Meta to train on prompts.
    KNOWN_MODELS = ["muse-spark-1.1", "muse-spark-1.2", "muse-spark-1.3", "muse-wonder-1.0"]

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
        max_retries: int = 3,
    ):
        self.model_name = (
            model_name or
            os.environ.get("META_MODEL") or
            os.environ.get("MUSE_MODEL") or
            self.DEFAULT_MODEL
        )
        self.base_url = (
            base_url or
            os.environ.get("META_API_ENDPOINT") or
            os.environ.get("META_BASE_URL") or
            self.DEFAULT_BASE_URL
        ).rstrip("/")
        
        # Resolve API key securely (never logged)
        self.api_key = (
            api_key or
            get_credential("meta") or
            get_credential("muse") or
            os.environ.get("META_API_KEY") or
            os.environ.get("MODEL_API_KEY")
        )
        self.timeout = timeout
        self.max_retries = max(0, min(10, max_retries))
        self.client = httpx.Client(timeout=timeout)

    def __repr__(self) -> str:
        masked_key = mask_secret(self.api_key)
        return f"<MetaMuseProvider model='{self.model_name}' base_url='{self.base_url}' api_key='{masked_key}'>"

    def _get_headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise ValueError(
                "Meta API key is missing. Set META_API_KEY environment variable or run 'buzzard /connect meta'."
            )
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Buzzard-Code-Agent/1.0",
        }

    def _sanitize_error_text(self, text: str) -> str:
        """Removes any sensitive tokens or internal URLs from error text."""
        if not text:
            return ""
        if self.api_key and self.api_key in text:
            text = text.replace(self.api_key, "[REDACTED_API_KEY]")
        return text.strip()[:300]

    def _format_http_error(self, status_code: int, raw_text: str) -> str:
        sanitized = self._sanitize_error_text(raw_text)
        if status_code == 401:
            return "Meta API authentication failed (401): Invalid or expired META_API_KEY."
        elif status_code == 403:
            return "Meta API permission denied (403): Unauthorized access to requested Meta model."
        elif status_code == 404:
            return f"Meta API endpoint not found (404): Check model '{self.model_name}' or endpoint URL."
        elif status_code == 429:
            return "Meta API rate limit exceeded (429): Request throttled. Please retry shortly."
        elif status_code in (500, 502, 503, 504):
            return f"Meta API upstream service error ({status_code}): Service temporarily unavailable."
        return f"Meta API error ({status_code}): {sanitized}"

    def is_available(self) -> bool:
        """Checks if Meta API is reachable and credentials are valid."""
        if not self.api_key:
            return False
        try:
            resp = self.client.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
                timeout=5.0
            )
            return resp.status_code == 200
        except Exception:
            return False

    def get_available_models(self) -> List[str]:
        """Queries Meta API for available models or returns known Meta models."""
        if not self.api_key:
            return list(self.KNOWN_MODELS)
        try:
            resp = self.client.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [
                    m["id"] for m in data.get("data", [])
                    if any(prefix in m.get("id", "").lower() for prefix in ("muse", "meta", "llama"))
                ]
                if models:
                    return sorted(models)
        except Exception:
            pass
        return list(self.KNOWN_MODELS)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sends a full message history to Meta Muse API with retry controls.
        Returns response dictionary with content and token usage reporting.
        """
        headers = self._get_headers()
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": serialize_openai_messages(messages),
            "stream": False,
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        if options:
            payload.update(options)

        attempts = 0
        backoff = 1.0

        while attempts <= self.max_retries:
            try:
                resp = self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )

                if resp.status_code == 200:
                    data = resp.json()
                    choice = data.get("choices", [{}])[0]
                    response_message = choice.get("message", {})
                    # Tool-call responses carry "content": null
                    content = response_message.get("content") or ""

                    # Capture token usage statistics when reported
                    usage = data.get("usage", {})
                    result: Dict[str, Any] = {
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "tool_calls": normalize_openai_tool_calls(response_message.get("tool_calls")),
                        },
                        "raw": data,
                        "usage": usage,
                    }
                    if "finish_reason" in choice:
                        result["finish_reason"] = choice["finish_reason"]
                    return result

                # Check if retryable (429 rate limit or 5xx server error)
                if resp.status_code in (429, 500, 502, 503, 504) and attempts < self.max_retries:
                    attempts += 1
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue

                error_msg = self._format_http_error(resp.status_code, resp.text)
                raise RuntimeError(error_msg)

            except httpx.RequestError as e:
                if attempts < self.max_retries:
                    attempts += 1
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                raise RuntimeError(f"Meta Muse API network error: {self._sanitize_error_text(str(e))}")

        raise RuntimeError("Meta Muse API request exceeded maximum retry attempts.")

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams chat completion tokens from Meta Muse API.
        """
        headers = self._get_headers()
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": serialize_openai_messages(messages),
            "stream": True,
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        if options:
            payload.update(options)

        try:
            with self.client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            ) as response:
                if response.status_code != 200:
                    body = response.read().decode("utf-8", errors="replace")
                    error_msg = self._format_http_error(response.status_code, body)
                    raise RuntimeError(error_msg)

                # Tool-call fragments arrive across chunks, keyed by index
                pending_tool_calls: Dict[int, Dict[str, Any]] = {}
                for line in response.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        raw_data = line[6:].strip()
                        if raw_data == "[DONE]":
                            final_message: Dict[str, Any] = {"content": ""}
                            if pending_tool_calls:
                                final_message["tool_calls"] = finish_openai_tool_fragments(pending_tool_calls)
                            yield {"message": final_message, "done": True}
                            break
                        try:
                            chunk = json.loads(raw_data)
                            choices = chunk.get("choices") or [{}]
                            delta = choices[0].get("delta", {})
                            merge_openai_tool_fragments(pending_tool_calls, delta.get("tool_calls"))
                            content_delta = delta.get("content") or ""
                            usage = chunk.get("usage")
                            if content_delta or usage:
                                out = {"message": {"content": content_delta or ""}, "done": False}
                                if usage:
                                    out["usage"] = usage
                                yield out
                        except Exception:
                            continue
        except Exception as e:
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(f"Meta Muse streaming failed: {self._sanitize_error_text(str(e))}")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generates single completion adapting to chat format."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        resp = self.chat(messages, options=options)
        return resp.get("message", {}).get("content", "")

    def health_check(self) -> Dict[str, Any]:
        has_key = bool(self.api_key)
        available = self.is_available() if has_key else False
        return {
            "status": "ok" if available else "error",
            "provider": "meta",
            "model": self.model_name,
            "has_credentials": has_key,
            "available": available,
            "endpoint": self.base_url,
        }

    def capabilities(self) -> Dict[str, Any]:
        return {
            "streaming": True,
            "chat": True,
            "tools": True,
            "native_tools": True,
            "local": False,
            "provider": "meta",
            "token_usage_reporting": True,
            "retry_control": True,
        }

