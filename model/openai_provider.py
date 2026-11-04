"""
OpenAI Model Provider for Buzzard Code.

Supports GPT-4o, GPT-4o-mini, o1, o3-mini and other OpenAI chat completion models.
API keys are loaded securely from credentials store or environment variables.
"""

import os
import json
import time
import httpx
from typing import List, Dict, Any, Generator, Optional
from model.provider import ModelProvider
from model.retry import MAX_RETRIES, RETRYABLE_STATUS, post_with_retries, retry_delay
from model.tool_calls import (
    finish_openai_tool_fragments,
    merge_openai_tool_fragments,
    normalize_openai_tool_calls,
    serialize_openai_messages,
    to_openai_tools,
)
from core.credentials import get_credential, mask_secret

class _RetryableStreamError(Exception):
    """A stream was refused before any output, so it is safe to try again."""

    def __init__(self, message: str, delay: float):
        super().__init__(message)
        self.delay = delay


class OpenAIProvider(ModelProvider):
    """
    OpenAI Chat Completions API Provider.
    """
    DEFAULT_MODEL = "gpt-4o"
    DEFAULT_BASE_URL = "https://api.openai.com/v1"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
    ):
        self.model_name = model_name or os.environ.get("OPENAI_MODEL", self.DEFAULT_MODEL)
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", self.DEFAULT_BASE_URL)).rstrip("/")
        self.api_key = api_key or get_credential("openai") or os.environ.get("OPENAI_API_KEY")
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)

    def __repr__(self) -> str:
        masked_key = mask_secret(self.api_key)
        return f"<OpenAIProvider model='{self.model_name}' base_url='{self.base_url}' api_key='{masked_key}'>"

    def _get_headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise ValueError(
                "OpenAI API key is missing. Set OPENAI_API_KEY environment variable or run 'buzzard /connect openai'."
            )
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def is_available(self) -> bool:
        """Checks if OpenAI API is reachable and API key is valid."""
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
        """Queries OpenAI API for available models or returns curated defaults."""
        if not self.api_key:
            return ["gpt-4o", "gpt-4o-mini", "o1", "o3-mini"]
        try:
            resp = self.client.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [m["id"] for m in data.get("data", []) if "gpt" in m["id"] or "o1" in m["id"] or "o3" in m["id"]]
                return sorted(models) or ["gpt-4o", "gpt-4o-mini"]
        except Exception:
            pass
        return ["gpt-4o", "gpt-4o-mini", "o1", "o3-mini"]

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sends chat completion request to OpenAI API.
        """
        headers = self._get_headers()
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": serialize_openai_messages(messages),
            "stream": False,
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        max_output_tokens = os.environ.get("BUZZARD_MAX_OUTPUT_TOKENS")
        if max_output_tokens:
            payload["max_tokens"] = int(max_output_tokens)
        if options:
            payload.update(options)

        try:
            resp = post_with_retries(self.client, f"{self.base_url}/chat/completions", headers, payload)
            if resp.status_code != 200:
                err_text = resp.text[:300]
                raise RuntimeError(f"OpenAI API error ({resp.status_code}): {err_text}")
            
            data = resp.json()
            choice = data["choices"][0]
            response_message = choice.get("message", {})
            return {
                "message": {
                    "role": "assistant",
                    # Tool-call responses carry "content": null
                    "content": response_message.get("content") or "",
                    "tool_calls": normalize_openai_tool_calls(response_message.get("tool_calls")),
                },
                "raw": data
            }
        except Exception as e:
            raise RuntimeError(f"OpenAI chat request failed: {e}")

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams chat completion tokens, retrying rate limits and server errors.
        Retries happen only before any output, so nothing is ever duplicated.
        """
        for attempt in range(MAX_RETRIES + 1):
            try:
                self._stream_attempt_count = attempt - 1
                yield from self._stream_once(messages, tools, options)
                return
            except _RetryableStreamError as e:
                if attempt == MAX_RETRIES:
                    raise RuntimeError(f"OpenAI stream failed: {e}") from e
                time.sleep(e.delay)

    def _stream_attempts(self) -> int:
        self._stream_attempt_count = getattr(self, "_stream_attempt_count", -1) + 1
        return min(self._stream_attempt_count, 4)

    def _stream_once(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        headers = self._get_headers()
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": serialize_openai_messages(messages),
            "stream": True,
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        max_output_tokens = os.environ.get("BUZZARD_MAX_OUTPUT_TOKENS")
        if max_output_tokens:
            payload["max_tokens"] = int(max_output_tokens)
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
                    full_body = response.read().decode("utf-8", errors="replace")
                    body = full_body[:300]
                    if response.status_code in RETRYABLE_STATUS:
                        raise _RetryableStreamError(
                            f"OpenAI stream error ({response.status_code}): {body}",
                            retry_delay(response, self._stream_attempts()),
                        )
                    raise RuntimeError(f"OpenAI stream error ({response.status_code}): {body}")

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
                            if content_delta:
                                yield {"message": {"content": content_delta}, "done": False}
                        except Exception:
                            continue
        except _RetryableStreamError:
            raise
        except Exception as e:
            raise RuntimeError(f"OpenAI stream failed: {e}")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generates single completion by adapting to chat format."""
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
            "provider": "openai",
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
            "provider": "openai"
        }
