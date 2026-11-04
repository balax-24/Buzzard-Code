"""
Anthropic Model Provider for Buzzard Code.

Supports Claude 3.5 Sonnet, Claude 3.7 Sonnet, Claude 3 Opus, Claude 3 Haiku via Messages API.
API keys are loaded securely from credentials store or ANTHROPIC_API_KEY.
"""

import os
import json
import httpx
from typing import List, Dict, Any, Generator, Optional, Tuple
from security_agent.model.provider import ModelProvider
from security_agent.model.retry import post_with_retries
from security_agent.model.tool_calls import (
    finish_openai_tool_fragments,
    from_anthropic_blocks,
    merge_openai_tool_fragments,
    to_anthropic_messages,
    to_anthropic_tools,
)
from security_agent.core.credentials import get_credential, mask_secret

class AnthropicProvider(ModelProvider):
    """
    Anthropic Messages API Provider.
    """
    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
    DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
    ):
        self.model_name = model_name or os.environ.get("ANTHROPIC_MODEL", self.DEFAULT_MODEL)
        self.base_url = (base_url or os.environ.get("ANTHROPIC_BASE_URL", self.DEFAULT_BASE_URL)).rstrip("/")
        self.api_key = api_key or get_credential("anthropic") or os.environ.get("ANTHROPIC_API_KEY")
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)

    def __repr__(self) -> str:
        masked_key = mask_secret(self.api_key)
        return f"<AnthropicProvider model='{self.model_name}' api_key='{masked_key}'>"

    def _get_headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise ValueError(
                "Anthropic API key is missing. Set ANTHROPIC_API_KEY environment variable or run 'buzzard /connect anthropic'."
            )
        return {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        # Anthropic has no generic ping endpoint, check via models endpoint or 0-token request
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
        if not self.api_key:
            return ["claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219", "claude-3-5-haiku-20241022"]
        try:
            resp = self.client.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                return sorted([m["id"] for m in data.get("data", [])])
        except Exception:
            pass
        return ["claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219", "claude-3-5-haiku-20241022"]

    def _convert_messages(self, messages: List[Dict[str, Any]]) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        return to_anthropic_messages(messages)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        headers = self._get_headers()
        system_prompt, converted_messages = self._convert_messages(messages)
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": converted_messages,
            "max_tokens": 4096,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = to_anthropic_tools(tools)
        if options:
            payload.update(options)

        try:
            resp = post_with_retries(self.client, f"{self.base_url}/messages", headers, payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Anthropic API error ({resp.status_code}): {resp.text[:300]}")
            data = resp.json()
            text, tool_calls = from_anthropic_blocks(data.get("content", []))
            return {
                "message": {
                    "role": "assistant",
                    "content": text,
                    "tool_calls": tool_calls,
                },
                "raw": data
            }
        except Exception as e:
            raise RuntimeError(f"Anthropic chat request failed: {e}")

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        headers = self._get_headers()
        system_prompt, converted_messages = self._convert_messages(messages)
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": converted_messages,
            "max_tokens": 4096,
            "stream": True,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = to_anthropic_tools(tools)
        if options:
            payload.update(options)

        try:
            with self.client.stream(
                "POST",
                f"{self.base_url}/messages",
                headers=headers,
                json=payload
            ) as response:
                if response.status_code != 200:
                    body = response.read().decode("utf-8", errors="replace")[:300]
                    raise RuntimeError(f"Anthropic stream error ({response.status_code}): {body}")

                # tool_use blocks stream their input as JSON fragments, keyed by block index
                pending_tool_calls: Dict[int, Dict[str, Any]] = {}
                for line in response.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        raw_data = line[6:].strip()
                        try:
                            event = json.loads(raw_data)
                            event_type = event.get("type")
                            if event_type == "content_block_start":
                                block = event.get("content_block", {})
                                if block.get("type") == "tool_use":
                                    merge_openai_tool_fragments(pending_tool_calls, [{
                                        "index": event.get("index", 0),
                                        "id": block.get("id"),
                                        "function": {"name": block.get("name")},
                                    }])
                            elif event_type == "content_block_delta":
                                delta = event.get("delta", {})
                                if delta.get("type") == "input_json_delta":
                                    merge_openai_tool_fragments(pending_tool_calls, [{
                                        "index": event.get("index", 0),
                                        "function": {"arguments": delta.get("partial_json", "")},
                                    }])
                                delta_text = delta.get("text", "")
                                if delta_text:
                                    yield {"message": {"content": delta_text}, "done": False}
                            elif event_type == "message_stop":
                                final_message: Dict[str, Any] = {"content": ""}
                                if pending_tool_calls:
                                    final_message["tool_calls"] = finish_openai_tool_fragments(pending_tool_calls)
                                yield {"message": final_message, "done": True}
                                break
                        except Exception:
                            continue
        except Exception as e:
            raise RuntimeError(f"Anthropic stream failed: {e}")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
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
            "provider": "anthropic",
            "model": self.model_name,
            "has_credentials": has_key,
            "available": available,
        }

    def capabilities(self) -> Dict[str, Any]:
        return {
            "streaming": True,
            "chat": True,
            "tools": True,
            "native_tools": True,
            "local": False,
            "provider": "anthropic"
        }
