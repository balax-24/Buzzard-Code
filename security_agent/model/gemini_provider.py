"""
Google Gemini Model Provider for Buzzard Code.

Supports Gemini 2.0 Flash, Gemini 1.5 Pro/Flash, and other Gemini models via REST API.
API keys are loaded securely from credentials store or GEMINI_API_KEY / GOOGLE_API_KEY.
"""

import os
import json
import httpx
from typing import List, Dict, Any, Generator, Optional, Tuple
from security_agent.model.provider import ModelProvider
from security_agent.core.credentials import get_credential, mask_secret
from security_agent.model.retry import post_with_retries
from security_agent.model.tool_calls import from_gemini_parts, to_gemini_contents, to_gemini_tools

class GeminiProvider(ModelProvider):
    """
    Google Gemini REST API Provider.
    """
    DEFAULT_MODEL = "gemini-2.0-flash"
    DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
    ):
        self.model_name = model_name or os.environ.get("GEMINI_MODEL", self.DEFAULT_MODEL)
        self.base_url = (base_url or os.environ.get("GEMINI_BASE_URL", self.DEFAULT_BASE_URL)).rstrip("/")
        self.api_key = api_key or get_credential("gemini") or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)

    def __repr__(self) -> str:
        masked_key = mask_secret(self.api_key)
        return f"<GeminiProvider model='{self.model_name}' api_key='{masked_key}'>"

    def _get_headers(self) -> Dict[str, str]:
        """The key travels in a header so it cannot leak through URLs in errors or logs."""
        if not self.api_key:
            raise ValueError(
                "Gemini API key is missing. Set GEMINI_API_KEY environment variable or run 'buzzard /connect gemini'."
            )
        return {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

    def _sanitize(self, text: str) -> str:
        return text.replace(self.api_key, "[REDACTED_API_KEY]") if self.api_key else text

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            resp = self.client.get(f"{self.base_url}/models", headers=self._get_headers(), timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    def get_available_models(self) -> List[str]:
        if not self.api_key:
            return ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]
        try:
            resp = self.client.get(f"{self.base_url}/models", headers=self._get_headers(), timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                models = [
                    m["name"].split("/")[-1]
                    for m in data.get("models", [])
                    if "generateContent" in m.get("supportedGenerationMethods", [])
                ]
                return sorted(models) or ["gemini-2.0-flash", "gemini-1.5-pro"]
        except Exception:
            pass
        return ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]

    def _convert_messages(self, messages: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """Converts agent-loop messages to Gemini format."""
        return to_gemini_contents(messages)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        headers = self._get_headers()
        system_inst, contents = self._convert_messages(messages)
        payload: Dict[str, Any] = {"contents": contents}
        if system_inst:
            payload["systemInstruction"] = system_inst
        if tools:
            payload["tools"] = to_gemini_tools(tools)
        if options:
            payload.update(options)

        url = f"{self.base_url}/models/{self.model_name}:generateContent"
        try:
            resp = post_with_retries(self.client, url, headers, payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API error ({resp.status_code}): {self._sanitize(resp.text[:300])}")
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return {"message": {"role": "assistant", "content": "", "tool_calls": []}, "raw": data}
            text, tool_calls = from_gemini_parts(candidates[0].get("content", {}).get("parts", []))
            usage = data.get("usageMetadata", {})
            return {
                "message": {
                    "role": "assistant",
                    "content": text,
                    "tool_calls": tool_calls,
                },
                "raw": data,
                "metrics": {
                    "prompt_eval_count": usage.get("promptTokenCount", 0),
                    "eval_count": usage.get("candidatesTokenCount", 0),
                },
            }
        except Exception as e:
            raise RuntimeError(f"Gemini chat request failed: {self._sanitize(str(e))}")

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        headers = self._get_headers()
        system_inst, contents = self._convert_messages(messages)
        payload: Dict[str, Any] = {"contents": contents}
        if system_inst:
            payload["systemInstruction"] = system_inst
        if tools:
            payload["tools"] = to_gemini_tools(tools)

        url = f"{self.base_url}/models/{self.model_name}:streamGenerateContent?alt=sse"
        stream_tool_calls: List[Dict[str, Any]] = []
        try:
            with self.client.stream("POST", url, headers=headers, json=payload) as response:
                if response.status_code != 200:
                    body = response.read().decode("utf-8", errors="replace")[:300]
                    raise RuntimeError(f"Gemini stream error ({response.status_code}): {body}")

                for line in response.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        raw_data = line[6:].strip()
                        try:
                            chunk = json.loads(raw_data)
                            candidates = chunk.get("candidates", [])
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                text_chunk, chunk_calls = from_gemini_parts(parts)
                                stream_tool_calls.extend(chunk_calls)
                                if text_chunk:
                                    yield {"message": {"content": text_chunk}, "done": False}
                        except Exception:
                            continue
            final_message: Dict[str, Any] = {"content": ""}
            if stream_tool_calls:
                final_message["tool_calls"] = stream_tool_calls
            yield {"message": final_message, "done": True}
        except Exception as e:
            raise RuntimeError(f"Gemini stream failed: {self._sanitize(str(e))}")

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
            "provider": "gemini",
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
            "provider": "gemini"
        }
