"""
OpenAI-Compatible Custom Model Provider for Buzzard Code.

Supports custom endpoints such as LocalAI, vLLM, LMStudio, Groq, Together, DeepSeek,
or self-hosted OpenAI-compatible inference servers.
"""

import os
from typing import Optional, Dict, Any, List
from model.openai_provider import OpenAIProvider
from core.credentials import get_credential, mask_secret

class OpenAICompatibleProvider(OpenAIProvider):
    """
    Generic OpenAI-compatible provider for custom endpoints.
    """
    DEFAULT_MODEL = "default"
    DEFAULT_BASE_URL = "http://localhost:8000/v1"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
    ):
        resolved_base = base_url or os.environ.get("OPENAI_COMPATIBLE_BASE_URL") or self.DEFAULT_BASE_URL
        resolved_key = (
            api_key or 
            get_credential("openai-compatible") or 
            get_credential("custom") or 
            os.environ.get("OPENAI_COMPATIBLE_API_KEY") or 
            os.environ.get("CUSTOM_API_KEY") or
            "not-required"
        )
        resolved_model = model_name or os.environ.get("OPENAI_COMPATIBLE_MODEL", self.DEFAULT_MODEL)
        
        super().__init__(
            model_name=resolved_model,
            api_key=resolved_key,
            base_url=resolved_base,
            timeout=timeout
        )

    def __repr__(self) -> str:
        return f"<OpenAICompatibleProvider model='{self.model_name}' base_url='{self.base_url}'>"

    def health_check(self) -> Dict[str, Any]:
        info = super().health_check()
        info["provider"] = "openai-compatible"
        return info

    def capabilities(self) -> Dict[str, Any]:
        return {
            "streaming": True,
            "chat": True,
            "tools": True,
            "native_tools": True,
            "local": True,
            "provider": "openai-compatible"
        }
