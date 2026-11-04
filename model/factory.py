"""
Model Provider Factory and Model Specification Resolver for Buzzard Code.

Provides centralized provider instantiation, model resolution, and discovery.
BUZZARD CODE OWNS EXECUTION AND SECURITY. THE MODEL IS REPLACEABLE.
"""

from typing import Dict, Any, List, Optional, Tuple, Type
import logging
import os
from model.provider import ModelProvider
from model.ollama import OllamaProvider
from model.openai_provider import OpenAIProvider
from model.gemini_provider import GeminiProvider
from model.anthropic_provider import AnthropicProvider
from model.openai_compatible import OpenAICompatibleProvider
from model.failover import FailoverProvider
from model.meta_muse import MetaMuseProvider

logger = logging.getLogger(__name__)
from core.config import load_merged_config

SUPPORTED_PROVIDERS = {
    "ollama": {
        "class": OllamaProvider,
        "name": "Ollama",
        "description": "Local models run via Ollama server (default: localhost:11434)",
        "requires_auth": False,
        "is_local": True,
    },
    "openai": {
        "class": OpenAIProvider,
        "name": "OpenAI",
        "description": "Cloud GPT-4o, GPT-4o-mini, o1, o3-mini via OpenAI API",
        "requires_auth": True,
        "is_local": False,
    },
    "gemini": {
        "class": GeminiProvider,
        "name": "Google Gemini",
        "description": "Cloud Gemini 2.0 Flash, Gemini 1.5 Pro via Google AI API",
        "requires_auth": True,
        "is_local": False,
    },
    "anthropic": {
        "class": AnthropicProvider,
        "name": "Anthropic",
        "description": "Cloud Claude 3.5 Sonnet, Claude 3.7 Sonnet via Anthropic API",
        "requires_auth": True,
        "is_local": False,
    },
    "meta": {
        "class": MetaMuseProvider,
        "name": "Meta Muse",
        "description": "Meta Muse frontier coding models via Meta Model API (muse-spark-1.x, muse-wonder-1.0)",
        "requires_auth": True,
        "is_local": False,
    },
    "muse": {
        "class": MetaMuseProvider,
        "name": "Meta Muse",
        "description": "Alias for Meta Muse",
        "requires_auth": True,
        "is_local": False,
    },
    "openai-compatible": {
        "class": OpenAICompatibleProvider,
        "name": "OpenAI-Compatible Custom",
        "description": "Local or custom inference servers (vLLM, LMStudio, Groq, DeepSeek, LocalAI)",
        "requires_auth": False,
        "is_local": True,
    },
}

def resolve_provider_and_model(
    spec: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Resolves provider and model from spec (e.g. 'ollama/qwen3:8b', 'gpt-4o', 'claude-3-5-sonnet')
    or falls back to configuration.
    """
    cfg = config or load_merged_config()
    m_entry = cfg.get("model", {})
    if isinstance(m_entry, str):
        default_provider = "ollama"
        default_model = m_entry
    else:
        default_provider = (m_entry or {}).get("provider", "ollama").lower()
        default_model = (m_entry or {}).get("name", "qwen3:8b")

    if not spec:
        return default_provider, default_model

    spec = spec.strip()
    if "/" in spec:
        provider_part, model_part = spec.split("/", 1)
        provider_clean = provider_part.lower().replace("_", "-")
        if provider_clean in ("custom", "local", "vllm", "compatible"):
            provider_clean = "openai-compatible"
        if provider_clean in ("muse", "meta-muse"):
            provider_clean = "meta"
        return provider_clean, model_part

    # Heuristic resolution for common un-prefixed model names
    spec_lower = spec.lower()
    if spec_lower.startswith(("gpt-", "o1", "o3", "text-davinci")):
        return "openai", spec
    if spec_lower.startswith(("claude-", "anthropic")):
        return "anthropic", spec
    if spec_lower.startswith("gemini-"):
        return "gemini", spec
    if spec_lower.startswith(("muse-", "muse/", "meta-", "meta/")):
        return "meta", spec

    # Default to configured provider with given model name
    return default_provider, spec

def _configured_fallbacks(cfg: Dict[str, Any]) -> List[str]:
    """Fallback model specs from BUZZARD_FALLBACK_MODELS (comma-separated) or model.fallbacks."""
    from_env = os.environ.get("BUZZARD_FALLBACK_MODELS", "")
    if from_env.strip():
        return [spec.strip() for spec in from_env.split(",") if spec.strip()]
    model_cfg = cfg.get("model", {})
    return list(model_cfg.get("fallbacks") or []) if isinstance(model_cfg, dict) else []


def get_model_provider(
    provider_name: Optional[str] = None,
    model_name: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> ModelProvider:
    """
    Returns the configured provider, wrapped for failover when fallbacks are configured.
    Keyword arguments such as api_key apply to the primary only, so a key never reaches another host.
    """
    cfg = config or load_merged_config()
    primary = _build_provider(provider_name, model_name, cfg, **kwargs)
    chain = [primary]
    for spec in _configured_fallbacks(cfg):
        fallback_provider, fallback_model = resolve_provider_and_model(spec, cfg)
        try:
            candidate = _build_provider(fallback_provider, fallback_model, cfg)
        except (ValueError, KeyError, TypeError) as e:
            logger.warning("Skipping fallback model '%s': %s", spec, e)
            continue
        same_as_existing = any(
            type(existing) is type(candidate) and existing.model_name == candidate.model_name
            for existing in chain
        )
        if not same_as_existing:
            chain.append(candidate)
    return FailoverProvider(chain) if len(chain) > 1 else primary


def _build_provider(
    provider_name: Optional[str] = None,
    model_name: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> ModelProvider:
    """
    Instantiates a single ModelProvider.
    """
    cfg = config or load_merged_config()
    model_cfg = cfg.get("model", {})
    if isinstance(model_cfg, str):
        model_cfg = {"name": model_cfg, "provider": "ollama"}

    p_name = provider_name or model_cfg.get("provider", "ollama")
    p_name = p_name.lower().replace("_", "-")
    if p_name in ("custom", "local", "vllm", "compatible"):
        p_name = "openai-compatible"

    m_name = model_name or model_cfg.get("name")

    # An endpoint belongs to its configured provider. Reusing it for another provider
    # would send that provider's API key to the wrong server.
    configured_provider = str(model_cfg.get("provider", "ollama")).lower().replace("_", "-")
    configured_endpoint = model_cfg.get("endpoint") if configured_provider == p_name else None

    if p_name == "ollama":
        host = kwargs.get("host") or configured_endpoint
        return OllamaProvider(host=host, model_name=m_name, **kwargs)
    elif p_name == "openai":
        base_url = kwargs.get("base_url") or configured_endpoint
        return OpenAIProvider(model_name=m_name, base_url=base_url, **kwargs)
    elif p_name == "gemini":
        base_url = kwargs.get("base_url") or configured_endpoint
        return GeminiProvider(model_name=m_name, base_url=base_url, **kwargs)
    elif p_name == "anthropic":
        base_url = kwargs.get("base_url") or configured_endpoint
        return AnthropicProvider(model_name=m_name, base_url=base_url, **kwargs)
    elif p_name in ("meta", "muse"):
        base_url = kwargs.get("base_url") or configured_endpoint
        return MetaMuseProvider(model_name=m_name, base_url=base_url, **kwargs)
    elif p_name in ("openai-compatible", "custom"):
        base_url = kwargs.get("base_url") or configured_endpoint
        return OpenAICompatibleProvider(model_name=m_name, base_url=base_url, **kwargs)
    else:
        # Fallback to Ollama or raise
        return OllamaProvider(model_name=m_name, **kwargs)

def list_supported_providers() -> List[Dict[str, Any]]:
    """Returns metadata for all supported providers."""
    result = []
    for pid, meta in SUPPORTED_PROVIDERS.items():
        result.append({
            "id": pid,
            "name": meta["name"],
            "description": meta["description"],
            "requires_auth": meta["requires_auth"],
            "is_local": meta["is_local"]
        })
    return result
