"""
Automatic model failover.

Wraps an ordered list of providers behind the normal provider interface. When one fails,
the request moves to the next, and the failed provider is skipped for a cooldown period.
Fallbacks are only ever those the user configured, because a fallback may send project
content to a different host.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Generator, List, Optional

from model.provider import ModelProvider

logger = logging.getLogger(__name__)

COOLDOWN_SECONDS = 60.0


class AllProvidersFailedError(RuntimeError):
    """Every configured provider failed for one request."""


class FailoverProvider(ModelProvider):
    def __init__(self, providers: List[ModelProvider], cooldown_seconds: float = COOLDOWN_SECONDS):
        if not providers:
            raise ValueError("FailoverProvider needs at least one provider.")
        self.providers = providers
        self.cooldown_seconds = cooldown_seconds
        self._active = providers[0]
        self._failed_at: Dict[int, float] = {}
        self._simulated_outage: Optional[ModelProvider] = None

    def simulate_outage(self) -> str:
        """Makes the active model fail its next request, to rehearse failover safely."""
        self._simulated_outage = self._active
        return getattr(self._active, "model_name", "model")

    def _check_simulated_outage(self, provider: ModelProvider) -> None:
        if provider is self._simulated_outage:
            self._simulated_outage = None
            raise RuntimeError("simulated outage from /failover test")

    @property
    def active(self) -> ModelProvider:
        return self._active

    @property
    def model_name(self) -> str:
        return getattr(self._active, "model_name", "model")

    @property
    def num_ctx(self) -> Optional[int]:
        return getattr(self._active, "num_ctx", None)

    def _candidates(self) -> List[ModelProvider]:
        """Healthy providers in configured order; cooling ones remain as a last resort."""
        now = time.monotonic()
        cooling = [
            provider for index, provider in enumerate(self.providers)
            if now - self._failed_at.get(index, -self.cooldown_seconds) < self.cooldown_seconds
        ]
        return [provider for provider in self.providers if provider not in cooling] + cooling

    def _mark_failed(self, provider: ModelProvider, error: Exception) -> None:
        self._failed_at[self.providers.index(provider)] = time.monotonic()
        logger.warning("Model '%s' failed, trying the next one: %s", getattr(provider, "model_name", "?"), error)

    def _mark_used(self, provider: ModelProvider) -> None:
        self._active = provider
        self._failed_at.pop(self.providers.index(provider), None)

    def _all_failed(self, errors: List[str]) -> AllProvidersFailedError:
        return AllProvidersFailedError("All configured models failed. " + " | ".join(errors))

    def chat(self, messages, tools=None, options=None) -> Dict[str, Any]:
        errors: List[str] = []
        for provider in self._candidates():
            try:
                self._check_simulated_outage(provider)
                response = provider.chat(messages, tools=tools, options=options)
            except Exception as e:  # Any failure, including a missing key, moves to the next model
                self._mark_failed(provider, e)
                errors.append(f"{getattr(provider, 'model_name', '?')}: {e}")
                continue
            self._mark_used(provider)
            return response
        raise self._all_failed(errors)

    def stream_chat(self, messages, tools=None, options=None) -> Generator[Dict[str, Any], None, None]:
        errors: List[str] = []
        for provider in self._candidates():
            started = False
            try:
                self._check_simulated_outage(provider)
                for chunk in provider.stream_chat(messages, tools=tools, options=options):
                    started = True
                    self._mark_used(provider)
                    yield chunk
                if started:
                    return
                raise RuntimeError("the stream ended without a response")
            except GeneratorExit:
                raise
            except Exception as e:
                # After output has reached the caller, retrying elsewhere would duplicate it
                if started:
                    raise
                self._mark_failed(provider, e)
                errors.append(f"{getattr(provider, 'model_name', '?')}: {e}")
        raise self._all_failed(errors)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> str:
        messages = [{"role": "system", "content": system_prompt}] if system_prompt else []
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, options=options).get("message", {}).get("content", "")

    def is_available(self) -> bool:
        return any(provider.is_available() for provider in self.providers)

    def get_available_models(self) -> List[str]:
        return list(self._active.get_available_models())

    def capabilities(self) -> Dict[str, Any]:
        """Native tools are claimed only if every model in the chain supports them."""
        declared = dict(self._active.capabilities())
        declared["native_tools"] = all(
            provider.capabilities().get("native_tools") is True for provider in self.providers
        )
        declared["failover"] = [getattr(provider, "model_name", "?") for provider in self.providers]
        return declared
