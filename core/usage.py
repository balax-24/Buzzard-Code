"""Session token accounting and context window lookup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Only sizes confirmed from published documentation. Unknown models report no percentage
# rather than a guessed one.
KNOWN_CONTEXT_WINDOWS: Dict[str, int] = {
    "muse-spark-1.3": 1_048_576,
}
CHARS_PER_TOKEN_ESTIMATE = 4
# USD per million input and output tokens, as listed by OpenRouter on 2026-11-04. Prices change,
# so costs are always shown as estimates, and models without a known price show none.
KNOWN_PRICES_PER_MILLION: Dict[str, tuple] = {
    "muse-glimmer-30b": (0.30, 1.20),
    "muse-spark-1.1": (1.25, 4.25),
    "muse-spark-1.2": (1.25, 4.25),
    "muse-spark-1.3": (1.25, 4.25),
    "muse-spark-open": (1.25, 4.25),
    "muse-wonder": (4.00, 20.00),
}


def usage_to_metrics(usage: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """
    Converts OpenAI-format or Anthropic-format usage to the loop's metric names.

    `prompt_eval_count` is always the whole prompt. Anthropic reports cache reads and writes
    separately from `input_tokens`, so they are added back; OpenAI includes cached tokens in
    `prompt_tokens` and lists them under `prompt_tokens_details.cached_tokens`.
    """
    if not usage:
        return {}
    cache_read = int(usage.get("cache_read_input_tokens") or 0)
    cache_write = int(usage.get("cache_creation_input_tokens") or 0)
    if "prompt_tokens" in usage:
        prompt = int(usage.get("prompt_tokens") or 0)
        details = usage.get("prompt_tokens_details") or {}
        cache_read = int(details.get("cached_tokens") or 0) if isinstance(details, dict) else 0
    else:
        prompt = int(usage.get("input_tokens") or 0) + cache_read + cache_write
    metrics = {
        "prompt_eval_count": prompt,
        "eval_count": int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
    }
    if cache_read:
        metrics["cached_prompt_tokens"] = cache_read
    if cache_write:
        metrics["cache_write_tokens"] = cache_write
    return metrics


def estimate_tokens(messages: List[Dict[str, Any]]) -> int:
    """Rough size of a message list, for providers that report no usage."""
    return sum(
        len(str(message.get("content") or "")) + len(str(message.get("tool_calls") or ""))
        for message in messages
    ) // CHARS_PER_TOKEN_ESTIMATE


def budget_limit_usd() -> Optional[float]:
    """Reads BUZZARD_BUDGET_USD. Invalid or non-positive values mean no limit."""
    try:
        limit = float(os.environ.get("BUZZARD_BUDGET_USD", ""))
    except ValueError:
        return None
    return limit if limit > 0 else None


def format_tokens(count: int) -> str:
    return f"{count / 1000:.1f}k" if count >= 1000 else str(count)


def context_window_for(model_name: str, provider: Any = None) -> Optional[int]:
    """Returns the model's context size when known. Ollama reports its configured num_ctx."""
    configured = getattr(provider, "num_ctx", None)
    if isinstance(configured, int) and configured > 0:
        return configured
    return KNOWN_CONTEXT_WINDOWS.get(model_name.split("/")[-1])


@dataclass
class SessionUsage:
    """Tokens used this session. `estimated` is set once any figure was approximated."""

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    last_prompt_tokens: int = 0
    requests: int = 0
    estimated: bool = False
    cost_usd: float = 0.0
    cost_known: bool = False

    def record(
        self, prompt_tokens: int, output_tokens: int, estimated: bool = False, model_name: str = "",
        cached_tokens: int = 0,
    ) -> None:
        price = KNOWN_PRICES_PER_MILLION.get(model_name.split("/")[-1])
        if price:
            self.cost_usd += (prompt_tokens * price[0] + output_tokens * price[1]) / 1_000_000
            self.cost_known = True
        self.input_tokens += prompt_tokens
        self.output_tokens += output_tokens
        self.cached_input_tokens += max(0, min(cached_tokens, prompt_tokens))
        self.last_prompt_tokens = prompt_tokens
        self.requests += 1
        self.estimated = self.estimated or estimated

    @property
    def cache_hit_percent(self) -> Optional[int]:
        """Share of input tokens served from the provider's prompt cache, when any were reported."""
        if not self.input_tokens or not self.cached_input_tokens:
            return None
        return round(100 * self.cached_input_tokens / self.input_tokens)

    def context_percent(self, context_window: Optional[int]) -> Optional[int]:
        if not context_window:
            return None
        return min(100, round(100 * self.last_prompt_tokens / context_window))

    def status_text(self, context_window: Optional[int]) -> str:
        marker = "~" if self.estimated else ""
        text = f"{marker}↑{format_tokens(self.input_tokens)} {marker}↓{format_tokens(self.output_tokens)}"
        percent = self.context_percent(context_window)
        if percent is not None:
            text += f" ctx {percent}%"
        if self.cost_known:
            text += f" ~${self.cost_usd:.4f}"
        return text
