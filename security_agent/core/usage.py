"""Session token accounting and context window lookup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Only sizes confirmed from published documentation. Unknown models report no percentage
# rather than a guessed one.
KNOWN_CONTEXT_WINDOWS: Dict[str, int] = {
    "muse-spark-1.3": 1_048_576,
}
CHARS_PER_TOKEN_ESTIMATE = 4


def usage_to_metrics(usage: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Converts OpenAI-format or Anthropic-format usage to the loop's metric names."""
    if not usage:
        return {}
    return {
        "prompt_eval_count": usage.get("prompt_tokens") or usage.get("input_tokens") or 0,
        "eval_count": usage.get("completion_tokens") or usage.get("output_tokens") or 0,
    }


def estimate_tokens(messages: List[Dict[str, Any]]) -> int:
    """Rough size of a message list, for providers that report no usage."""
    return sum(len(str(message.get("content") or "")) for message in messages) // CHARS_PER_TOKEN_ESTIMATE


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
    last_prompt_tokens: int = 0
    requests: int = 0
    estimated: bool = False

    def record(self, prompt_tokens: int, output_tokens: int, estimated: bool = False) -> None:
        self.input_tokens += prompt_tokens
        self.output_tokens += output_tokens
        self.last_prompt_tokens = prompt_tokens
        self.requests += 1
        self.estimated = self.estimated or estimated

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
        return text
