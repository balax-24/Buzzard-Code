"""
Per-task budgets for coding tasks (roadmap E4 and F5).

A coding task used to stop at a fixed number of turns, however much work was left and however
little it cost. With a budget, the task runs until it finishes or reaches a limit on tokens,
money or time, and the turn limit only guards against runaway loops. When a limit is reached
the task stops as paused (so `/tasks resume` can continue it) with a message saying which
limit was reached.

Configuration, in the Buzzard config:

    "task_budget": {"max_tokens": 2000000, "max_usd": 2.0, "max_minutes": 60, "max_turns": 150}

Every field is optional. A money limit needs a known price for the model (see
core/usage.py); without one it cannot be enforced and the task says so when it starts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

BUDGETED_TURN_LIMIT = 150  # turns allowed when another limit is set but max_turns is not
MAX_TURN_LIMIT = 500
_FIELDS = {"max_turns": int, "max_tokens": int, "max_usd": float, "max_minutes": float}


class TaskBudgetError(ValueError):
    """The task_budget setting is not valid."""


@dataclass(frozen=True)
class TaskBudget:
    max_turns: Optional[int] = None
    max_tokens: Optional[int] = None
    max_usd: Optional[float] = None
    max_minutes: Optional[float] = None

    @property
    def limited(self) -> bool:
        """True when a token, money or time limit governs the task."""
        return any(value is not None for value in (self.max_tokens, self.max_usd, self.max_minutes))

    def turn_limit(self, default: int) -> int:
        if self.max_turns is not None:
            return self.max_turns
        return max(default, BUDGETED_TURN_LIMIT) if self.limited else default

    def exceeded(self, tokens: int, cost_usd: Optional[float], elapsed_seconds: float) -> Optional[str]:
        """Which limit is reached, in words, or None."""
        if self.max_tokens is not None and tokens >= self.max_tokens:
            return f"token limit reached ({tokens:,} of {self.max_tokens:,})"
        if self.max_usd is not None and cost_usd is not None and cost_usd >= self.max_usd:
            return f"cost limit reached (about ${cost_usd:.2f} of ${self.max_usd:.2f})"
        if self.max_minutes is not None and elapsed_seconds >= self.max_minutes * 60:
            return f"time limit reached ({elapsed_seconds / 60:.1f} of {self.max_minutes:g} minutes)"
        return None


def task_budget_from(config: Dict[str, Any]) -> TaskBudget:
    """Reads `task_budget` from the config. An invalid value raises TaskBudgetError, never a silent default."""
    raw = config.get("task_budget")
    if raw is None:
        return TaskBudget()
    if not isinstance(raw, dict):
        raise TaskBudgetError("task_budget must be an object such as {\"max_tokens\": 2000000}")
    unknown = sorted(set(raw) - set(_FIELDS))
    if unknown:
        raise TaskBudgetError(f"task_budget has unknown field(s): {', '.join(unknown)}")
    values: Dict[str, Any] = {}
    for name, kind in _FIELDS.items():
        value = raw.get(name)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (kind is int and not isinstance(value, int)):
            raise TaskBudgetError(f"task_budget.{name} must be a {'whole ' if kind is int else ''}number, not {value!r}")
        if value <= 0:
            raise TaskBudgetError(f"task_budget.{name} must be greater than 0")
        values[name] = kind(value)
    if values.get("max_turns", 0) > MAX_TURN_LIMIT:
        raise TaskBudgetError(f"task_budget.max_turns can be at most {MAX_TURN_LIMIT}")
    return TaskBudget(**values)


def price_per_million(model_name: str) -> Optional[Tuple[float, float]]:
    from core.usage import KNOWN_PRICES_PER_MILLION

    return KNOWN_PRICES_PER_MILLION.get(str(model_name).split("/")[-1])
