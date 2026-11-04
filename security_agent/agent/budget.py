"""
Budget tracker for security assessments.

Tracks resource consumption against configurable limits:
- Wall-clock time
- Tool calls  
- HTTP requests
- Model tokens (input + output)
- High-risk actions

Emits budget.warning and budget.exceeded events through the EventBus
when thresholds are reached.

See plan sections 2.6 and 46.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

from security_agent.events.types import Event, EventType, EventSeverity


@dataclass
class BudgetConfig:
    """Configurable budget limits for an assessment."""
    duration_seconds: int = 3600        # 1 hour default
    max_tool_calls: int = 500
    max_requests: int = 1000
    max_model_tokens: int = 500_000     # total input + output tokens
    max_high_risk_actions: int = 50
    warning_threshold: float = 0.80     # emit warning at 80% usage


@dataclass
class BudgetTracker:
    """
    Tracks resource consumption and checks against budget limits.
    
    Call `check()` after each operation to get the budget status.
    The tracker does NOT enforce limits — it provides information
    for the orchestrator to act on.
    """
    config: BudgetConfig = field(default_factory=BudgetConfig)
    start_time: float = field(default_factory=time.time)

    # Counters
    tool_calls: int = 0
    requests: int = 0
    browser_actions: int = 0
    retries_count: int = 0
    compression_cycles: int = 0
    checkpoint_operations: int = 0
    model_input_tokens: int = 0
    model_output_tokens: int = 0
    high_risk_actions: int = 0

    # Latencies (seconds)
    total_model_latency: float = 0.0
    total_tool_latency: float = 0.0
    total_browser_latency: float = 0.0

    # Track which warnings have already been emitted
    _warned: Dict[str, bool] = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def model_tokens_total(self) -> int:
        return self.model_input_tokens + self.model_output_tokens

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_tool_call(self, latency: float = 0.0) -> None:
        self.tool_calls += 1
        self.total_tool_latency += latency

    def record_browser_action(self, latency: float = 0.0) -> None:
        self.browser_actions += 1
        self.total_browser_latency += latency

    def record_retry(self) -> None:
        self.retries_count += 1

    def record_compression(self) -> None:
        self.compression_cycles += 1

    def record_checkpoint_op(self) -> None:
        self.checkpoint_operations += 1

    def record_request(self) -> None:
        self.requests += 1

    def record_model_tokens(self, input_tokens: int = 0, output_tokens: int = 0, latency: float = 0.0) -> None:
        self.model_input_tokens += input_tokens
        self.model_output_tokens += output_tokens
        self.total_model_latency += latency

    def get_cost_metrics(
        self,
        findings_count: int = 0,
        capabilities_count: int = 0,
        objectives_verified_count: int = 0
    ) -> Dict[str, float]:
        """
        Calculates unified cost per action, finding, capability, and verified objective.
        """
        # Estimated cost model ($3/M in, $15/M out for enterprise LLM reference)
        token_cost = (self.model_input_tokens * 3.0 / 1_000_000) + (self.model_output_tokens * 15.0 / 1_000_000)
        total_actions = max(1, self.tool_calls + self.browser_actions)

        return {
            "total_estimated_cost_usd": round(token_cost, 4),
            "cost_per_action_usd": round(token_cost / total_actions, 5),
            "cost_per_finding_usd": round(token_cost / max(1, findings_count), 4) if findings_count else 0.0,
            "cost_per_capability_usd": round(token_cost / max(1, capabilities_count), 4) if capabilities_count else 0.0,
            "cost_per_verified_objective_usd": round(token_cost / max(1, objectives_verified_count), 4) if objectives_verified_count else 0.0,
            "avg_model_latency_seconds": round(self.total_model_latency / max(1, self.tool_calls), 3),
            "avg_tool_latency_seconds": round(self.total_tool_latency / max(1, self.tool_calls), 3)
        }

    def record_high_risk(self) -> None:
        self.high_risk_actions += 1

    # ------------------------------------------------------------------
    # Checking
    # ------------------------------------------------------------------

    def is_exceeded(self) -> bool:
        """Check if any budget limit has been exceeded."""
        return (
            self.elapsed_seconds > self.config.duration_seconds
            or self.tool_calls > self.config.max_tool_calls
            or self.requests > self.config.max_requests
            or self.model_tokens_total > self.config.max_model_tokens
            or self.high_risk_actions > self.config.max_high_risk_actions
        )

    def get_status(self) -> Dict[str, Any]:
        """
        Returns a structured status dict showing usage vs limits.
        Suitable for display in the live dashboard.
        """
        return {
            "time": {
                "used": int(self.elapsed_seconds),
                "limit": self.config.duration_seconds,
                "pct": min(100, int(100 * self.elapsed_seconds / max(1, self.config.duration_seconds))),
            },
            "tool_calls": {
                "used": self.tool_calls,
                "limit": self.config.max_tool_calls,
                "pct": min(100, int(100 * self.tool_calls / max(1, self.config.max_tool_calls))),
            },
            "requests": {
                "used": self.requests,
                "limit": self.config.max_requests,
                "pct": min(100, int(100 * self.requests / max(1, self.config.max_requests))),
            },
            "tokens": {
                "used": self.model_tokens_total,
                "limit": self.config.max_model_tokens,
                "pct": min(100, int(100 * self.model_tokens_total / max(1, self.config.max_model_tokens))),
                "input": self.model_input_tokens,
                "output": self.model_output_tokens,
            },
            "high_risk": {
                "used": self.high_risk_actions,
                "limit": self.config.max_high_risk_actions,
                "pct": min(100, int(100 * self.high_risk_actions / max(1, self.config.max_high_risk_actions))),
            },
            "exceeded": self.is_exceeded(),
        }

    def check_warnings(self) -> list:
        """
        Returns a list of budget categories that have crossed
        the warning threshold but haven't been warned about yet.
        """
        warnings = []
        threshold = self.config.warning_threshold
        status = self.get_status()

        for category, data in status.items():
            if category == "exceeded":
                continue
            if isinstance(data, dict) and "pct" in data:
                if data["pct"] >= threshold * 100 and not self._warned.get(category):
                    self._warned[category] = True
                    warnings.append({
                        "category": category,
                        "used": data["used"],
                        "limit": data["limit"],
                        "pct": data["pct"],
                    })

        return warnings

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for persistence."""
        return {
            "start_time": self.start_time,
            "tool_calls": self.tool_calls,
            "requests": self.requests,
            "model_input_tokens": self.model_input_tokens,
            "model_output_tokens": self.model_output_tokens,
            "high_risk_actions": self.high_risk_actions,
            "config": {
                "duration_seconds": self.config.duration_seconds,
                "max_tool_calls": self.config.max_tool_calls,
                "max_requests": self.config.max_requests,
                "max_model_tokens": self.config.max_model_tokens,
                "max_high_risk_actions": self.config.max_high_risk_actions,
                "warning_threshold": self.config.warning_threshold,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BudgetTracker":
        config_data = data.get("config", {})
        config = BudgetConfig(
            duration_seconds=config_data.get("duration_seconds", 3600),
            max_tool_calls=config_data.get("max_tool_calls", 500),
            max_requests=config_data.get("max_requests", 1000),
            max_model_tokens=config_data.get("max_model_tokens", 500_000),
            max_high_risk_actions=config_data.get("max_high_risk_actions", 50),
            warning_threshold=config_data.get("warning_threshold", 0.80),
        )
        tracker = cls(config=config)
        tracker.start_time = data.get("start_time", time.time())
        tracker.tool_calls = data.get("tool_calls", 0)
        tracker.requests = data.get("requests", 0)
        tracker.model_input_tokens = data.get("model_input_tokens", 0)
        tracker.model_output_tokens = data.get("model_output_tokens", 0)
        tracker.high_risk_actions = data.get("high_risk_actions", 0)
        return tracker

    def format_display(self) -> str:
        """Format budget for CLI display."""
        status = self.get_status()
        t = status["time"]
        tc = status["tool_calls"]
        rq = status["requests"]
        tk = status["tokens"]

        mins, secs = divmod(t["used"], 60)
        t_limit_mins, t_limit_secs = divmod(t["limit"], 60)

        lines = [
            f"Time:       {mins}m {secs:02d}s / {t_limit_mins}m {t_limit_secs:02d}s",
            f"Tool calls: {tc['used']} / {tc['limit']}",
            f"Requests:   {rq['used']} / {rq['limit']}",
            f"Tokens:     {tk['used']:,} / {tk['limit']:,} (in: {tk['input']:,} out: {tk['output']:,})",
        ]
        return "\n".join(lines)
