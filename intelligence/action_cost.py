"""
Phase 15: Action Cost & Investigation Efficiency Engine.

Calculates multi-attribute operational cost for security actions:
  action_cost = latency_cost + tool_cost + retry_cost + context_token_cost

Calculates:
  action_efficiency = actual_gain / max(0.1, action_cost)
  expected_efficiency = expected_gain / max(0.1, expected_cost)

Enforces efficiency-driven planning rather than unconstrained tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CostBreakdown:
    tool_cost: float
    latency_cost: float
    retry_cost: float
    context_cost: float
    total_cost: float
    expected_efficiency: float


class ActionCostEngine:
    """
    Computes expected and actual costs for actions.
    """

    # Base cost per tool category (in normalized units)
    TOOL_BASE_COSTS: Dict[str, float] = {
        "http_request": 0.5,
        "http_client": 0.5,
        "curl": 0.5,
        "nmap": 2.0,
        "port_scan": 2.0,
        "sqlmap": 3.0,
        "sqli_probe": 2.5,
        "browser_navigate": 2.5,
        "browser_fill": 1.5,
        "browser_click": 1.5,
        "browser_snapshot": 2.0,
        "verify_finding": 1.0,
        "verify_objective": 1.0,
    }

    @classmethod
    def estimate_cost(
        cls,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        expected_latency_seconds: float = 1.0,
        retry_count: int = 0,
        context_tokens: int = 1000,
        expected_gain: float = 1.0,
    ) -> CostBreakdown:
        """Estimates total cost and expected efficiency for a candidate action."""
        tool_norm = (tool_name or "").lower()
        tool_cost = cls.TOOL_BASE_COSTS.get(tool_norm, 1.0)
        lat_cost = expected_latency_seconds * 0.2
        retry_cost = retry_count * 0.5
        ctx_cost = (context_tokens / 1000.0) * 0.1

        total_cost = tool_cost + lat_cost + retry_cost + ctx_cost
        exp_eff = expected_gain / max(0.1, total_cost)

        return CostBreakdown(
            tool_cost=tool_cost,
            latency_cost=lat_cost,
            retry_cost=retry_cost,
            context_cost=ctx_cost,
            total_cost=total_cost,
            expected_efficiency=exp_eff,
        )

    @classmethod
    def calculate_actual_efficiency(
        cls,
        actual_gain: float,
        actual_latency_seconds: float,
        tool_name: str,
        retries_used: int = 0,
    ) -> float:
        """Calculates realized efficiency post execution."""
        tool_norm = (tool_name or "").lower()
        base_cost = cls.TOOL_BASE_COSTS.get(tool_norm, 1.0)
        total_cost = base_cost + (actual_latency_seconds * 0.2) + (retries_used * 0.5)
        return actual_gain / max(0.1, total_cost)
