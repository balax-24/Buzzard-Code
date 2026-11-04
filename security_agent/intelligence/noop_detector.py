"""
Phase 15: No-Op Action & Stagnation Detection Engine.

Identifies actions that produce zero state delta:
  - No new evidence
  - No new graph nodes / edges
  - No capability transitions
  - No hypothesis updates
  - No verified findings
  - No additional surface coverage

Classifies these as NO_INFORMATION_ACTION and computes stagnation triggers
for strategy diversification and branching pivots.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ActionDelta:
    new_evidence_count: int = 0
    new_nodes_count: int = 0
    new_edges_count: int = 0
    new_capabilities_count: int = 0
    new_findings_count: int = 0
    refuted_hypotheses_count: int = 0
    coverage_delta_pct: float = 0.0


@dataclass
class NoOpEvaluation:
    is_noop: bool
    total_delta_score: float
    consecutive_noops: int
    should_trigger_pivot: bool
    rationale: str

    @property
    def should_pivot(self) -> bool:
        return self.should_trigger_pivot


class NoOpDetector:
    """
    Monitors action execution deltas and flags non-productive stagnation loops.
    """

    def __init__(self, pivot_threshold: int = 3):
        self.pivot_threshold = pivot_threshold
        self.consecutive_noops: int = 0
        self.total_noops: int = 0
        self.total_actions: int = 0

    def evaluate_delta(
        self,
        delta: ActionDelta,
        tool_name: str,
        target: str,
    ) -> NoOpEvaluation:
        """Evaluates an action's state delta and determines if it is a No-Op."""
        self.total_actions += 1

        delta_score = (
            (delta.new_evidence_count * 1.0) +
            (delta.new_nodes_count * 2.0) +
            (delta.new_edges_count * 1.5) +
            (delta.new_capabilities_count * 5.0) +
            (delta.new_findings_count * 10.0) +
            (delta.refuted_hypotheses_count * 1.5) +
            (delta.coverage_delta_pct * 0.5)
        )

        is_noop = (delta_score == 0.0)

        if is_noop:
            self.consecutive_noops += 1
            self.total_noops += 1
            should_pivot = (self.consecutive_noops >= self.pivot_threshold)
            rationale = (
                f"Action `{tool_name}` on `{target}` produced 0 delta "
                f"({self.consecutive_noops} consecutive no-ops). "
                f"{'STRATEGY PIVOT REQUIRED.' if should_pivot else ''}"
            )
        else:
            self.consecutive_noops = 0
            should_pivot = False
            rationale = f"Productive action: delta score = {delta_score:.2f}"

        return NoOpEvaluation(
            is_noop=is_noop,
            total_delta_score=delta_score,
            consecutive_noops=self.consecutive_noops,
            should_trigger_pivot=should_pivot,
            rationale=rationale,
        )

    def reset_consecutive(self) -> None:
        """Resets consecutive counter (e.g. after branch switch or pivot)."""
        self.consecutive_noops = 0

    @property
    def noop_rate(self) -> float:
        """Returns overall fraction of actions that were no-ops."""
        if self.total_actions == 0:
            return 0.0
        return self.total_noops / self.total_actions
