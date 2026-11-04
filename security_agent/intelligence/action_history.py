"""
Phase 15: Action History & Empirical Outcome Store.

Maintains an immutable, queryable audit trail of all candidate actions, expected vs actual
information gain, prediction calibration, failures, evidence created, and graph mutations.
Allows the planner to answer:
  1. "Have I already done this action?"
  2. "What happened last time I executed this action?"
  3. "Is my expected gain predictor well calibrated?"
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from security_agent.intelligence.action_identity import ActionIdentity, SemanticActionKey


class ActionOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    NO_OP = "NO_OP"
    BLOCKED_AUTH = "BLOCKED_AUTH"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class ActionHistoryRecord:
    """Detailed record of an executed action and its empirical delta."""
    action_id: str
    canonical_action_key: str
    target: str
    tool_name: str
    parameters: Dict[str, Any]
    branch_id: str = "main"
    capability_context: str = "default"
    hypothesis_id: Optional[str] = None
    purpose: str = ""
    expected_gain: float = 1.0
    actual_gain: float = 0.0
    prediction_error: float = 1.0  # expected - actual
    cost: float = 1.0
    efficiency: float = 0.0        # actual_gain / cost
    timestamp: float = field(default_factory=time.time)
    outcome: ActionOutcome = ActionOutcome.SUCCESS
    evidence_created: List[str] = field(default_factory=list)
    nodes_created: int = 0
    edges_created: int = 0
    capabilities_acquired: List[str] = field(default_factory=list)
    findings_discovered: List[str] = field(default_factory=list)
    repeated_count: int = 0
    why_this_action: str = ""


@dataclass
class ActionHistoryStore:
    """
    Queryable history store for all executed security actions.
    """
    records: List[ActionHistoryRecord] = field(default_factory=list)
    _action_counts: Dict[str, int] = field(default_factory=dict)
    _action_outcomes: Dict[str, List[ActionOutcome]] = field(default_factory=dict)
    _action_contexts: Dict[str, Set[str]] = field(default_factory=dict)

    def record_action(
        self,
        action_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        target: str,
        branch_id: str = "main",
        capability_context: str = "default",
        hypothesis_id: Optional[str] = None,
        purpose: str = "",
        expected_gain: float = 1.0,
        actual_gain: float = 0.0,
        cost: float = 1.0,
        outcome: ActionOutcome = ActionOutcome.SUCCESS,
        evidence_created: Optional[List[str]] = None,
        nodes_created: int = 0,
        edges_created: int = 0,
        capabilities_acquired: Optional[List[str]] = None,
        findings_discovered: Optional[List[str]] = None,
        why_this_action: str = "",
        timestamp: Optional[float] = None,
    ) -> ActionHistoryRecord:
        """Records an action execution and updates internal indices."""
        key_obj = ActionIdentity.generate_canonical_key(
            tool_name=tool_name,
            parameters=parameters,
            target=target,
            capability_context=capability_context,
        )
        canonical_key = key_obj.canonical_key
        prev_count = self._action_counts.get(canonical_key, 0)
        repetition_count = prev_count + 1

        pred_err = expected_gain - actual_gain
        eff = actual_gain / max(0.1, cost)

        rec = ActionHistoryRecord(
            action_id=action_id,
            canonical_action_key=canonical_key,
            target=target,
            tool_name=tool_name,
            parameters=parameters,
            branch_id=branch_id,
            capability_context=capability_context,
            hypothesis_id=hypothesis_id,
            purpose=purpose,
            expected_gain=expected_gain,
            actual_gain=actual_gain,
            prediction_error=pred_err,
            cost=cost,
            efficiency=eff,
            timestamp=timestamp if timestamp is not None else time.time(),
            outcome=outcome,
            evidence_created=evidence_created or [],
            nodes_created=nodes_created,
            edges_created=edges_created,
            capabilities_acquired=capabilities_acquired or [],
            findings_discovered=findings_discovered or [],
            repeated_count=repetition_count,
            why_this_action=why_this_action,
        )

        self.records.append(rec)
        self._action_counts[canonical_key] = repetition_count
        if canonical_key not in self._action_outcomes:
            self._action_outcomes[canonical_key] = []
        self._action_outcomes[canonical_key].append(outcome)

        if canonical_key not in self._action_contexts:
            self._action_contexts[canonical_key] = set()
        self._action_contexts[canonical_key].add(capability_context)

        return rec

    def has_action_been_attempted(
        self,
        canonical_key: str,
        capability_context: Optional[str] = None,
    ) -> bool:
        """Checks if a canonical action has been attempted (optionally in a specific context)."""
        if canonical_key not in self._action_counts:
            return False
        if capability_context is not None:
            return capability_context in self._action_contexts.get(canonical_key, set())
        return True

    def get_repetition_count(self, canonical_key: str) -> int:
        """Returns the number of times this canonical action was executed."""
        return self._action_counts.get(canonical_key, 0)

    def get_last_outcome(self, canonical_key: str) -> Optional[ActionOutcome]:
        """Returns the most recent outcome for an action key."""
        outcomes = self._action_outcomes.get(canonical_key, [])
        return outcomes[-1] if outcomes else None

    def get_recent_records(self, limit: int = 10) -> List[ActionHistoryRecord]:
        """Returns the last N executed actions."""
        return self.records[-limit:]

    def get_recent_noop_rate(self, window: int = 20) -> float:
        """Computes the fraction of actions that produced NO_OP or 0 actual gain in recent history."""
        sample = self.records[-window:]
        if not sample:
            return 0.0
        noops = sum(1 for r in sample if r.outcome == ActionOutcome.NO_OP or r.actual_gain == 0.0)
        return noops / len(sample)

    def get_average_prediction_error(self, window: int = 20) -> float:
        """Returns average prediction error in the given window."""
        sample = self.records[-window:]
        if not sample:
            return 0.0
        return sum(abs(r.prediction_error) for r in sample) / len(sample)

    def get_average_efficiency(self, window: int = 20) -> float:
        """Returns average action efficiency (gain / cost)."""
        sample = self.records[-window:]
        if not sample:
            return 0.0
        return sum(r.efficiency for r in sample) / len(sample)

    def get_records_for_action(
        self,
        canonical_key: str,
        capability_context: Optional[str] = None,
    ) -> List[ActionHistoryRecord]:
        """Returns all history records for a canonical action key, optionally filtered by context."""
        if capability_context:
            return [r for r in self.records if r.canonical_action_key == canonical_key and r.capability_context == capability_context]
        return [r for r in self.records if r.canonical_action_key == canonical_key]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes action history for checkpoint persistence."""
        return {
            "records": [
                {
                    "action_id": r.action_id,
                    "canonical_action_key": r.canonical_action_key,
                    "target": r.target,
                    "tool_name": r.tool_name,
                    "parameters": r.parameters,
                    "branch_id": r.branch_id,
                    "capability_context": r.capability_context,
                    "hypothesis_id": r.hypothesis_id,
                    "purpose": r.purpose,
                    "expected_gain": r.expected_gain,
                    "actual_gain": r.actual_gain,
                    "prediction_error": r.prediction_error,
                    "cost": r.cost,
                    "efficiency": r.efficiency,
                    "timestamp": r.timestamp,
                    "outcome": r.outcome.value,
                    "evidence_created": r.evidence_created,
                    "nodes_created": r.nodes_created,
                    "edges_created": r.edges_created,
                    "capabilities_acquired": r.capabilities_acquired,
                    "findings_discovered": r.findings_discovered,
                    "repeated_count": r.repeated_count,
                    "why_this_action": r.why_this_action,
                }
                for r in self.records
            ]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ActionHistoryStore:
        """Restores action history from dict."""
        store = cls()
        for d in data.get("records", []):
            rec = ActionHistoryRecord(
                action_id=d["action_id"],
                canonical_action_key=d["canonical_action_key"],
                target=d["target"],
                tool_name=d["tool_name"],
                parameters=d.get("parameters", {}),
                branch_id=d.get("branch_id", "main"),
                capability_context=d.get("capability_context", "default"),
                hypothesis_id=d.get("hypothesis_id"),
                purpose=d.get("purpose", ""),
                expected_gain=float(d.get("expected_gain", 1.0)),
                actual_gain=float(d.get("actual_gain", 0.0)),
                prediction_error=float(d.get("prediction_error", 1.0)),
                cost=float(d.get("cost", 1.0)),
                efficiency=float(d.get("efficiency", 0.0)),
                timestamp=float(d.get("timestamp", 0.0)),
                outcome=ActionOutcome(d.get("outcome", "SUCCESS")),
                evidence_created=d.get("evidence_created", []),
                nodes_created=int(d.get("nodes_created", 0)),
                edges_created=int(d.get("edges_created", 0)),
                capabilities_acquired=d.get("capabilities_acquired", []),
                findings_discovered=d.get("findings_discovered", []),
                repeated_count=int(d.get("repeated_count", 0)),
                why_this_action=d.get("why_this_action", ""),
            )
            store.records.append(rec)
            store._action_counts[rec.canonical_action_key] = rec.repeated_count
            if rec.canonical_action_key not in store._action_outcomes:
                store._action_outcomes[rec.canonical_action_key] = []
            store._action_outcomes[rec.canonical_action_key].append(rec.outcome)

            if rec.canonical_action_key not in store._action_contexts:
                store._action_contexts[rec.canonical_action_key] = set()
            store._action_contexts[rec.canonical_action_key].add(rec.capability_context)

        return store
