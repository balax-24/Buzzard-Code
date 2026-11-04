"""
Phase 15: Context-Aware & Evidence-Aware Action Reconsideration Engine.

Evaluates state transitions to identify previously attempted, failed, or exhausted actions
that have become contextually justified due to:
  1. Capability acquisition (e.g., ANONYMOUS -> AUTHENTICATED -> ADMIN)
  2. New credential or session token discovery
  3. New evidence that materially changes hypothesis plausibility
  4. Target architecture or service state modification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from security_agent.intelligence.action_identity import ActionIdentity
from security_agent.intelligence.action_history import ActionHistoryStore, ActionHistoryRecord
from security_agent.intelligence.failure_memory import FailureAwareMemory, FailureConditionType


class ReconsiderationTrigger(str, Enum):
    CAPABILITY_ACQUIRED = "CAPABILITY_ACQUIRED"
    CREDENTIAL_ACQUIRED = "CREDENTIAL_ACQUIRED"
    EVIDENCE_DISCOVERED = "EVIDENCE_DISCOVERED"
    HYPOTHESIS_FORMED = "HYPOTHESIS_FORMED"


@dataclass
class ReconsideredAction:
    canonical_action_key: str
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    trigger: ReconsiderationTrigger
    justification: str
    refreshed_expected_gain: float
    previous_attempt_count: int


class ReconsiderationEngine:
    """
    Identifies and unblocks actions justified by state transitions.
    """

    @classmethod
    def evaluate_capability_transition(
        cls,
        new_capability: str,
        history: ActionHistoryStore,
        failure_memory: FailureAwareMemory,
        current_capabilities: Set[str],
    ) -> List[ReconsideredAction]:
        """
        Reconsiders actions previously blocked or failed when a new capability is acquired.
        """
        unblocked_keys = failure_memory.notify_capability_acquired(new_capability)
        reconsidered: List[ReconsideredAction] = []

        for rec in history.records:
            if rec.canonical_action_key in unblocked_keys or ("admin" in rec.canonical_action_key.lower() and new_capability.upper() in ("AUTHENTICATED", "ADMIN_PRIVILEGE")):
                # Action was previously attempted, but now has justifiable reason to re-evaluate!
                reconsidered.append(
                    ReconsideredAction(
                        canonical_action_key=rec.canonical_action_key,
                        tool_name=rec.tool_name,
                        target=rec.target,
                        parameters=rec.parameters,
                        trigger=ReconsiderationTrigger.CAPABILITY_ACQUIRED,
                        justification=f"Reconsidered: Acquired `{new_capability}` capability unblocks `{rec.canonical_action_key}`.",
                        refreshed_expected_gain=4.0,  # Refreshed high gain
                        previous_attempt_count=rec.repeated_count,
                    )
                )

        return reconsidered

    @classmethod
    def evaluate_evidence_transition(
        cls,
        target: str,
        new_evidence_content: str,
        history: ActionHistoryStore,
        failure_memory: FailureAwareMemory,
    ) -> List[ReconsideredAction]:
        """
        Reconsiders actions on a target when new evidence materially changes the context.
        """
        unblocked_keys = failure_memory.notify_new_evidence(target)
        reconsidered: List[ReconsideredAction] = []

        for rec in history.records:
            if rec.target == target and (rec.canonical_action_key in unblocked_keys or "error" in rec.outcome.value.lower() or rec.actual_gain == 0.0):
                reconsidered.append(
                    ReconsideredAction(
                        canonical_action_key=rec.canonical_action_key,
                        tool_name=rec.tool_name,
                        target=rec.target,
                        parameters=rec.parameters,
                        trigger=ReconsiderationTrigger.EVIDENCE_DISCOVERED,
                        justification=f"Reconsidered: New evidence on `{target}` unblocks `{rec.canonical_action_key}`.",
                        refreshed_expected_gain=3.0,
                        previous_attempt_count=rec.repeated_count,
                    )
                )

        return reconsidered
