"""
Phase 14 Tool & Model Failure Recovery Engine.

Provides deterministic classification and recovery strategies for:
1. Tool Failures:
   - TIMEOUT
   - MALFORMED_OUTPUT
   - SCHEMA_ERROR
   - CONNECTION_FAILURE
   - EMPTY_RESPONSE
   - PARTIAL_RESPONSE
   - TOOL_CRASH
   - SANDBOX_FAILURE
   - BROWSER_TIMEOUT

2. Model Failures:
   - EMPTY_OUTPUT
   - INVALID_JSON
   - MALFORMED_TOOL_CALL
   - WRONG_PARAMETER_NAME
   - HALLUCINATED_TOOL
   - REPEATED_IDENTICAL_ACTION
   - PREMATURE_COMPLETION
   - REASONING_TRUNCATION
   - TIMEOUT

Failure Outcomes:
- RETRY (bounded with explicit reason)
- REFORMULATE (correct parameters/format)
- PIVOT (switch target or approach)
- ABANDON (deprioritize dead ends)
- ESCALATE (acquire prerequisites)
- CONCLUDE (surface exhausted)
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple


class ToolFailureType(str, Enum):
    TIMEOUT = "TIMEOUT"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    CONNECTION_FAILURE = "CONNECTION_FAILURE"
    EMPTY_RESPONSE = "EMPTY_RESPONSE"
    PARTIAL_RESPONSE = "PARTIAL_RESPONSE"
    TOOL_CRASH = "TOOL_CRASH"
    SANDBOX_FAILURE = "SANDBOX_FAILURE"
    BROWSER_TIMEOUT = "BROWSER_TIMEOUT"
    UNKNOWN = "UNKNOWN"


class ModelFailureType(str, Enum):
    EMPTY_OUTPUT = "EMPTY_OUTPUT"
    INVALID_JSON = "INVALID_JSON"
    MALFORMED_TOOL_CALL = "MALFORMED_TOOL_CALL"
    WRONG_PARAMETER_NAME = "WRONG_PARAMETER_NAME"
    HALLUCINATED_TOOL = "HALLUCINATED_TOOL"
    REPEATED_IDENTICAL_ACTION = "REPEATED_IDENTICAL_ACTION"
    PREMATURE_COMPLETION = "PREMATURE_COMPLETION"
    REASONING_TRUNCATION = "REASONING_TRUNCATION"
    TIMEOUT = "TIMEOUT"


class RecoveryAction(str, Enum):
    RETRY = "RETRY"
    REFORMULATE = "REFORMULATE"
    PIVOT = "PIVOT"
    ABANDON = "ABANDON"
    ESCALATE = "ESCALATE"
    CONCLUDE = "CONCLUDE"


@dataclass
class FailureRecoveryPlan:
    action: RecoveryAction
    reason: str
    remediation_prompt: str
    max_retries_allowed: int = 2
    current_retry_count: int = 0
    suggested_tool_or_target: Optional[str] = None


class FailureRecoveryController:
    """
    Classifies tool and model failures and generates deterministic recovery directives.
    """

    def __init__(self, max_tool_retries: int = 2, max_model_retries: int = 2):
        self.max_tool_retries = max_tool_retries
        self.max_model_retries = max_model_retries
        self.tool_retry_tracker: Dict[str, int] = {}  # key -> count
        self.model_retry_tracker: Dict[str, int] = {}

    def classify_tool_failure(
        self,
        tool_name: str,
        target: str,
        error_message: str,
        exit_code: Optional[int] = None
    ) -> ToolFailureType:
        err = error_message.lower()
        if "timed out" in err or "timeout" in err or "deadline exceeded" in err:
            if "browser" in tool_name or "playwright" in err:
                return ToolFailureType.BROWSER_TIMEOUT
            return ToolFailureType.TIMEOUT
        if "connection refused" in err or "no route to host" in err or "network is unreachable" in err:
            return ToolFailureType.CONNECTION_FAILURE
        if "schema" in err or "invalid parameter" in err or "missing required" in err:
            return ToolFailureType.SCHEMA_ERROR
        if "container" in err or "sandbox" in err or "docker" in err or exit_code == 137:
            return ToolFailureType.SANDBOX_FAILURE
        if not err.strip():
            return ToolFailureType.EMPTY_RESPONSE
        if "jsondecodeerror" in err or "syntaxerror" in err:
            return ToolFailureType.MALFORMED_OUTPUT
        if exit_code and exit_code != 0:
            return ToolFailureType.TOOL_CRASH
        return ToolFailureType.UNKNOWN

    def plan_tool_recovery(
        self,
        tool_name: str,
        target: str,
        failure_type: ToolFailureType,
        error_details: str
    ) -> FailureRecoveryPlan:
        tracker_key = f"{tool_name}:{target}:{failure_type.value}"
        attempts = self.tool_retry_tracker.get(tracker_key, 0) + 1
        self.tool_retry_tracker[tracker_key] = attempts

        if failure_type in (ToolFailureType.TIMEOUT, ToolFailureType.CONNECTION_FAILURE):
            if attempts <= self.max_tool_retries:
                return FailureRecoveryPlan(
                    action=RecoveryAction.RETRY,
                    reason=f"Transient {failure_type.value} on `{target}` (attempt {attempts}/{self.max_tool_retries})",
                    remediation_prompt=f"Tool `{tool_name}` encountered {failure_type.value} against `{target}`. Retrying with extended timeout.",
                    max_retries_allowed=self.max_tool_retries,
                    current_retry_count=attempts
                )
            else:
                return FailureRecoveryPlan(
                    action=RecoveryAction.PIVOT,
                    reason=f"Exhausted retries ({attempts}) for `{tool_name}` against `{target}`",
                    remediation_prompt=f"Target `{target}` is unresponsive via `{tool_name}`. Pivot to alternate services or endpoints.",
                    max_retries_allowed=self.max_tool_retries,
                    current_retry_count=attempts
                )

        if failure_type == ToolFailureType.SCHEMA_ERROR:
            return FailureRecoveryPlan(
                action=RecoveryAction.REFORMULATE,
                reason=f"Parameter schema validation failed for `{tool_name}`: {error_details}",
                remediation_prompt=f"Correct parameter types/names for `{tool_name}` according to registered tool schema.",
                max_retries_allowed=1,
                current_retry_count=attempts
            )

        if failure_type == ToolFailureType.SANDBOX_FAILURE:
            return FailureRecoveryPlan(
                action=RecoveryAction.ESCALATE,
                reason="Sandbox execution environment failure",
                remediation_prompt="Restart container runtime sandbox and re-dispatch command.",
                max_retries_allowed=1,
                current_retry_count=attempts
            )

        return FailureRecoveryPlan(
            action=RecoveryAction.PIVOT,
            reason=f"Unhandled tool failure {failure_type.value}",
            remediation_prompt=f"Tool `{tool_name}` failed. Explore alternate reachable nodes in attack graph.",
            max_retries_allowed=1,
            current_retry_count=attempts
        )

    def classify_model_failure(
        self,
        raw_output: str,
        parsed_action: Optional[Any],
        is_duplicate: bool = False,
        timed_out: bool = False,
    ) -> ModelFailureType:
        if timed_out:
            return ModelFailureType.TIMEOUT
        if not raw_output or not raw_output.strip():
            return ModelFailureType.EMPTY_OUTPUT
        if is_duplicate:
            return ModelFailureType.REPEATED_IDENTICAL_ACTION
        if parsed_action is None:
            if "```json" in raw_output and "}" not in raw_output:
                return ModelFailureType.REASONING_TRUNCATION
            return ModelFailureType.INVALID_JSON
        return ModelFailureType.INVALID_JSON

    def plan_model_recovery(
        self,
        failure_type: ModelFailureType,
        context_prompt: str,
        attempt: int = 1
    ) -> FailureRecoveryPlan:
        if failure_type == ModelFailureType.EMPTY_OUTPUT:
            return FailureRecoveryPlan(
                action=RecoveryAction.RETRY,
                reason="Model generated zero tokens or blank response",
                remediation_prompt="Please generate a valid structured candidate selection decision based on the active evidence.",
                max_retries_allowed=self.max_model_retries,
                current_retry_count=attempt
            )
        if failure_type == ModelFailureType.INVALID_JSON:
            return FailureRecoveryPlan(
                action=RecoveryAction.REFORMULATE,
                reason="Model response was not valid JSON conforming to CandidateAction schema",
                remediation_prompt="Output MUST be strictly valid JSON matching the CandidateAction schema. Do not output raw explanations outside JSON.",
                max_retries_allowed=self.max_model_retries,
                current_retry_count=attempt
            )
        if failure_type == ModelFailureType.REPEATED_IDENTICAL_ACTION:
            return FailureRecoveryPlan(
                action=RecoveryAction.PIVOT,
                reason="Model proposed identical action that previously yielded zero information gain",
                remediation_prompt="Selected action was already executed without new findings. Choose an unvisited node or untested hypothesis.",
                max_retries_allowed=self.max_model_retries,
                current_retry_count=attempt
            )
        if failure_type == ModelFailureType.TIMEOUT:
            return FailureRecoveryPlan(
                action=RecoveryAction.RETRY,
                reason="Model inference timed out",
                remediation_prompt="Re-dispatching candidate prompt with compact state summary.",
                max_retries_allowed=self.max_model_retries,
                current_retry_count=attempt
            )
        return FailureRecoveryPlan(
            action=RecoveryAction.REFORMULATE,
            reason=f"Model error: {failure_type.value}",
            remediation_prompt="Ensure action proposal references verified scope and available tools.",
            max_retries_allowed=self.max_model_retries,
            current_retry_count=attempt
        )
