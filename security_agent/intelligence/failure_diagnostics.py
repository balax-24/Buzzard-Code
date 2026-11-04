"""
Structured Failure Recovery & Diagnostic Feedback Engine for Buzzard Code.

Provides informative, non-prescriptive feedback to the model following tool failures,
teaching the model that failure provides information and repeated identical failures
mandate a strategy pivot.

Invariants:
- Never hardcodes scenario-specific solutions ('if X fails, always do Y').
- Classifies failures into standard operational categories.
- Highlights whether the failure yielded diagnostic information (e.g. 401 confirms endpoint exists).
- Suggests broad alternative action classes rather than prescriptive tool names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FailureCategory(str, Enum):
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    FORBIDDEN_ACCESS = "FORBIDDEN_ACCESS"
    COMMAND_EXECUTION_ERROR = "COMMAND_EXECUTION_ERROR"
    PARAMETER_SCHEMA_ERROR = "PARAMETER_SCHEMA_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    GENERAL_ERROR = "GENERAL_ERROR"


@dataclass
class StructuredFailureFeedback:
    tool_name: str
    tool_arguments: Dict[str, Any]
    raw_error: str
    failure_category: FailureCategory
    is_retryable: bool
    produced_information: bool
    information_gained_summary: str
    previous_similar_failures: int = 0
    affected_hypothesis: Optional[str] = None
    alternative_action_classes: List[str] = field(default_factory=list)

    def format_feedback_block(self) -> str:
        """
        Emits a structured diagnostic feedback block for model prompt injection.
        """
        lines = [
            f"⚡ [STRUCTURED FAILURE DIAGNOSTIC: {self.tool_name}]",
            f"• Category: {self.failure_category.value}",
            f"• Retryable: {'YES (with altered parameters)' if self.is_retryable else 'NO (do not repeat identical action)'}",
            f"• Diagnostic Information: {self.information_gained_summary}",
        ]
        if self.previous_similar_failures > 0:
            lines.append(
                f"• Warning: {self.previous_similar_failures} similar failure(s) recorded in memory. PIVOT STRATEGY REQUIRED."
            )
        if self.alternative_action_classes:
            lines.append(
                f"• Recommended Alternative Strategies: {', '.join(self.alternative_action_classes)}"
            )
        return "\n".join(lines)

    def format_for_model(self) -> str:
        return self.format_feedback_block()


class FailureDiagnosticsEngine:
    """
    Analyzes raw tool failure outputs and builds structured diagnostic feedback.
    """

    @classmethod
    def diagnose_failure(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        raw_output: str,
        exit_code: int = 1,
        previous_failure_count: int = 0,
        active_hypothesis: Optional[str] = None,
        error_type: Optional[str] = None,
    ) -> StructuredFailureFeedback:
        out_lower = (raw_output + " " + (error_type or "")).lower()

        # 1. Connection / Network errors
        if any(w in out_lower for w in ("connection refused", "connect error", "unreachable", "errno 111")):
            category = FailureCategory.CONNECTION_REFUSED
            retryable = False
            info = "Target port is closed or host is not listening on this protocol. Confirms port is unreachable."
            alts = ["Perform port scan on alternate ports", "Check host accessibility via ping"]

        # 2. 404 Not Found
        elif "404" in out_lower or "not found" in out_lower:
            category = FailureCategory.ENDPOINT_NOT_FOUND
            retryable = True  # Retryable with different URL path
            info = "Endpoint does not exist. Confirms this specific route is invalid."
            alts = ["Directory / route discovery", "Inspect HTML / API documentation for valid routes"]

        # 3. 401 Unauthorized
        elif "401" in out_lower or "unauthorized" in out_lower:
            category = FailureCategory.AUTHENTICATION_REQUIRED
            retryable = True
            info = "Endpoint EXISTS and is protected by authentication. High-value target for credential or session validation."
            alts = ["Provide authentication headers or session cookies", "Search for credentials in previously observed responses"]

        # 4. 403 Forbidden
        elif "403" in out_lower or "forbidden" in out_lower:
            category = FailureCategory.FORBIDDEN_ACCESS
            retryable = False
            info = "Endpoint exists but access is forbidden by policy or ACL."
            alts = ["Test for header-based IP bypasses", "Explore alternate endpoints or roles"]

        # 5. Schema / argument errors
        elif any(w in out_lower for w in ("missing required", "invalid argument", "schema error", "validation error")):
            category = FailureCategory.PARAMETER_SCHEMA_ERROR
            retryable = True
            info = "Tool arguments did not match the declared schema definition."
            alts = ["Review tool schema parameter types and required fields"]

        # 6. Timeout
        elif "timeout" in out_lower or "timed out" in out_lower:
            category = FailureCategory.TIMEOUT_ERROR
            retryable = True
            info = "Request timed out waiting for server response."
            alts = ["Verify service responsiveness", "Increase timeout or test alternate network path"]

        # 7. General error fallback
        else:
            category = FailureCategory.GENERAL_ERROR
            retryable = True
            info = f"Command failed with exit code {exit_code}."
            alts = ["Analyze error output and pivot to alternative reconnaissance tool"]

        return StructuredFailureFeedback(
            tool_name=tool_name,
            tool_arguments=arguments,
            raw_error=raw_output[:300],
            failure_category=category,
            is_retryable=retryable,
            produced_information=True,
            information_gained_summary=info,
            previous_similar_failures=previous_failure_count,
            affected_hypothesis=active_hypothesis,
            alternative_action_classes=alts,
        )
