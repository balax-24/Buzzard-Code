"""
Phase 15: Failure-Aware Action Memory & Context-Sensitive Unblocking Engine.

Tracks failure reasons, missing prerequisites, and required conditions for failed actions
(e.g., HTTP 401 Unauthorized -> requires AUTHENTICATED capability).
Blocks blind re-execution while state remains unchanged, but automatically unblocks
actions as soon as relevant capabilities, credentials, or new evidence are acquired.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from intelligence.action_identity import ActionIdentity, SemanticActionKey


class FailureConditionType(str, Enum):
    REQUIRES_AUTH = "REQUIRES_AUTH"
    REQUIRES_ADMIN = "REQUIRES_ADMIN"
    REQUIRES_CREDENTIALS = "REQUIRES_CREDENTIALS"
    PORT_CLOSED = "PORT_CLOSED"
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    PAYLOAD_BLOCKED = "PAYLOAD_BLOCKED"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


@dataclass
class FailureMemoryRecord:
    """Stores the specific reason and prerequisite condition for a failed action."""
    canonical_action_key: str
    target: str
    endpoint: str
    condition_type: FailureConditionType
    failure_reason: str
    required_capabilities: Set[str] = field(default_factory=set)
    required_evidence_types: Set[str] = field(default_factory=set)
    failed_at: float = field(default_factory=time.time)
    unblocked: bool = False
    unblocked_reason: str = ""


class FailureAwareMemory:
    """
    Maintains semantic knowledge of failures and computes dynamic action eligibility.
    """

    def __init__(self):
        self.failure_records: Dict[str, FailureMemoryRecord] = {}

    def record_failure(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        target: str,
        status_code: Optional[int] = None,
        error_message: str = "",
        raw_output: str = "",
    ) -> FailureMemoryRecord:
        """Analyzes an action failure and registers its blocking prerequisite condition."""
        key_obj = ActionIdentity.generate_canonical_key(tool_name, parameters, target)
        canonical_key = key_obj.canonical_key
        output_lower = (raw_output + " " + error_message).lower()

        cond_type = FailureConditionType.UNKNOWN_FAILURE
        req_caps: Set[str] = set()
        reason = error_message or "Action failed"

        # 1. HTTP 401 Unauthorized / Authentication required
        if status_code == 401 or "401" in output_lower or "unauthorized" in output_lower or "login required" in output_lower:
            cond_type = FailureConditionType.REQUIRES_AUTH
            req_caps.add("AUTHENTICATED")
            reason = f"HTTP 401: {key_obj.endpoint} requires authentication credentials/session."

        # 2. HTTP 403 Forbidden / Admin privilege required
        elif status_code == 403 or "403" in output_lower or "forbidden" in output_lower or "access denied" in output_lower:
            cond_type = FailureConditionType.REQUIRES_ADMIN
            req_caps.add("ADMIN_PRIVILEGE")
            req_caps.add("AUTHENTICATED")
            reason = f"HTTP 403: {key_obj.endpoint} requires elevated/admin privileges."

        # 3. HTTP 404 Not Found
        elif status_code == 404 or "404" in output_lower or "not found" in output_lower:
            cond_type = FailureConditionType.ENDPOINT_NOT_FOUND
            reason = f"HTTP 404: Endpoint {key_obj.endpoint} not present on target."

        # 4. Connection refused / Port closed
        elif "connection refused" in output_lower or "refused" in output_lower or "closed" in output_lower:
            cond_type = FailureConditionType.PORT_CLOSED
            reason = f"Port/service unreachable on {target}."

        # 5. Rate limiting (HTTP 429)
        elif status_code == 429 or "429" in output_lower or "too many requests" in output_lower or "rate limit" in output_lower:
            cond_type = FailureConditionType.RATE_LIMITED
            reason = f"Target {target} rate-limited action."

        # 6. WAF / Security filter block
        elif "waf" in output_lower or "blocked by security rule" in output_lower or "firewall" in output_lower:
            cond_type = FailureConditionType.PAYLOAD_BLOCKED
            reason = f"Payload blocked by security filter on {target}."

        rec = FailureMemoryRecord(
            canonical_action_key=canonical_key,
            target=target,
            endpoint=key_obj.endpoint,
            condition_type=cond_type,
            failure_reason=reason,
            required_capabilities=req_caps,
        )
        self.failure_records[canonical_key] = rec
        return rec

    def is_action_blocked(
        self,
        canonical_key: str,
        current_capabilities: Set[str],
        known_credentials: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Determines whether an action is currently blocked by past failure memory.
        Returns (is_blocked: bool, block_reason: str).
        """
        rec = self.failure_records.get(canonical_key)
        if not rec:
            return False, ""

        if rec.unblocked:
            return False, f"Previously unblocked: {rec.unblocked_reason}"

        # Check unblocking conditions
        # 1. Required auth capabilities
        if rec.condition_type == FailureConditionType.REQUIRES_AUTH:
            if "AUTHENTICATED" in current_capabilities or "ADMIN_PRIVILEGE" in current_capabilities or (known_credentials and len(known_credentials) > 0):
                rec.unblocked = True
                rec.unblocked_reason = "Acquired AUTHENTICATED capability"
                return False, rec.unblocked_reason
            return True, f"Blocked: {rec.failure_reason} (Missing AUTHENTICATED capability)"

        # 2. Required admin capabilities
        if rec.condition_type == FailureConditionType.REQUIRES_ADMIN:
            if "ADMIN_PRIVILEGE" in current_capabilities:
                rec.unblocked = True
                rec.unblocked_reason = "Acquired ADMIN_PRIVILEGE capability"
                return False, rec.unblocked_reason
            return True, f"Blocked: {rec.failure_reason} (Missing ADMIN_PRIVILEGE capability)"

        # 3. Port closed or 404
        if rec.condition_type in (FailureConditionType.PORT_CLOSED, FailureConditionType.ENDPOINT_NOT_FOUND):
            return True, f"Blocked: {rec.failure_reason}"

        # 4. Rate limited
        if rec.condition_type == FailureConditionType.RATE_LIMITED:
            # Check cooldown (e.g. 5 seconds)
            if time.time() - rec.failed_at > 5.0:
                rec.unblocked = True
                rec.unblocked_reason = "Rate limit cooldown expired"
                return False, rec.unblocked_reason
            return True, f"Blocked: {rec.failure_reason} (Cooldown in progress)"

        return True, f"Blocked: {rec.failure_reason}"

    def notify_capability_acquired(self, capability_name: str) -> List[str]:
        """Unblocks all actions that were waiting for this capability."""
        cap_upper = capability_name.upper()
        unblocked_keys: List[str] = []

        for key, rec in self.failure_records.items():
            if not rec.unblocked:
                if cap_upper in rec.required_capabilities or (cap_upper == "ADMIN_PRIVILEGE" and "AUTHENTICATED" in rec.required_capabilities):
                    rec.unblocked = True
                    rec.unblocked_reason = f"Acquired capability: {cap_upper}"
                    unblocked_keys.append(key)

        return unblocked_keys

    def notify_new_evidence(self, target: str, endpoint: Optional[str] = None) -> List[str]:
        """Unblocks actions on a target/endpoint if new evidence invalidates past assumptions."""
        unblocked_keys: List[str] = []
        for key, rec in self.failure_records.items():
            if not rec.unblocked and rec.target == target:
                if endpoint is None or endpoint in rec.endpoint:
                    rec.unblocked = True
                    rec.unblocked_reason = f"New evidence discovered for {target}"
                    unblocked_keys.append(key)
        return unblocked_keys

    def to_dict(self) -> Dict[str, Any]:
        """Serializes failure memory."""
        return {
            "failure_records": {
                k: {
                    "canonical_action_key": v.canonical_action_key,
                    "target": v.target,
                    "endpoint": v.endpoint,
                    "condition_type": v.condition_type.value,
                    "failure_reason": v.failure_reason,
                    "required_capabilities": list(v.required_capabilities),
                    "required_evidence_types": list(v.required_evidence_types),
                    "failed_at": v.failed_at,
                    "unblocked": v.unblocked,
                    "unblocked_reason": v.unblocked_reason,
                }
                for k, v in self.failure_records.items()
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FailureAwareMemory:
        """Restores failure memory from dict."""
        mem = cls()
        for k, v in data.get("failure_records", {}).items():
            rec = FailureMemoryRecord(
                canonical_action_key=v["canonical_action_key"],
                target=v["target"],
                endpoint=v["endpoint"],
                condition_type=FailureConditionType(v["condition_type"]),
                failure_reason=v["failure_reason"],
                required_capabilities=set(v.get("required_capabilities", [])),
                required_evidence_types=set(v.get("required_evidence_types", [])),
                failed_at=float(v.get("failed_at", 0.0)),
                unblocked=bool(v.get("unblocked", False)),
                unblocked_reason=v.get("unblocked_reason", ""),
            )
            mem.failure_records[k] = rec
        return mem
