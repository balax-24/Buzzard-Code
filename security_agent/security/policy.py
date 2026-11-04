"""
Comprehensive Security Policy Engine.

Evaluates every tool execution request through the full deterministic control plane:
1. Kill Switch verification
2. Scope & target authorization
3. Assessment authorization certificate validation
4. Environment safety & production constraints
5. Risk class & graduated autonomy checks
6. Per-tool assessment execution quotas
7. Human approval gates

See plan sections 0, 43, 44, 45, 46, 47.
"""

import re
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple, Set

from security_agent.events.bus import EventBus
from security_agent.events.types import EventType, EventSeverity
from security_agent.security.scope import is_in_scope, extract_host_and_port
from security_agent.security.autonomy import AutonomyLevel, EnvironmentProfile
from security_agent.security.risk import RiskClass, ToolRiskMetadata, get_tool_risk_metadata
from security_agent.security.authorization import AssessmentAuthorization, AuthorizationEngine, create_default_authorization
from security_agent.security.kill_switch import KillSwitch
from security_agent.security.approvals import ApprovalGate


@dataclass
class PolicyDecision:
    """Structured decision returned by PolicyEngine."""
    permitted: bool
    reason: str
    risk_class: RiskClass
    requires_approval: bool = False
    approved: bool = False


def _names_existing_file(candidate: str, command: str) -> bool:
    """True when a domain-like string in a command is really a file path, such as test_app.py."""
    from pathlib import Path
    from security_agent.tools.filesystem import get_active_workspace

    workspace = Path(get_active_workspace())
    for token in command.replace("::", " ").split():
        token = token.strip("\"'")
        if candidate in token and "://" not in token and (workspace / token).is_file():
            return True
    return False


class PolicyEngine:
    """
    Control Plane Policy Engine.
    Guarantees deterministic safety boundaries outside LLM weights.
    """
    def __init__(
        self,
        scope: List[str],
        authorization: Optional[AssessmentAuthorization] = None,
        environment: Optional[EnvironmentProfile] = None,
        autonomy_level: Optional[AutonomyLevel] = None,
        event_bus: Optional[EventBus] = None,
        approval_gate: Optional[ApprovalGate] = None,
        kill_switch: Optional[KillSwitch] = None,
    ):
        self.scope = list(scope) if scope else ["localhost", "127.0.0.1"]
        self.event_bus = event_bus
        self.kill_switch = kill_switch or KillSwitch.get_instance(event_bus=event_bus)

        # Setup authorization certificate
        if authorization:
            self.authorization = authorization
        else:
            primary_target = self.scope[0] if self.scope else "localhost"
            env = environment or EnvironmentProfile.LAB
            self.authorization = create_default_authorization(primary_target, scope=self.scope, environment=env)

        # Ensure target_hosts is reference-linked or synced with scope
        self.authorization.target_hosts = self.scope
        self.auth_engine = AuthorizationEngine(self.authorization)
        self.environment = environment or self.authorization.environment
        self.autonomy_level = autonomy_level or self.authorization.max_autonomy_level

        # Lab environment does not imply operator consent. Keep auto-approval
        # disabled unless a caller explicitly injects a separately reviewed gate.
        self.approval_gate = approval_gate or ApprovalGate(
            autonomy_level=self.autonomy_level,
            environment=self.environment,
            event_bus=self.event_bus,
            auto_approve_lab=False,
        )

        # Call counter to enforce max_calls_per_assessment per tool
        self._tool_call_counts: Dict[str, int] = {}

    def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluates a tool call request before execution.
        Backward-compatible interface returning Tuple[bool, str].
        """
        decision = self.evaluate(tool_name, arguments)
        return decision.permitted, decision.reason

    def evaluate(self, tool_name: str, arguments: Dict[str, Any]) -> PolicyDecision:
        """
        Comprehensive multi-stage policy evaluation.
        """
        tool_meta = get_tool_risk_metadata(tool_name)

        if self.event_bus:
            self.event_bus.emit(
                EventType.POLICY_CHECK_STARTED,
                {"tool": tool_name, "risk_class": tool_meta.risk_class.value},
            )

        # Stage 1: Kill Switch Check
        if self.kill_switch.is_triggered():
            reason = f"Execution blocked: Kill switch is ACTIVE ({self.kill_switch.reason})."
            self._emit_denied(tool_name, reason)
            return PolicyDecision(permitted=False, reason=reason, risk_class=tool_meta.risk_class)

        # Stage 2: Assessment Authorization Expiration & Claims
        auth_valid, auth_msg = self.auth_engine.validate_authorization()
        if not auth_valid:
            reason = f"Authorization Denied: {auth_msg}"
            self._emit_denied(tool_name, reason)
            return PolicyDecision(permitted=False, reason=reason, risk_class=tool_meta.risk_class)

        # Stage 3: Scope Enforcement (Direct arguments & embedded commands)
        target_in_scope, scope_msg = self._check_scope(tool_name, arguments)
        if not target_in_scope:
            self._emit_denied(tool_name, scope_msg)
            return PolicyDecision(permitted=False, reason=scope_msg, risk_class=tool_meta.risk_class)

        # Stage 4: Environment Profile & Production Constraints
        if not tool_meta.is_allowed_in_env(self.environment):
            reason = (
                f"Policy Denied: Tool '{tool_name}' ({tool_meta.risk_class.value}) is not permitted in "
                f"the '{self.environment.value}' environment."
            )
            self._emit_denied(tool_name, reason)
            return PolicyDecision(permitted=False, reason=reason, risk_class=tool_meta.risk_class)

        # Stage 5: Risk Class Compliance with Authorization Certificate
        if not self.auth_engine.is_risk_class_permitted(tool_meta.risk_class):
            reason = (
                f"Authorization Denied: Risk class {tool_meta.risk_class.value} is not permitted by "
                f"Authorization {self.authorization.id}."
            )
            self._emit_denied(tool_name, reason)
            return PolicyDecision(permitted=False, reason=reason, risk_class=tool_meta.risk_class)

        # Stage 6: Tool Execution Quota Enforcement
        current_calls = self._tool_call_counts.get(tool_name, 0)
        if current_calls >= tool_meta.max_calls_per_assessment:
            reason = (
                f"Policy Denied: Tool '{tool_name}' exceeded maximum allowed invocations "
                f"({tool_meta.max_calls_per_assessment}) for this assessment."
            )
            self._emit_denied(tool_name, reason)
            return PolicyDecision(permitted=False, reason=reason, risk_class=tool_meta.risk_class)

        # Stage 7: Human Approval Gate
        req_approval, approval_reason = self.approval_gate.requires_approval(tool_name, arguments, tool_meta)
        if req_approval:
            is_approved = self.approval_gate.request_approval(tool_name, arguments, tool_meta)
            if not is_approved:
                reason = f"Operator Approval Denied: {approval_reason}"
                self._emit_denied(tool_name, reason)
                return PolicyDecision(
                    permitted=False,
                    reason=reason,
                    risk_class=tool_meta.risk_class,
                    requires_approval=True,
                    approved=False
                )

        # Approved and permitted!
        self._tool_call_counts[tool_name] = current_calls + 1
        if self.event_bus:
            self.event_bus.emit(
                EventType.POLICY_ALLOWED,
                {"tool": tool_name, "risk_class": tool_meta.risk_class.value},
            )

        return PolicyDecision(
            permitted=True,
            reason="Operation permitted under active policy and authorization.",
            risk_class=tool_meta.risk_class,
            requires_approval=req_approval,
            approved=True
        )

    def _check_scope(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """Checks scope for direct parameters and terminal commands."""
        if not arguments:
            return True, "Scope valid."

        # 1. Direct target arguments
        host_param = (
            arguments.get("host")
            or arguments.get("target")
            or arguments.get("url")
            or arguments.get("domain")
            or arguments.get("ip")
            or arguments.get("cidr")
            or arguments.get("base_url")
            or arguments.get("ip_or_asn")
        )
        if host_param:
            if not is_in_scope(str(host_param), self.scope):
                return False, f"Target '{host_param}' is outside the authorized testing scope: {self.scope}"
            # Also verify with authorization certificate
            auth_ok, auth_err = self.auth_engine.is_target_authorized(str(host_param))
            if not auth_ok:
                return False, auth_err

        # 2. Inspect terminal.execute command payloads
        if tool_name == "terminal.execute" and "command" in arguments:
            command = str(arguments["command"])
            if not command:
                return True, "Scope valid."

            domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', command)
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', command)

            for candidate in domains + ips:
                if candidate.lower() in ["localhost", "127.0.0.1"]:
                    continue
                if _names_existing_file(candidate, command):
                    continue
                if not is_in_scope(candidate, self.scope):
                    return False, f"Command contains out-of-scope target '{candidate}'. Scope is: {self.scope}"
                auth_ok, auth_err = self.auth_engine.is_target_authorized(candidate)
                if not auth_ok:
                    return False, auth_err

        return True, "Scope valid."

    def _emit_denied(self, tool_name: str, reason: str) -> None:
        if self.event_bus:
            self.event_bus.emit(
                EventType.POLICY_DENIED,
                {"tool": tool_name, "reason": reason},
                severity=EventSeverity.WARN,
            )
