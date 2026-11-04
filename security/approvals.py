"""
Approval Gates and Human-in-the-Loop Control.

Evaluates whether high-impact or invasive actions require human operator confirmation,
and manages interactive or programmatic approval requests.
See plan sections 44, 45, 50.
"""

import re
import sys
from typing import Dict, Any, Optional, Callable, Tuple
from events.bus import EventBus
from events.types import EventType, EventSeverity
from security.autonomy import AutonomyLevel, EnvironmentProfile
from security.risk import RiskClass, ToolRiskMetadata, get_tool_risk_metadata


SESSION_APPROVABLE_EDIT_TOOLS = frozenset({"file_edit", "file.edit", "file_write", "file.write"})
_PLAIN_COMMAND = re.compile(r"^[\w ./:=@%+-]+$")


def session_rule_for(tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
    """
    Returns what "allow for this session" would cover, or None when it must always ask.
    File edits share one rule. A command is covered only as that exact text, and never with
    shell operators or a dangerous pattern. MCP and other tools always ask.
    """
    if tool_name in SESSION_APPROVABLE_EDIT_TOOLS:
        return "file edits"
    if tool_name == "terminal.execute":
        from sandbox.container import DANGEROUS_COMMAND_PATTERNS

        command = str((arguments or {}).get("command", "")).strip()
        if command and _PLAIN_COMMAND.match(command) and not any(p.search(command) for p in DANGEROUS_COMMAND_PATTERNS):
            return f"command: {command}"
    return None


class ApprovalGate:
    """
    Manages operator approval checks for high-risk tools and actions.
    """
    def __init__(
        self,
        autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
        environment: EnvironmentProfile = EnvironmentProfile.LAB,
        event_bus: Optional[EventBus] = None,
        approval_callback: Optional[Callable[[str, Dict[str, Any], ToolRiskMetadata], bool]] = None,
        auto_approve_lab: bool = False
    ):
        self.autonomy_level = autonomy_level
        self.environment = environment
        self.event_bus = event_bus
        self.approval_callback = approval_callback or self._default_console_approval
        self.auto_approve_lab = auto_approve_lab

    def requires_approval(self, tool_name: str, arguments: Dict[str, Any], metadata: Optional[ToolRiskMetadata] = None) -> Tuple[bool, str]:
        """
        Determines if a tool call requires explicit human approval.
        
        Returns:
            Tuple[bool, str]: (requires_approval, reason)
        """
        meta = metadata or get_tool_risk_metadata(tool_name)

        # In lab with high autonomy or automated test mode, skip approval if configured
        if self.environment == EnvironmentProfile.LAB and self.auto_approve_lab:
            return False, "Auto-approved for lab autonomous mode."

        # Production environment: any R2, R3, R4 requires approval
        if self.environment == EnvironmentProfile.PRODUCTION:
            if meta.risk_class in (RiskClass.R2_MEDIUM, RiskClass.R3_HIGH, RiskClass.R4_CRITICAL):
                return True, f"Production environment requires approval for {meta.risk_class.value} action."

        # Explicit tool requirement
        if meta.requires_approval:
            return True, f"Tool '{tool_name}' explicitly requires operator approval ({meta.risk_class.value})."

        # Autonomy Level thresholds:
        # If tool's risk class requires higher autonomy than current setting
        if self.autonomy_level <= AutonomyLevel.LEVEL_1_PASSIVE and meta.risk_class != RiskClass.R0_PASSIVE:
            return True, f"Current autonomy ({self.autonomy_level.name}) requires approval for active {meta.risk_class.value} testing."

        if self.autonomy_level == AutonomyLevel.LEVEL_2_SAFE_ACTIVE and meta.risk_class in (RiskClass.R3_HIGH, RiskClass.R4_CRITICAL):
            return True, f"Autonomy Level 2 requires approval for high-risk action ({meta.risk_class.value})."

        return False, "Action permitted without additional approval."

    def request_approval(self, tool_name: str, arguments: Dict[str, Any], metadata: Optional[ToolRiskMetadata] = None) -> bool:
        """
        Executes the approval request flow, emitting events and awaiting operator decision.
        """
        meta = metadata or get_tool_risk_metadata(tool_name)

        if self.event_bus:
            self.event_bus.emit(
                EventType.APPROVAL_REQUESTED,
                {"tool": tool_name, "arguments": arguments, "risk_class": meta.risk_class.value},
                severity=EventSeverity.WARN,
            )

        approved = False
        try:
            approved = self.approval_callback(tool_name, arguments, meta)
        except Exception:
            approved = False

        if self.event_bus:
            event_type = EventType.APPROVAL_APPROVED if approved else EventType.APPROVAL_REJECTED
            self.event_bus.emit(
                event_type,
                {"tool": tool_name, "approved": approved},
                severity=EventSeverity.INFO if approved else EventSeverity.WARN,
            )

        return approved

    def _default_console_approval(self, tool_name: str, arguments: Dict[str, Any], metadata: ToolRiskMetadata) -> bool:
        """Interactive console prompt when running in an interactive terminal."""
        if not sys.stdin.isatty():
            return False

        print(f"\n\033[1;33m[APPROVAL GATE]\033[0m Operator confirmation required for:")
        print(f"  Tool:       \033[1;36m{tool_name}\033[0m (Risk: \033[1;31m{metadata.risk_class.value}\033[0m)")
        print(f"  Arguments:  {arguments}")
        print(f"  Environment:{self.environment.value.upper()}")
        from sandbox.container import is_docker_active
        if not is_docker_active():
            print("  Isolation:  NONE. Commands run on this machine as the current user.")
        
        try:
            ans = input("Authorize this action? [y/N]: ").strip().lower()
            return ans in ("y", "yes")
        except (KeyboardInterrupt, EOFError):
            return False
