"""
Risk classification and tool metadata for the security platform.

Implements Risk Classes (R0-R4) and tool risk descriptors as specified in plan section 46.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from security_agent.security.autonomy import EnvironmentProfile, AutonomyLevel


class RiskClass(str, Enum):
    """
    Risk classifications for security testing actions and tools.
    """
    R0_PASSIVE = "R0"      # Purely passive, zero side-effects (e.g. read file, DNS query, read headers)
    R1_LOW = "R1"          # Low risk, standard read requests (e.g. open web page, GET request, ping)
    R2_MEDIUM = "R2"       # Active reconnaissance & light active probing (e.g. port scan, banner grab, form fill)
    R3_HIGH = "R3"         # Invasive security tests, potential state change (e.g. auth tests, injections, fuzzing)
    R4_CRITICAL = "R4"     # Destructive or high-impact actions (e.g. raw shell execution, heavy load, drop/write)


@dataclass
class ToolRiskMetadata:
    """
    Declarative risk profile attached to every tool.
    Enforced deterministically by the PolicyEngine.
    """
    name: str
    risk_class: RiskClass = RiskClass.R1_LOW
    requires_approval: bool = False
    environments: List[EnvironmentProfile] = field(
        default_factory=lambda: [EnvironmentProfile.LAB, EnvironmentProfile.STAGING, EnvironmentProfile.PRODUCTION]
    )
    production_allowed: bool = True
    timeout_seconds: int = 30
    max_calls_per_assessment: int = 200
    min_autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_1_PASSIVE

    def is_allowed_in_env(self, env: EnvironmentProfile) -> bool:
        """Check if tool is permitted in the designated environment."""
        if env == EnvironmentProfile.PRODUCTION and not self.production_allowed:
            return False
        return env in self.environments


# Standard risk registry for built-in tools
DEFAULT_TOOL_RISK_PROFILES: Dict[str, ToolRiskMetadata] = {
    # R0: Passive Tools
    "check_headers": ToolRiskMetadata(
        name="check_headers",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "ssl_check": ToolRiskMetadata(
        name="ssl_check",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "dns_lookup": ToolRiskMetadata(
        name="dns_lookup",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "file.read": ToolRiskMetadata(
        name="file.read",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=10,
        min_autonomy_level=AutonomyLevel.LEVEL_0_OBSERVER,
    ),
    "file.search": ToolRiskMetadata(
        name="file.search",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_0_OBSERVER,
    ),

    # R1: Low Risk Tools
    "ping_host": ToolRiskMetadata(
        name="ping_host",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "browser.open": ToolRiskMetadata(
        name="browser.open",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "browser.goto": ToolRiskMetadata(
        name="browser.goto",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "browser.get_forms": ToolRiskMetadata(
        name="browser.get_forms",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "browser.get_html": ToolRiskMetadata(
        name="browser.get_html",
        risk_class=RiskClass.R1_LOW,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_1_PASSIVE,
    ),
    "log_finding": ToolRiskMetadata(
        name="log_finding",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        min_autonomy_level=AutonomyLevel.LEVEL_0_OBSERVER,
    ),
    "log_evidence": ToolRiskMetadata(
        name="log_evidence",
        risk_class=RiskClass.R0_PASSIVE,
        requires_approval=False,
        production_allowed=True,
        min_autonomy_level=AutonomyLevel.LEVEL_0_OBSERVER,
    ),

    # R2: Medium Risk Tools
    "scan_ports": ToolRiskMetadata(
        name="scan_ports",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=False,
        environments=[EnvironmentProfile.LAB, EnvironmentProfile.STAGING],
        timeout_seconds=60,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),
    "grab_banner": ToolRiskMetadata(
        name="grab_banner",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=20,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),
    "http.request": ToolRiskMetadata(
        name="http.request",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=30,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),
    "browser.click": ToolRiskMetadata(
        name="browser.click",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=20,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),
    "browser.fill": ToolRiskMetadata(
        name="browser.fill",
        risk_class=RiskClass.R2_MEDIUM,
        requires_approval=False,
        production_allowed=True,
        timeout_seconds=20,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),
    "file.write": ToolRiskMetadata(
        name="file.write",
        requires_approval=True,
        risk_class=RiskClass.R2_MEDIUM,
        production_allowed=False,
        environments=[EnvironmentProfile.LAB, EnvironmentProfile.STAGING],
        timeout_seconds=15,
        min_autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
    ),

    # Workspace edits need operator approval, like commands
    "file_edit": ToolRiskMetadata(name="file_edit", risk_class=RiskClass.R1_LOW, requires_approval=True),
    "file.edit": ToolRiskMetadata(name="file.edit", risk_class=RiskClass.R1_LOW, requires_approval=True),
    "file_write": ToolRiskMetadata(name="file_write", risk_class=RiskClass.R1_LOW, requires_approval=True),

    # R3 / R4: High & Critical Risk Tools
    "terminal.execute": ToolRiskMetadata(
        name="terminal.execute",
        risk_class=RiskClass.R4_CRITICAL,
        requires_approval=True,
        production_allowed=False,
        environments=[EnvironmentProfile.LAB, EnvironmentProfile.STAGING],
        timeout_seconds=120,
        max_calls_per_assessment=30,
        min_autonomy_level=AutonomyLevel.LEVEL_3_HIGH_IMPACT,
    ),
}


_REGISTRY_CACHE = None

def _get_registry_definition(tool_name: str):
    global _REGISTRY_CACHE
    try:
        if _REGISTRY_CACHE is None:
            from security_agent.tools.registry import create_authoritative_registry
            _REGISTRY_CACHE = create_authoritative_registry()
        canonical = _REGISTRY_CACHE.TOOL_ALIASES.get(tool_name, tool_name)
        return _REGISTRY_CACHE.definitions.get(canonical)
    except Exception:
        return None

def get_tool_risk_metadata(tool_name: str) -> ToolRiskMetadata:
    """
    Retrieves the declared risk metadata for a tool, or constructs a safe default.
    Directly queries ToolDefinition metadata when available to ensure a single,
    unified security architecture.
    """
    if tool_name in DEFAULT_TOOL_RISK_PROFILES:
        return DEFAULT_TOOL_RISK_PROFILES[tool_name]

    defn = _get_registry_definition(tool_name)
    if defn:
        # Derive ToolRiskMetadata directly from authoritative ToolDefinition
        lvl = str(getattr(defn, "risk_level", "LOW")).upper()
        if lvl == "CRITICAL":
            r_class = RiskClass.R4_CRITICAL
            min_autonomy = AutonomyLevel.LEVEL_3_HIGH_IMPACT
            prod_ok = False
        elif lvl == "HIGH":
            r_class = RiskClass.R3_HIGH
            min_autonomy = AutonomyLevel.LEVEL_3_HIGH_IMPACT
            prod_ok = False
        elif lvl == "MEDIUM":
            r_class = RiskClass.R2_MEDIUM
            min_autonomy = AutonomyLevel.LEVEL_2_SAFE_ACTIVE
            prod_ok = not getattr(defn, "destructive", False)
        else:
            r_class = RiskClass.R0_PASSIVE if getattr(defn, "read_only", True) and not getattr(defn, "network_required", False) else RiskClass.R1_LOW
            min_autonomy = AutonomyLevel.LEVEL_1_PASSIVE
            prod_ok = True

        appr = getattr(defn, "approval_required", False) or (r_class == RiskClass.R4_CRITICAL)
        t_out = getattr(defn, "timeout", 30)

        meta = ToolRiskMetadata(
            name=tool_name,
            risk_class=r_class,
            requires_approval=appr,
            production_allowed=prod_ok,
            timeout_seconds=t_out,
            min_autonomy_level=min_autonomy,
        )
        DEFAULT_TOOL_RISK_PROFILES[tool_name] = meta
        return meta

    # Conservative fallback for unknown/custom tools
    return ToolRiskMetadata(
        name=tool_name,
        risk_class=RiskClass.R3_HIGH,
        requires_approval=True,
        production_allowed=False,
        environments=[EnvironmentProfile.LAB],
        min_autonomy_level=AutonomyLevel.LEVEL_3_HIGH_IMPACT,
    )
