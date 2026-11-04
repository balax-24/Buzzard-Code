"""
Autonomy Levels and Environment Profiles for Buzzard Code.

Defines the graduated autonomy model (Levels 0-5) and deployment environments (Lab, Staging, Production)
as specified in OWASP APTS and plan sections 44 & 45.
"""

from enum import Enum, IntEnum
from typing import Dict, Set


class AutonomyLevel(IntEnum):
    """
    Graduated autonomy levels for security testing operations.
    
    Higher levels grant greater independence to the agent, while lower
    levels require explicit human gates or restrict actions to non-invasive inspection.
    """
    LEVEL_0_OBSERVER = 0         # Source review, config analysis, static docs review only
    LEVEL_1_PASSIVE = 1          # Passive network/browser inspection, metadata, headers
    LEVEL_2_SAFE_ACTIVE = 2      # Controlled API inspection, authorized test identities, safe probes
    LEVEL_3_HIGH_IMPACT = 3      # Active verification, fuzzing, parameter tampering (approval required)
    LEVEL_4_LAB_AUTONOMOUS = 4   # Full autonomy within an isolated lab / cyber range
    LEVEL_5_PRODUCTION = 5       # Strict production guardrails (read-only + safe verification + approval gates)


class EnvironmentProfile(str, Enum):
    """
    Target deployment environment profile.
    Controls default risk thresholds, allowed tools, and safety policies.
    """
    LAB = "lab"                 # Isolated cyber range or local testing container
    STAGING = "staging"         # Pre-production environment
    PRODUCTION = "production"   # Live production service (maximum caution)


def get_default_max_autonomy(env: EnvironmentProfile) -> AutonomyLevel:
    """
    Returns the maximum safe default autonomy level for a given environment.
    """
    if env == EnvironmentProfile.LAB:
        return AutonomyLevel.LEVEL_4_LAB_AUTONOMOUS
    elif env == EnvironmentProfile.STAGING:
        return AutonomyLevel.LEVEL_2_SAFE_ACTIVE
    else:
        return AutonomyLevel.LEVEL_1_PASSIVE
