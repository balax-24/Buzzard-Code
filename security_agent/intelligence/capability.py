"""
Explicit Capability Model for Autonomous Security Assessment.

Defines the capability primitives that govern attack surface expansion,
privilege transitions, and recursive reachability in Buzzard Code.

Re-exports canonical Capability and CapabilityType from AssessmentState.
"""

from security_agent.agent.assessment_state import Capability, CapabilityType

__all__ = ["Capability", "CapabilityType"]
