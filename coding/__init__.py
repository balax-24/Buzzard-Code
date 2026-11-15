"""
Buzzard Code lean core package (roadmap H).

Exports the pure software engineering capabilities of Buzzard Code without
dependencies on legacy security or penetration testing modules.
"""

from __future__ import annotations

from agent.loop import CODING_SESSION_ONLY_TOOLS, CODING_TOOL_NAMES
from agent.run_session import RunSession as CodingSession
from coding.interfaces import (
    CodingGate,
    CodingModelProvider,
    CodingOutcome,
    CodingToolRegistry,
)
from coding.loop import CodingLoop
from coding.registry import create_coding_registry
from verification.coding_verifier import CodingVerifier

__all__ = [
    "create_coding_registry",
    "CODING_TOOL_NAMES",
    "CODING_SESSION_ONLY_TOOLS",
    "CodingLoop",
    "CodingSession",
    "CodingVerifier",
    "CodingOutcome",
    "CodingModelProvider",
    "CodingGate",
    "CodingToolRegistry",
]
