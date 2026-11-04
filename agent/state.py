"""
Assessment state machine compatibility shim.
The authoritative canonical implementation is unified in agent.assessment_state.
"""

from agent.assessment_state import (
    AssessmentPhase,
    AssessmentState,
    VALID_TRANSITIONS,
    _default_objective,
)

__all__ = [
    "AssessmentPhase",
    "AssessmentState",
    "VALID_TRANSITIONS",
    "_default_objective",
]
