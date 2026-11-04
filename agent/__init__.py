"""
Security Agent Execution Engine & State Management.
"""

from typing import TYPE_CHECKING

from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ObjectiveStatus,
    VerificationPredicates,
)
from agent.planner import (
    Planner,
    PlannerDecision,
)
from agent.tool_executor import (
    ToolExecutor,
    ToolExecutionResult,
)
from agent.context_manager import ContextManager
from agent.loop_controller import (
    LoopRecoveryController,
    StuckLoopDetector,
)

if TYPE_CHECKING:
    from agent.loop import AgentLoop


def __getattr__(name: str):
    if name == "AgentLoop":
        from agent.loop import AgentLoop
        return AgentLoop
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AssessmentState",
    "AssessmentPhase",
    "AssessmentContext",
    "ObjectiveStatus",
    "VerificationPredicates",
    "Planner",
    "PlannerDecision",
    "ToolExecutor",
    "ToolExecutionResult",
    "ContextManager",
    "LoopRecoveryController",
    "StuckLoopDetector",
    "AgentLoop",
]
