"""
Event types for the Buzzard Code event bus.

Every meaningful action in the assessment lifecycle emits a typed event.
Events are serializable, immutable after creation, and persisted for
audit, replay, and live dashboard rendering.
"""

import uuid
import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


class EventType(str, Enum):
    """All event types emitted during an assessment lifecycle."""

    # Assessment lifecycle
    ASSESSMENT_STARTED = "assessment.started"
    ASSESSMENT_PHASE_CHANGED = "assessment.phase_changed"
    ASSESSMENT_PAUSED = "assessment.paused"
    ASSESSMENT_RESUMED = "assessment.resumed"
    ASSESSMENT_STOPPED = "assessment.stopped"
    ASSESSMENT_COMPLETED = "assessment.completed"

    # Agent state
    AGENT_STATUS = "agent.status"
    AGENT_THINKING_STARTED = "agent.thinking_started"
    AGENT_THINKING_COMPLETED = "agent.thinking_completed"
    AGENT_PLAN_CREATED = "agent.plan_created"
    AGENT_ACTION_PROPOSED = "agent.action_proposed"

    # Policy engine
    POLICY_CHECK_STARTED = "policy.check_started"
    POLICY_ALLOWED = "policy.allowed"
    POLICY_DENIED = "policy.denied"

    # Approval gates
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_REJECTED = "approval.rejected"

    # Tool execution
    TOOL_STARTED = "tool.started"
    TOOL_PROGRESS = "tool.progress"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"

    # Browser
    BROWSER_NAVIGATION = "browser.navigation"

    # HTTP
    HTTP_REQUEST = "http.request"
    HTTP_RESPONSE = "http.response"

    # Source analysis
    SOURCE_FILE_ANALYZED = "source.file_analyzed"

    # Hypothesis engine
    HYPOTHESIS_CREATED = "hypothesis.created"
    HYPOTHESIS_UPDATED = "hypothesis.updated"

    # Findings
    FINDING_SUSPECTED = "finding.suspected"
    FINDING_VERIFIED = "finding.verified"
    FINDING_REJECTED = "finding.rejected"

    # Evidence
    EVIDENCE_CREATED = "evidence.created"

    # Risk
    RISK_UPDATED = "risk.updated"

    # Workers
    WORKER_STARTED = "worker.started"
    WORKER_COMPLETED = "worker.completed"

    # Model
    MODEL_STARTED = "model.started"
    MODEL_TOKEN = "model.token"
    MODEL_PROGRESS = "model.progress"
    MODEL_COMPLETED = "model.completed"
    MODEL_TIMEOUT = "model.timeout"

    # Budget
    BUDGET_WARNING = "budget.warning"
    BUDGET_EXCEEDED = "budget.exceeded"

    # Stagnation / loop
    STAGNATION_DETECTED = "stagnation.detected"
    LOOP_DETECTED = "loop.detected"

    # Phase 14 Structured Telemetry
    TURN_STARTED = "turn.started"
    TURN_COMPLETED = "turn.completed"
    CAPABILITY_ACQUIRED = "capability.acquired"
    GRAPH_EXPANDED = "graph.expanded"
    BRANCH_CREATED = "branch.created"
    BRANCH_SWITCHED = "branch.switched"
    CHECKPOINT_CREATED = "checkpoint.created"
    CHECKPOINT_RESTORED = "checkpoint.restored"
    MEMORY_COMPRESSED = "memory.compressed"
    VERIFICATION_STARTED = "verification.started"
    VERIFICATION_COMPLETED = "verification.completed"
    OBJECTIVE_VERIFIED = "objective.verified"
    OBJECTIVE_FAILED = "objective.failed"
    SESSION_RECOVERED = "session.recovered"



class EventSeverity(str, Enum):
    """Severity classification for display and filtering."""
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Event:
    """
    Immutable event emitted by any component during an assessment.
    
    Events are the fundamental unit of observability. They are published
    to the EventBus, persisted in the EventStore, and consumed by the
    live CLI dashboard, the web dashboard, and the audit log.
    """
    type: EventType
    payload: Dict[str, Any] = field(default_factory=dict)
    severity: EventSeverity = EventSeverity.INFO
    assessment_id: Optional[str] = None
    id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for persistence and transport."""
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Deserialize from a plain dict."""
        return cls(
            id=data.get("id", f"evt-{uuid.uuid4().hex[:12]}"),
            type=EventType(data["type"]),
            severity=EventSeverity(data.get("severity", "info")),
            assessment_id=data.get("assessment_id"),
            timestamp=data.get("timestamp", time.time()),
            payload=data.get("payload", {}),
        )

    @property
    def summary(self) -> str:
        """Human-readable one-line summary for live event feeds."""
        msg = self.payload.get("message") or self.payload.get("summary") or ""
        if msg:
            return f"[{self.type.value}] {msg}"
        return f"[{self.type.value}]"
