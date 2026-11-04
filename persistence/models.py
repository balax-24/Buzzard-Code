"""
Phase 12 Persistence Domain Models & Checkpoint Structures.

Defines:
- InvestigationCheckpoint
- StateSnapshot, GraphSnapshot, EvidenceSnapshot, HypothesisSnapshot,
  CapabilitySnapshot, SessionSnapshot, DecisionSnapshot, BudgetSnapshot, BranchSnapshot
- CheckpointIntegrityMetadata
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional


class InvestigationStatus(str, Enum):
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class JournalEventType(str, Enum):
    TOOL_SELECTED = "TOOL_SELECTED"
    TOOL_EXECUTED = "TOOL_EXECUTED"
    TOOL_FAILED = "TOOL_FAILED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    HYPOTHESIS_REFUTED = "HYPOTHESIS_REFUTED"
    HYPOTHESIS_REOPENED = "HYPOTHESIS_REOPENED"
    CAPABILITY_ACQUIRED = "CAPABILITY_ACQUIRED"
    CAPABILITY_VERIFIED = "CAPABILITY_VERIFIED"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_UPDATED = "SESSION_UPDATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    GRAPH_EXPANDED = "GRAPH_EXPANDED"
    GRAPH_NODE_EXHAUSTED = "GRAPH_NODE_EXHAUSTED"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    VERIFICATION_SUCCESS = "VERIFICATION_SUCCESS"
    OBJECTIVE_CHANGED = "OBJECTIVE_CHANGED"
    STRATEGY_CHANGED = "STRATEGY_CHANGED"
    CHECKPOINT_CREATED = "CHECKPOINT_CREATED"
    CHECKPOINT_RESTORED = "CHECKPOINT_RESTORED"
    BUDGET_WARNING = "BUDGET_WARNING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    INVESTIGATION_PAUSED = "INVESTIGATION_PAUSED"
    INVESTIGATION_RESUMED = "INVESTIGATION_RESUMED"


@dataclass
class JournalEntry:
    event_id: str
    investigation_id: str
    event_type: JournalEventType
    timestamp: float
    source: str
    payload: Dict[str, Any]
    evidence_ids: List[str] = field(default_factory=list)
    state_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "investigation_id": self.investigation_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "source": self.source,
            "payload": self.payload,
            "evidence_ids": self.evidence_ids,
            "state_version": self.state_version
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JournalEntry:
        return cls(
            event_id=data["event_id"],
            investigation_id=data["investigation_id"],
            event_type=JournalEventType(data["event_type"]),
            timestamp=data["timestamp"],
            source=data["source"],
            payload=data.get("payload", {}),
            evidence_ids=data.get("evidence_ids", []),
            state_version=data.get("state_version", 1)
        )


@dataclass
class StateSnapshot:
    target: str
    scope: List[str]
    current_phase: str
    objective_status: str
    services: Dict[str, Any]
    http_endpoints: Dict[str, Any]
    forms: Dict[str, Any]
    dom_snapshots: Dict[str, Any]
    findings: List[Dict[str, Any]]
    action_metadata_log: List[Dict[str, Any]]
    decision_records: List[Dict[str, Any]]
    autonomy_mode: str
    completion_mode: str
    hypotheses_considered: int
    hypotheses_selected: int
    hypotheses_refuted: int
    hypotheses_reopened: int
    evidence: Dict[str, Any] = field(default_factory=dict)
    hypotheses: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphSnapshot:
    nodes: Dict[str, Dict[str, Any]]
    edges: List[Dict[str, Any]]
    version: int = 1


@dataclass
class HypothesisSnapshot:
    hypotheses: Dict[str, Dict[str, Any]]
    refuted_ids: List[str] = field(default_factory=list)
    proposals_generated: int = 0
    proposals_executed: int = 0


@dataclass
class CapabilitySnapshot:
    capabilities: Dict[str, Dict[str, Any]]
    version: int = 1


@dataclass
class SessionSnapshot:
    sessions: Dict[str, Dict[str, Any]]
    active_session_ids: List[str] = field(default_factory=list)


@dataclass
class BranchSnapshot:
    branches: Dict[str, Dict[str, Any]]
    active_branch_id: Optional[str] = None


@dataclass
class BudgetSnapshot:
    elapsed_seconds: float
    max_seconds: float
    tool_calls_used: int
    max_tool_calls: int
    iterations_used: int
    max_iterations: int
    token_usage: int = 0


@dataclass
class CheckpointIntegrityMetadata:
    schema_version: str = "12.0.0"
    content_hash: str = ""
    parent_checkpoint_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class InvestigationCheckpoint:
    checkpoint_id: str
    investigation_id: str
    status: InvestigationStatus
    timestamp: float
    state_version: int
    objective: str
    scope: List[str]
    current_phase: str
    objective_status: str
    state_snapshot: StateSnapshot
    graph_snapshot: GraphSnapshot
    hypothesis_snapshot: HypothesisSnapshot
    capability_snapshot: CapabilitySnapshot
    session_snapshot: SessionSnapshot
    branch_snapshot: BranchSnapshot
    budget_snapshot: BudgetSnapshot
    integrity: CheckpointIntegrityMetadata

    def calculate_checksum(self) -> str:
        """Computes deterministic SHA-256 hash of all snapshot payload data."""
        canonical_dict = {
            "checkpoint_id": self.checkpoint_id,
            "investigation_id": self.investigation_id,
            "state_version": self.state_version,
            "objective": self.objective,
            "scope": sorted(self.scope),
            "state": asdict(self.state_snapshot),
            "graph": asdict(self.graph_snapshot),
            "hypotheses": asdict(self.hypothesis_snapshot),
            "capabilities": asdict(self.capability_snapshot),
            "sessions": asdict(self.session_snapshot),
            "branches": asdict(self.branch_snapshot),
            "budget": asdict(self.budget_snapshot),
        }
        encoded = json.dumps(canonical_dict, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
