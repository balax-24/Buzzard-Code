"""
Phase 14 Exactly-Once Idempotency & Operation Tracking Engine.

Ensures every externally observable action has an operation ID:
- operation_id
- session_id
- turn_id
- tool_call_id

Prevents duplicate evidence, duplicate findings, duplicate graph edges,
duplicate capabilities, and duplicate hypotheses during replay or restart recovery.
"""

from __future__ import annotations

import uuid
import hashlib
from typing import Set, Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class OperationRecord:
    operation_id: str
    session_id: str
    turn_id: int
    tool_call_id: str
    operation_type: str  # e.g. "TOOL_EXECUTION", "EVIDENCE_INGESTION", "FINDING_CREATION"
    target: str
    status: str = "COMPLETED"
    result_hash: str = ""
    created_at: float = 0.0


class IdempotencyManager:
    """
    Guards against duplicated operations, evidence, findings, capabilities, and edges.
    """

    def __init__(self):
        self.completed_operations: Dict[str, OperationRecord] = {}
        self.seen_evidence_hashes: Set[str] = set()
        self.seen_finding_signatures: Set[str] = set()
        self.seen_capability_keys: Set[str] = set()
        self.seen_edge_keys: Set[str] = set()
        self.seen_hypothesis_keys: Set[str] = set()

    @staticmethod
    def generate_operation_id(session_id: str, turn_id: int, tool_call_id: str, op_type: str) -> str:
        raw = f"{session_id}:{turn_id}:{tool_call_id}:{op_type}"
        return f"op-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"

    def is_operation_completed(self, operation_id: str) -> bool:
        return operation_id in self.completed_operations

    def record_operation(
        self,
        operation_id: str,
        session_id: str,
        turn_id: int,
        tool_call_id: str,
        op_type: str,
        target: str,
        result_data: Any = None,
    ) -> OperationRecord:
        res_hash = hashlib.sha256(str(result_data).encode("utf-8")).hexdigest()[:16]
        rec = OperationRecord(
            operation_id=operation_id,
            session_id=session_id,
            turn_id=turn_id,
            tool_call_id=tool_call_id,
            operation_type=op_type,
            target=target,
            result_hash=res_hash
        )
        self.completed_operations[operation_id] = rec
        return rec

    def is_evidence_duplicate(self, content: str, source_tool: str, target: str) -> bool:
        h = hashlib.sha256(f"{source_tool}:{target}:{content}".encode("utf-8")).hexdigest()
        if h in self.seen_evidence_hashes:
            return True
        self.seen_evidence_hashes.add(h)
        return False

    def is_finding_duplicate(self, title: str, target: str, vuln_type: str) -> bool:
        sig = f"{vuln_type.lower()}:{target.lower()}:{title.lower()}"
        if sig in self.seen_finding_signatures:
            return True
        self.seen_finding_signatures.add(sig)
        return False

    def is_capability_duplicate(self, cap_type: str, target_scope: str) -> bool:
        key = f"{cap_type.upper()}:{target_scope.lower()}"
        if key in self.seen_capability_keys:
            return True
        self.seen_capability_keys.add(key)
        return False

    def is_edge_duplicate(self, source_id: str, target_id: str, edge_kind: str) -> bool:
        key = f"{source_id}->{target_id}:{edge_kind}"
        if key in self.seen_edge_keys:
            return True
        self.seen_edge_keys.add(key)
        return False

    def is_hypothesis_duplicate(self, target: str, category: str) -> bool:
        key = f"{target.lower()}:{category.lower()}"
        if key in self.seen_hypothesis_keys:
            return True
        self.seen_hypothesis_keys.add(key)
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "completed_operations": {k: v.__dict__ for k, v in self.completed_operations.items()},
            "seen_evidence_hashes": list(self.seen_evidence_hashes),
            "seen_finding_signatures": list(self.seen_finding_signatures),
            "seen_capability_keys": list(self.seen_capability_keys),
            "seen_edge_keys": list(self.seen_edge_keys),
            "seen_hypothesis_keys": list(self.seen_hypothesis_keys),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IdempotencyManager:
        mgr = cls()
        mgr.seen_evidence_hashes = set(data.get("seen_evidence_hashes", []))
        mgr.seen_finding_signatures = set(data.get("seen_finding_signatures", []))
        mgr.seen_capability_keys = set(data.get("seen_capability_keys", []))
        mgr.seen_edge_keys = set(data.get("seen_edge_keys", []))
        mgr.seen_hypothesis_keys = set(data.get("seen_hypothesis_keys", []))
        for op_id, op_data in data.get("completed_operations", {}).items():
            mgr.completed_operations[op_id] = OperationRecord(**op_data)
        return mgr
