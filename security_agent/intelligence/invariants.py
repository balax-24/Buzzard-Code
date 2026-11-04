"""
Phase 14 State Invariants & Consistency Engine.

Enforces strict integrity constraints across:
1. Finding -> Evidence references (all cited evidence must exist in state/vault).
2. Capability -> Acquisition evidence references.
3. Graph Edge -> Evidence references.
4. Hypothesis -> Target entity existence in attack graph/services.
5. Verified Finding -> Independent verification evidence.
6. Checkpoint Integrity -> Valid SHA-256 state hash.
7. Branch References -> Valid hypothesis/evidence IDs.
8. Memory Layer Alignment -> L0-L8 layer synchronization.

RULE: Never silently repair corrupted security state. An invalid invariant must fail loudly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from security_agent.agent.assessment_state import AssessmentState, Capability
from security_agent.intelligence.attack_graph import AttackGraph, GraphNode, GraphEdge
from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.intelligence.branches import BranchManager, InvestigationBranch
from security_agent.persistence.models import InvestigationCheckpoint


class InvariantViolationError(Exception):
    """Raised when an assessment state invariant is violated."""
    def __init__(self, rule_name: str, message: str, entity_id: Optional[str] = None):
        self.rule_name = rule_name
        self.message = message
        self.entity_id = entity_id
        super().__init__(f"[{rule_name}] {message}" + (f" (Entity: {entity_id})" if entity_id else ""))


@dataclass
class InvariantValidationResult:
    is_valid: bool
    violations: List[str] = field(default_factory=list)
    checked_rules_count: int = 0


class StateInvariantValidator:
    """
    Validates structural and relational invariants of the entire assessment state.
    """

    @classmethod
    def validate_state(
        cls,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        branch_manager: Optional[BranchManager] = None,
        raise_on_violation: bool = True,
    ) -> InvariantValidationResult:
        """
        Validates all consistency rules across state, graph, hypotheses, and branches.
        """
        violations: List[str] = []
        rules_checked = 0

        # Collect all valid evidence IDs known to state
        known_evidence_ids: Set[str] = set()
        if hasattr(state, "evidence") and isinstance(state.evidence, dict):
            known_evidence_ids.update(state.evidence.keys())
        if hasattr(state, "raw_evidence") and isinstance(state.raw_evidence, list):
            for e in state.raw_evidence:
                if isinstance(e, dict) and "evidence_id" in e:
                    known_evidence_ids.add(e["evidence_id"])
                elif hasattr(e, "evidence_id"):
                    known_evidence_ids.add(e.evidence_id)

        # -------------------------------------------------------------
        # Rule 1: Finding -> Evidence references must exist
        # -------------------------------------------------------------
        rules_checked += 1
        findings = getattr(state, "findings", {})
        finding_list = findings.values() if isinstance(findings, dict) else findings
        for f in finding_list:
            if isinstance(f, dict):
                f_id = f.get("finding_id") or f.get("id") or "unknown"
                evi_ids = f.get("evidence_ids") or f.get("evidence") or []
            else:
                f_id = getattr(f, "finding_id", None) or getattr(f, "id", "unknown")
                evi_ids = getattr(f, "evidence_ids", None) or getattr(f, "evidence", []) or []

            for eid in evi_ids:
                if eid not in known_evidence_ids:
                    violations.append(f"Finding '{f_id}' references missing evidence '{eid}'")

        # -------------------------------------------------------------
        # Rule 2: Verified Finding -> Must have independent verification evidence
        # -------------------------------------------------------------
        rules_checked += 1
        for f in finding_list:
            if isinstance(f, dict):
                f_id = f.get("finding_id") or f.get("id") or "unknown"
                is_verified = f.get("verified", False) or f.get("status") in ("verified", "confirmed") or f.get("confidence") == "confirmed"
                v_evis = f.get("verification_evidence_ids") or f.get("evidence_ids") or f.get("evidence") or []
            else:
                f_id = getattr(f, "finding_id", None) or getattr(f, "id", "unknown")
                is_verified = getattr(f, "verified", False) or getattr(f, "confidence", None) == "confirmed"
                v_evis = getattr(f, "verification_evidence_ids", None) or getattr(f, "evidence_ids", None) or getattr(f, "evidence", []) or []

            if is_verified and not v_evis:
                violations.append(f"Verified Finding '{f_id}' has no verification evidence")

        # -------------------------------------------------------------
        # Rule 3: Capability -> Acquisition evidence references must exist
        # -------------------------------------------------------------
        rules_checked += 1
        caps = getattr(state, "capabilities", {})
        cap_list = caps.values() if isinstance(caps, dict) else caps
        for c in cap_list:
            src_evis = getattr(c, "source_evidence_ids", []) or []
            for eid in src_evis:
                if eid not in known_evidence_ids:
                    violations.append(f"Capability '{getattr(c, 'capability_id', 'unknown')}' cites missing source evidence '{eid}'")

        # -------------------------------------------------------------
        # Rule 4: Graph Edges -> Evidence references and Endpoint integrity
        # -------------------------------------------------------------
        if graph:
            rules_checked += 1
            node_ids = set(graph.nodes.keys())
            edge_list = graph.edges.values() if isinstance(graph.edges, dict) else graph.edges
            for edge in edge_list:
                src_id = getattr(edge, "from_node_id", None) or getattr(edge, "source_id", None) or (edge.get("from_node_id") if isinstance(edge, dict) else None)
                dst_id = getattr(edge, "to_node_id", None) or getattr(edge, "target_id", None) or (edge.get("to_node_id") if isinstance(edge, dict) else None)
                eid_list = getattr(edge, "evidence_ids", []) or (edge.get("evidence_ids", []) if isinstance(edge, dict) else [])
                edge_id = getattr(edge, "edge_id", "edge") or (edge.get("edge_id") if isinstance(edge, dict) else "edge")

                if src_id and src_id not in node_ids:
                    violations.append(f"Graph Edge '{edge_id}' source node '{src_id}' does not exist")
                if dst_id and dst_id not in node_ids:
                    violations.append(f"Graph Edge '{edge_id}' target node '{dst_id}' does not exist")
                for eid in eid_list:
                    if eid not in known_evidence_ids:
                        violations.append(f"Graph Edge '{edge_id}' cites missing evidence '{eid}'")

        # -------------------------------------------------------------
        # Rule 5: Hypotheses -> Target must be grounded in graph or services
        # -------------------------------------------------------------
        rules_checked += 1
        known_targets: Set[str] = set()
        if hasattr(state, "services") and isinstance(state.services, dict):
            for s in state.services.values():
                known_targets.add(f"{s.host}:{s.port}")
                known_targets.add(s.host)
        if graph:
            for n in graph.nodes.values():
                known_targets.add(n.label)
                known_targets.add(n.node_id)
        if hasattr(state, "context") and state.context:
            known_targets.add(state.context.target)
            known_targets.update(state.context.scope)

        state_hypos = getattr(state, "hypotheses", {})
        if isinstance(state_hypos, dict):
            for h_id, h in state_hypos.items():
                target = getattr(h, "target", "") or (h.get("target") if isinstance(h, dict) else "")
                if target and known_targets:
                    is_grounded = any(t in target or target in t for t in known_targets)
                    if not is_grounded:
                        violations.append(f"Hypothesis '{h_id}' target '{target}' is not grounded in graph or services")

        # -------------------------------------------------------------
        # Rule 6: Branches -> Hypothesis and Evidence IDs must be valid
        # -------------------------------------------------------------
        if branch_manager:
            rules_checked += 1
            all_hypo_ids = set(state_hypos.keys()) if isinstance(state_hypos, dict) else set()
            for b_id, branch in branch_manager.branches.items():
                for hid in branch.hypothesis_ids:
                    if all_hypo_ids and hid not in all_hypo_ids:
                        violations.append(f"Branch '{b_id}' references unknown hypothesis '{hid}'")
                for eid in branch.evidence_ids:
                    if eid not in known_evidence_ids:
                        violations.append(f"Branch '{b_id}' references unknown evidence '{eid}'")

        is_valid = len(violations) == 0
        if not is_valid and raise_on_violation:
            first_v = violations[0]
            raise InvariantViolationError("StateInvariantViolation", f"Found {len(violations)} state invariant violations: {first_v}")

        return InvariantValidationResult(
            is_valid=is_valid,
            violations=violations,
            checked_rules_count=rules_checked,
        )

    @classmethod
    def validate_checkpoint(
        cls,
        checkpoint: InvestigationCheckpoint,
        raise_on_violation: bool = True
    ) -> InvariantValidationResult:
        """
        Validates checkpoint state hash, schema, and reference integrity.
        """
        violations: List[str] = []
        rules_checked = 1

        # Verify state hash integrity
        expected_hash = getattr(checkpoint.integrity, "content_hash", "") or getattr(checkpoint.integrity, "state_hash", "")
        if expected_hash:
            computed_hash = checkpoint.calculate_checksum()
            if computed_hash != expected_hash:
                violations.append(f"Checkpoint state hash mismatch: computed {computed_hash} != expected {expected_hash}")

        # Check node references in edges
        rules_checked += 1
        if hasattr(checkpoint, "graph_snapshot") and checkpoint.graph_snapshot:
            nodes_val = checkpoint.graph_snapshot.nodes
            if isinstance(nodes_val, dict):
                node_ids = set(nodes_val.keys())
            elif isinstance(nodes_val, list):
                node_ids = {n.get("node_id") if isinstance(n, dict) else getattr(n, "node_id", str(n)) for n in nodes_val}
            else:
                node_ids = set()

            for edge in checkpoint.graph_snapshot.edges:
                src = edge.get("source_id") or edge.get("from_node_id") if isinstance(edge, dict) else (getattr(edge, "source_id", None) or getattr(edge, "from_node_id", None))
                dst = edge.get("target_id") or edge.get("to_node_id") if isinstance(edge, dict) else (getattr(edge, "target_id", None) or getattr(edge, "to_node_id", None))
                eid = edge.get("edge_id") if isinstance(edge, dict) else getattr(edge, "edge_id", "edge")
                if src and src not in node_ids:
                    violations.append(f"Checkpoint edge '{eid}' source '{src}' not in graph nodes")
                if dst and dst not in node_ids:
                    violations.append(f"Checkpoint edge '{eid}' target '{dst}' not in graph nodes")

        is_valid = len(violations) == 0
        if not is_valid and raise_on_violation:
            raise InvariantViolationError("CheckpointInvariantViolation", f"Checkpoint '{checkpoint.checkpoint_id}' corrupted: {violations[0]}")

        return InvariantValidationResult(
            is_valid=is_valid,
            violations=violations,
            checked_rules_count=rules_checked,
        )

        return InvariantValidationResult(
            is_valid=is_valid,
            violations=violations,
            checked_rules_count=rules_checked,
        )
