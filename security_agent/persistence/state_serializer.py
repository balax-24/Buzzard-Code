"""
Phase 18 Comprehensive State Serializer.
Handles bidirectional conversion of in-memory security assessment state into deterministic, inspectable JSON structures.
"""

from __future__ import annotations

import copy
import time
from typing import Any, Dict, List, Optional, Set

from security_agent.agent.assessment_state import (
    AssessmentContext,
    AssessmentPhase,
    AssessmentState,
    ObjectiveStatus,
    ServiceRecord,
    ServiceState,
)
from security_agent.intelligence.action_history import ActionHistoryRecord, ActionHistoryStore, ActionOutcome
from security_agent.intelligence.attack_graph import (
    AttackGraph,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    NodeStatus,
)
from security_agent.intelligence.branches import BranchManager, BranchPriority, BranchStatus, InvestigationBranch
from security_agent.intelligence.failure_memory import (
    FailureAwareMemory,
    FailureConditionType,
    FailureMemoryRecord,
)
from security_agent.persistence.integrity import StateIntegrity
from security_agent.persistence.migration import CURRENT_SCHEMA_VERSION, SchemaMigrator


class StateSerializer:
    """Serializes and deserializes the full ecosystem of assessment intelligence state."""

    @classmethod
    def serialize_state(
        cls,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        history: Optional[ActionHistoryStore] = None,
        failure_mem: Optional[FailureAwareMemory] = None,
        branch_mgr: Optional[BranchManager] = None,
        engagement_id: Optional[str] = None,
        budget_info: Optional[Dict[str, Any]] = None,
        attribution_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Serializes all objects into a single structured dictionary with integrity hash."""
        eng_id = engagement_id or getattr(state, "engagement_id", f"eng-{int(time.time())}")

        # 1. AssessmentState Core
        services_dict = {}
        for s_key, s_val in getattr(state, "services", {}).items():
            services_dict[s_key] = {
                "host": s_val.host,
                "port": s_val.port,
                "protocol": s_val.protocol,
                "state": s_val.state.value if hasattr(s_val.state, "value") else str(s_val.state),
                "service_name": s_val.service_name,
                "banner": s_val.banner,
                "version": s_val.version,
                "technologies": list(s_val.technologies) if hasattr(s_val, "technologies") else [],
                "endpoints": list(s_val.endpoints) if hasattr(s_val, "endpoints") else [],
                "first_seen": s_val.first_seen,
                "last_seen": s_val.last_seen,
                "evidence_ids": list(s_val.evidence_ids),
                "finding_ids": list(s_val.finding_ids),
            }

        evidence_dict = {}
        for e_id, e_rec in getattr(state, "evidence", {}).items():
            if isinstance(e_rec, dict):
                evidence_dict[e_id] = e_rec
            else:
                evidence_dict[e_id] = {
                    "evidence_id": getattr(e_rec, "evidence_id", e_id),
                    "source_tool": getattr(e_rec, "source_tool", "unknown"),
                    "target": getattr(e_rec, "target", ""),
                    "timestamp": getattr(e_rec, "timestamp", 0.0),
                    "category": getattr(e_rec, "category", "general"),
                    "raw_output": getattr(e_rec, "raw_output", getattr(e_rec, "raw_data", "")),
                    "structured_data": getattr(e_rec, "structured_data", {}),
                    "relevance_score": getattr(e_rec, "relevance_score", 1.0),
                    "contradicts": getattr(e_rec, "contradicts", []),
                    "corroborates": getattr(e_rec, "corroborates", []),
                }

        findings_dict = {}
        findings_src = getattr(state, "findings", {})
        if isinstance(findings_src, dict):
            for f_id, f_rec in findings_src.items():
                if isinstance(f_rec, dict):
                    findings_dict[f_id] = f_rec
                else:
                    findings_dict[f_id] = {
                        "finding_id": getattr(f_rec, "finding_id", f_id),
                        "title": getattr(f_rec, "title", ""),
                        "severity": str(getattr(f_rec, "severity", "HIGH")),
                        "category": getattr(f_rec, "category", "vuln"),
                        "target": getattr(f_rec, "target", ""),
                        "evidence_ids": list(getattr(f_rec, "evidence_ids", [])),
                        "verified": getattr(f_rec, "verified", False),
                    }
        elif isinstance(findings_src, list):
            for idx, f_rec in enumerate(findings_src):
                f_id = getattr(f_rec, "finding_id", f"find-{idx}")
                if isinstance(f_rec, dict):
                    findings_dict[f_id] = f_rec
                else:
                    findings_dict[f_id] = {
                        "finding_id": f_id,
                        "title": getattr(f_rec, "title", ""),
                        "severity": str(getattr(f_rec, "severity", "HIGH")),
                        "category": getattr(f_rec, "category", "vuln"),
                        "target": getattr(f_rec, "target", ""),
                        "evidence_ids": list(getattr(f_rec, "evidence_ids", [])),
                        "verified": getattr(f_rec, "verified", False),
                    }

        capabilities_dict = getattr(state, "capabilities", {})
        credentials_dict = getattr(state, "credentials", {})
        sessions_dict = getattr(state, "sessions", {})

        # 2. AttackGraph Serialization
        graph_dict = {"nodes": {}, "edges": []}
        if graph:
            for n_id, n_obj in graph.nodes.items():
                graph_dict["nodes"][n_id] = {
                    "node_id": n_obj.node_id,
                    "kind": n_obj.kind.value if hasattr(n_obj.kind, "value") else str(n_obj.kind),
                    "label": n_obj.label,
                    "status": n_obj.status.value if hasattr(n_obj.status, "value") else str(n_obj.status),
                    "evidence_ids": list(n_obj.evidence_ids),
                    "metadata": n_obj.metadata,
                }
            for e_obj in graph.edges:
                graph_dict["edges"].append({
                    "source_id": e_obj.source_id,
                    "target_id": e_obj.target_id,
                    "kind": e_obj.kind.value if hasattr(e_obj.kind, "value") else str(e_obj.kind),
                    "label": e_obj.label,
                    "evidence_ids": list(e_obj.evidence_ids),
                    "metadata": e_obj.metadata,
                })

        # 3. Action History Serialization
        history_list = []
        if history:
            for rec in history.records:
                history_list.append({
                    "action_id": rec.action_id,
                    "canonical_action_key": rec.canonical_action_key,
                    "tool_name": rec.tool_name,
                    "parameters": rec.parameters,
                    "target": rec.target,
                    "timestamp": rec.timestamp,
                    "expected_gain": rec.expected_gain,
                    "actual_gain": rec.actual_gain,
                    "cost": rec.cost,
                    "outcome": rec.outcome.value if hasattr(rec.outcome, "value") else str(rec.outcome),
                    "capability_context": rec.capability_context,
                    "why_this_action": rec.why_this_action,
                })

        # 4. Failure Memory Serialization
        failure_list = []
        if failure_mem:
            for k, f_rec in failure_mem.failure_records.items():
                failure_list.append({
                    "canonical_action_key": f_rec.canonical_action_key,
                    "target": f_rec.target,
                    "endpoint": f_rec.endpoint,
                    "condition_type": f_rec.condition_type.value if hasattr(f_rec.condition_type, "value") else str(f_rec.condition_type),
                    "failure_reason": f_rec.failure_reason,
                    "required_capabilities": list(f_rec.required_capabilities),
                    "required_evidence_types": list(f_rec.required_evidence_types),
                    "failed_at": f_rec.failed_at,
                    "unblocked": f_rec.unblocked,
                    "unblocked_reason": f_rec.unblocked_reason,
                })

        # 5. Branch Manager Serialization
        branches_dict = {}
        if branch_mgr:
            for b_id, b_obj in branch_mgr.branches.items():
                branches_dict[b_id] = {
                    "branch_id": b_obj.branch_id,
                    "name": b_obj.name,
                    "target": b_obj.target,
                    "status": b_obj.status.value if hasattr(b_obj.status, "value") else str(b_obj.status),
                    "priority": b_obj.priority.value if hasattr(b_obj.priority, "value") else str(b_obj.priority),
                    "hypothesis_ids": list(b_obj.hypothesis_ids),
                    "evidence_ids": list(b_obj.evidence_ids),
                    "capability_ids": list(b_obj.capability_ids),
                    "expected_gain_rating": b_obj.expected_gain_rating,
                    "tool_calls_allocated": b_obj.tool_calls_allocated,
                    "tool_calls_used": b_obj.tool_calls_used,
                    "total_gain": b_obj.total_gain,
                    "cost_incurred": b_obj.cost_incurred,
                    "turns_spent": getattr(b_obj, "turns_spent", 0),
                }

        payload = {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "engine_version": "1.0.0",
            "engagement_id": eng_id,
            "timestamp": time.time(),
            "assessment_state": {
                "target": state.context.target if hasattr(state, "context") else "",
                "scope": list(state.context.scope) if hasattr(state, "context") else [],
                "phase": state.current_phase.value if hasattr(state.current_phase, "value") else str(state.current_phase),
                "objective_status": state.objective_status.value if hasattr(state.objective_status, "value") else str(state.objective_status),
                "services": services_dict,
                "evidence": evidence_dict,
                "findings": findings_dict,
                "capabilities": capabilities_dict,
                "credentials": credentials_dict,
                "sessions": sessions_dict,
                "verification_success": getattr(state, "verification_success", False),
            },
            "attack_graph": graph_dict,
            "action_history": history_list,
            "failure_memory": failure_list,
            "branches": branches_dict,
            "budget": budget_info or {
                "iterations_used": 0,
                "max_iterations": 100,
                "tool_calls_used": 0,
                "max_tool_calls": 200,
                "cost_incurred": 0.0,
            },
            "model_attribution": attribution_info or {
                "selected_by_model": True,
                "selected_by_backend": False,
                "backend_fallback": False,
                "schema_repaired": False,
                "duplicate_blocked": False,
            },
        }

        # Add cryptographic hash
        content_hash = StateIntegrity.compute_hash(payload)
        payload["content_hash"] = content_hash
        return payload

    @classmethod
    def deserialize_state(
        cls,
        payload: Dict[str, Any],
        verify_hash: bool = True,
    ) -> Tuple[AssessmentState, AttackGraph, ActionHistoryStore, FailureAwareMemory, BranchManager]:
        """
        Deserializes structured dictionary into memory instances.
        Validates cryptographic integrity and schema migration if needed.
        """
        if verify_hash and "content_hash" in payload:
            expected_hash = payload["content_hash"]
            raw_copy = copy.deepcopy(payload)
            del raw_copy["content_hash"]
            is_valid, comp_hash = StateIntegrity.verify_integrity(raw_copy, expected_hash)
            if not is_valid:
                raise StateIntegrityError(f"State corruption detected! Expected hash {expected_hash}, computed {comp_hash}")

        # Migrate if needed
        data = SchemaMigrator.migrate_payload(payload)

        # 1. Rebuild AssessmentState
        ast_data = data.get("assessment_state", {})
        ctx = AssessmentContext(
            target=ast_data.get("target", ""),
            scope=ast_data.get("scope", []),
        )
        state = AssessmentState(context=ctx)
        state.current_phase = AssessmentPhase(ast_data.get("phase", AssessmentPhase.DISCOVERY.value))
        state.objective_status = ObjectiveStatus(ast_data.get("objective_status", ObjectiveStatus.OBJECTIVE_UNREACHED.value))
        state.verification_success = ast_data.get("verification_success", False)

        for s_key, s_val in ast_data.get("services", {}).items():
            rec = ServiceRecord(
                host=s_val["host"],
                port=s_val["port"],
                protocol=s_val.get("protocol", "tcp"),
                state=ServiceState(s_val.get("state", ServiceState.OPEN.value)),
                service_name=s_val.get("service_name", ""),
                banner=s_val.get("banner", ""),
                version=s_val.get("version", ""),
                technologies=set(s_val.get("technologies", [])),
                endpoints=set(s_val.get("endpoints", [])),
                first_seen=s_val.get("first_seen", 0.0),
                last_seen=s_val.get("last_seen", 0.0),
                evidence_ids=set(s_val.get("evidence_ids", [])),
                finding_ids=set(s_val.get("finding_ids", [])),
            )
            state.services[s_key] = rec

        for e_id, e_val in ast_data.get("evidence", {}).items():
            state.evidence[e_id] = e_val

        findings_src = ast_data.get("findings", {})
        if isinstance(findings_src, dict):
            for f_id, f_val in findings_src.items():
                if isinstance(state.findings, list):
                    state.findings.append(f_val)
                else:
                    state.findings[f_id] = f_val
        elif isinstance(findings_src, list):
            for f_val in findings_src:
                if isinstance(state.findings, list):
                    state.findings.append(f_val)
                else:
                    f_id = f_val.get("id", f_val.get("finding_id", "find-0"))
                    state.findings[f_id] = f_val

        state.capabilities = ast_data.get("capabilities", {})
        state.credentials = ast_data.get("credentials", {})
        state.sessions = ast_data.get("sessions", {})
        state.engagement_id = data.get("engagement_id", "")

        # 2. Rebuild AttackGraph
        graph = AttackGraph()
        graph_data = data.get("attack_graph", {})
        for n_id, n_val in graph_data.get("nodes", {}).items():
            node = GraphNode(
                node_id=n_val["node_id"],
                kind=NodeKind(n_val["kind"]),
                label=n_val["label"],
                status=NodeStatus(n_val["status"]),
                evidence_ids=set(n_val.get("evidence_ids", [])),
                metadata=n_val.get("metadata", {}),
            )
            graph.nodes[n_id] = node

        for e_val in graph_data.get("edges", []):
            edge = GraphEdge(
                source_id=e_val["source_id"],
                target_id=e_val["target_id"],
                kind=EdgeKind(e_val["kind"]),
                label=e_val.get("label", ""),
                evidence_ids=set(e_val.get("evidence_ids", [])),
                metadata=e_val.get("metadata", {}),
            )
            graph.edges.append(edge)

        # 3. Rebuild Action History
        history = ActionHistoryStore()
        for h_val in data.get("action_history", []):
            history.record_action(
                action_id=h_val["action_id"],
                tool_name=h_val["tool_name"],
                parameters=h_val.get("parameters", {}),
                target=h_val["target"],
                expected_gain=h_val.get("expected_gain", 0.0),
                actual_gain=h_val.get("actual_gain", 0.0),
                cost=h_val.get("cost", 1.0),
                outcome=ActionOutcome(h_val.get("outcome", ActionOutcome.SUCCESS.value)),
                capability_context=h_val.get("capability_context", "default"),
                why_this_action=h_val.get("why_this_action", ""),
            )

        # 4. Rebuild Failure Memory
        failure_mem = FailureAwareMemory()
        for f_val in data.get("failure_memory", []):
            rec = FailureMemoryRecord(
                canonical_action_key=f_val.get("canonical_action_key", ""),
                target=f_val.get("target", ""),
                endpoint=f_val.get("endpoint", ""),
                condition_type=FailureConditionType(f_val.get("condition_type", FailureConditionType.UNKNOWN_FAILURE.value)),
                failure_reason=f_val.get("failure_reason", ""),
                required_capabilities=set(f_val.get("required_capabilities", [])),
                required_evidence_types=set(f_val.get("required_evidence_types", [])),
                failed_at=f_val.get("failed_at", 0.0),
                unblocked=f_val.get("unblocked", False),
                unblocked_reason=f_val.get("unblocked_reason", ""),
            )
            failure_mem.failure_records[rec.canonical_action_key] = rec

        # 5. Rebuild Branch Manager
        branch_mgr = BranchManager()
        for b_id, b_val in data.get("branches", {}).items():
            branch = InvestigationBranch(
                branch_id=b_val["branch_id"],
                name=b_val["name"],
                target=b_val["target"],
                status=BranchStatus(b_val.get("status", BranchStatus.ACTIVE.value)),
                priority=BranchPriority(b_val.get("priority", BranchPriority.HIGH.value)),
                hypothesis_ids=b_val.get("hypothesis_ids", []),
                evidence_ids=b_val.get("evidence_ids", []),
                capability_ids=b_val.get("capability_ids", []),
                expected_gain_rating=b_val.get("expected_gain_rating", "HIGH"),
                tool_calls_allocated=b_val.get("tool_calls_allocated", 25),
                tool_calls_used=b_val.get("tool_calls_used", 0),
                total_gain=b_val.get("total_gain", 0.0),
                cost_incurred=b_val.get("cost_incurred", 0.0),
                turns_spent=b_val.get("turns_spent", 0),
            )
            branch_mgr.branches[b_id] = branch

        return state, graph, history, failure_mem, branch_mgr
