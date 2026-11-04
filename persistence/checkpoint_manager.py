"""
Phase 12 Atomic Checkpoint & Resume Manager.

Provides:
1. Atomic checkpoint serialization with integrity checksum verification.
2. Crash recovery and complete state reconstruction without duplicate entities.
3. Schema compatibility and corruption rejection.
"""

from __future__ import annotations

import os
import json
import time
import uuid
import tempfile
from pathlib import Path
from dataclasses import asdict
from typing import Dict, Any, List, Optional, Tuple

from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceRecord,
    Capability,
    CapabilityType,
    ObjectiveStatus,
    AssessmentPhase,
)
from state.session_store import SessionStore, Session, Cookie, BearerToken
from intelligence.attack_graph import AttackGraph, GraphNode, GraphEdge, NodeKind, NodeStatus, EdgeKind
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.decision import DecisionRecord, DecisionSource
from persistence.models import (
    InvestigationCheckpoint,
    InvestigationStatus,
    StateSnapshot,
    GraphSnapshot,
    HypothesisSnapshot,
    CapabilitySnapshot,
    SessionSnapshot,
    BranchSnapshot,
    BudgetSnapshot,
    CheckpointIntegrityMetadata,
)


class CheckpointCorruptionError(Exception):
    """Raised when a checkpoint file is missing, malformed, or fails hash verification."""
    pass


class CheckpointManager:
    """
    Manages atomic checkpoint persistence and state restoration.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path.home() / ".security-agent" / "checkpoints"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_checkpoint_path(self, checkpoint_id: str) -> Path:
        return self.storage_dir / f"{checkpoint_id}.json"

    def create_checkpoint(
        self,
        investigation_id: str,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        budget: Optional[BudgetSnapshot] = None,
        status: InvestigationStatus = InvestigationStatus.RUNNING,
        parent_checkpoint_id: Optional[str] = None,
        branches_data: Optional[Dict[str, Any]] = None,
    ) -> InvestigationCheckpoint:
        """
        Creates an atomic, integrity-validated checkpoint file.
        """
        checkpoint_id = f"chk-{uuid.uuid4().hex[:12]}"
        now = time.time()

        # 1. State Snapshot
        target = getattr(getattr(state, "context", None), "target", "127.0.0.1")
        scope = list(getattr(getattr(state, "context", None), "scope", [target]))
        current_phase = getattr(state, "current_phase", AssessmentPhase.INITIALIZING).value
        obj_status = getattr(state, "objective_status", ObjectiveStatus.OBJECTIVE_UNREACHED).value

        # Serialize services
        services_dict = {}
        for s_key, s in getattr(state, "services", {}).items():
            services_dict[s_key] = {
                "host": s.host,
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service,
                "version": s.version,
                "banner": s.banner,
                "evidence_ids": s.evidence_ids
            }

        # Serialize findings
        findings_serialized = []
        finding_items = getattr(state, "findings", [])
        if isinstance(finding_items, dict):
            finding_items = list(finding_items.values())
        for f in finding_items:
            if hasattr(f, "model_dump"):
                findings_serialized.append(f.model_dump(mode="json"))
            elif hasattr(f, "dict"):
                findings_serialized.append(f.dict())
            elif hasattr(f, "to_dict"):
                findings_serialized.append(f.to_dict())
            elif isinstance(f, dict):
                findings_serialized.append(f)
            elif hasattr(f, "__dataclass_fields__"):
                findings_serialized.append(asdict(f))
            else:
                findings_serialized.append(f)

        # Serialize hypotheses
        hypotheses_dict = {}
        for h_id, h in getattr(state, "hypotheses", {}).items():
            if hasattr(h, "to_dict"):
                hypotheses_dict[h_id] = h.to_dict()
            elif isinstance(h, dict):
                hypotheses_dict[h_id] = h
            elif hasattr(h, "__dataclass_fields__"):
                hypotheses_dict[h_id] = asdict(h)
            else:
                hypotheses_dict[h_id] = h

        state_snap = StateSnapshot(
            target=target,
            scope=scope,
            current_phase=current_phase,
            objective_status=obj_status,
            services=services_dict,
            http_endpoints=getattr(state, "http_endpoints", {}),
            forms=getattr(state, "forms", {}),
            dom_snapshots={},
            findings=findings_serialized,
            action_metadata_log=getattr(state, "action_metadata_log", []),
            decision_records=[asdict(d) if hasattr(d, "__dataclass_fields__") else d for d in getattr(state, "decision_records", [])],
            autonomy_mode=getattr(state, "autonomy_mode", "RAW_MODEL"),
            completion_mode=getattr(state, "completion_mode", "TARGETED"),
            hypotheses_considered=getattr(state, "hypotheses_considered", 0),
            hypotheses_selected=getattr(state, "hypotheses_selected", 0),
            hypotheses_refuted=getattr(state, "hypotheses_refuted", 0),
            hypotheses_reopened=getattr(state, "hypotheses_reopened", 0),
            evidence=dict(getattr(state, "evidence", {})),
            hypotheses=hypotheses_dict,
        )

        # 2. Graph Snapshot
        nodes_dict = {}
        edges_list = []
        if graph and hasattr(graph, "nodes"):
            for n_id, n in graph.nodes.items():
                nodes_dict[n_id] = {
                    "node_id": n.node_id,
                    "kind": n.kind.value if hasattr(n.kind, "value") else str(n.kind),
                    "label": n.label,
                    "status": n.status.value if hasattr(n.status, "value") else str(n.status),
                    "evidence_ids": n.evidence_ids,
                    "metadata": n.metadata
                }
            for e in getattr(graph, "edges", []):
                edges_list.append({
                    "edge_id": e.edge_id,
                    "from_node_id": e.from_node_id,
                    "to_node_id": e.to_node_id,
                    "kind": e.kind.value if hasattr(e.kind, "value") else str(e.kind),
                    "label": getattr(e, "label", ""),
                    "evidence_ids": getattr(e, "evidence_ids", []),
                    "metadata": e.metadata
                })
        graph_snap = GraphSnapshot(nodes=nodes_dict, edges=edges_list)

        # 3. Hypothesis Snapshot
        hyp_dict = {}
        refuted_list = []
        if hypothesis_engine:
            refuted_list = list(getattr(hypothesis_engine, "_refuted_hypotheses", set()))
        hypothesis_snap = HypothesisSnapshot(
            hypotheses=hyp_dict,
            refuted_ids=refuted_list,
            proposals_generated=getattr(hypothesis_engine, "_proposals_generated", 0) if hypothesis_engine else 0,
            proposals_executed=getattr(hypothesis_engine, "_proposals_executed", 0) if hypothesis_engine else 0,
        )

        # 4. Capability Snapshot
        caps_dict = {}
        for c_id, cap in getattr(state, "capabilities", {}).items():
            if isinstance(cap, dict):
                caps_dict[c_id] = {
                    "capability_id": cap.get("capability_id") or cap.get("name") or c_id,
                    "capability_type": str(cap.get("capability_type", "CLOUD_ACCESS")),
                    "target_scope": cap.get("target_scope", ""),
                    "source_evidence_ids": cap.get("source_evidence_ids", []),
                    "metadata": cap.get("metadata", {}),
                    "verified": cap.get("verified", True),
                }
            else:
                cap_type = getattr(cap, "capability_type", "CLOUD_ACCESS")
                if hasattr(cap_type, "value"):
                    cap_type = cap_type.value
                caps_dict[c_id] = {
                    "capability_id": getattr(cap, "capability_id", getattr(cap, "name", c_id)),
                    "capability_type": str(cap_type),
                    "target_scope": getattr(cap, "target_scope", ""),
                    "source_evidence_ids": getattr(cap, "source_evidence_ids", []),
                    "metadata": getattr(cap, "metadata", {}),
                    "verified": getattr(cap, "verified", True),
                }
        cap_snap = CapabilitySnapshot(capabilities=caps_dict)

        # 5. Session Snapshot
        sess_dict = {}
        active_sess = []
        if hasattr(state, "get_session_store"):
            store = state.get_session_store()
            for s_id, s in getattr(store, "sessions", {}).items():
                is_auth = s.is_authenticated() if callable(s.is_authenticated) else bool(s.is_authenticated)
                sess_dict[s_id] = {
                    "session_id": s.session_id,
                    "target_origin": s.target_origin,
                    "role": s.role,
                    "is_authenticated": is_auth,
                    "authentication_state": s.authentication_state.value if hasattr(s.authentication_state, "value") else str(s.authentication_state),
                    "cookies": {c_name: asdict(c) for c_name, c in s.cookies.items()},
                    "bearer_tokens": {t_name: asdict(t) for t_name, t in s.bearer_tokens.items()},
                    "csrf_tokens": {tok_name: asdict(tok) for tok_name, tok in s.csrf_tokens.items()},
                }
                if is_auth:
                    active_sess.append(s_id)
        sess_snap = SessionSnapshot(sessions=sess_dict, active_session_ids=active_sess)

        # 6. Branch Snapshot
        branch_snap = BranchSnapshot(
            branches=branches_data.get("branches", {}) if branches_data else {},
            active_branch_id=branches_data.get("active_branch_id") if branches_data else None
        )

        # 7. Budget Snapshot
        if not budget:
            budget = BudgetSnapshot(
                elapsed_seconds=0.0,
                max_seconds=3600.0,
                tool_calls_used=0,
                max_tool_calls=100,
                iterations_used=0,
                max_iterations=40
            )

        # 8. Checkpoint Integrity
        integrity = CheckpointIntegrityMetadata(
            schema_version="12.0.0",
            parent_checkpoint_id=parent_checkpoint_id,
            created_at=now
        )

        checkpoint = InvestigationCheckpoint(
            checkpoint_id=checkpoint_id,
            investigation_id=investigation_id,
            status=status,
            timestamp=now,
            state_version=getattr(state, "state_version", 1),
            objective=getattr(getattr(state, "context", None), "objective", "Assess target security"),
            scope=scope,
            current_phase=current_phase,
            objective_status=obj_status,
            state_snapshot=state_snap,
            graph_snapshot=graph_snap,
            hypothesis_snapshot=hypothesis_snap,
            capability_snapshot=cap_snap,
            session_snapshot=sess_snap,
            branch_snapshot=branch_snap,
            budget_snapshot=budget,
            integrity=integrity
        )

        # Calculate and set checksum
        integrity.content_hash = checkpoint.calculate_checksum()

        # Atomic commit: write to temp file then rename
        final_path = self._get_checkpoint_path(checkpoint_id)
        temp_fd, temp_path = tempfile.mkstemp(dir=str(self.storage_dir), prefix="chk_tmp_", suffix=".json")
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(asdict(checkpoint), f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, final_path)
        return checkpoint

    def restore_checkpoint(
        self,
        checkpoint_id: str
    ) -> Tuple[AssessmentState, AttackGraph, HypothesisEngine, SessionStore, BudgetSnapshot, InvestigationCheckpoint]:
        """
        Restores full logical state from checkpoint file after verifying integrity.
        """
        path = self._get_checkpoint_path(checkpoint_id)
        if not path.exists():
            raise CheckpointCorruptionError(f"Checkpoint {checkpoint_id} not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise CheckpointCorruptionError(f"Checkpoint {checkpoint_id} JSON is corrupt: {e}")

        # Check schema compatibility
        schema_ver = data.get("integrity", {}).get("schema_version")
        if not schema_ver or not schema_ver.startswith("12."):
            raise CheckpointCorruptionError(f"Incompatible checkpoint schema version: {schema_ver}")

        # Reconstruct typed structures
        state_data = data["state_snapshot"]
        graph_data = data["graph_snapshot"]
        hyp_data = data["hypothesis_snapshot"]
        cap_data = data["capability_snapshot"]
        sess_data = data["session_snapshot"]
        branch_data = data["branch_snapshot"]
        budget_data = data["budget_snapshot"]
        integ_data = data["integrity"]

        checkpoint = InvestigationCheckpoint(
            checkpoint_id=data["checkpoint_id"],
            investigation_id=data["investigation_id"],
            status=InvestigationStatus(data["status"]),
            timestamp=data["timestamp"],
            state_version=data["state_version"],
            objective=data["objective"],
            scope=data["scope"],
            current_phase=data["current_phase"],
            objective_status=data["objective_status"],
            state_snapshot=StateSnapshot(**state_data),
            graph_snapshot=GraphSnapshot(**graph_data),
            hypothesis_snapshot=HypothesisSnapshot(**hyp_data),
            capability_snapshot=CapabilitySnapshot(**cap_data),
            session_snapshot=SessionSnapshot(**sess_data),
            branch_snapshot=BranchSnapshot(**branch_data),
            budget_snapshot=BudgetSnapshot(**budget_data),
            integrity=CheckpointIntegrityMetadata(**integ_data),
        )

        # Verify checksum
        computed_hash = checkpoint.calculate_checksum()
        if computed_hash != checkpoint.integrity.content_hash:
            raise CheckpointCorruptionError(
                f"Checkpoint {checkpoint_id} hash mismatch! Expected {checkpoint.integrity.content_hash}, got {computed_hash}"
            )

        # 1. Reconstruct AssessmentState
        context = AssessmentContext(
            target=state_data["target"],
            scope=state_data["scope"],
            objective=data["objective"]
        )
        state = AssessmentState(context=context)
        state.current_phase = AssessmentPhase(state_data["current_phase"])
        state.objective_status = ObjectiveStatus(state_data["objective_status"])
        state.autonomy_mode = state_data.get("autonomy_mode", "RAW_MODEL")
        state.completion_mode = state_data.get("completion_mode", "TARGETED")
        state.hypotheses_considered = state_data.get("hypotheses_considered", 0)
        state.hypotheses_selected = state_data.get("hypotheses_selected", 0)
        state.hypotheses_refuted = state_data.get("hypotheses_refuted", 0)
        state.hypotheses_reopened = state_data.get("hypotheses_reopened", 0)
        state.findings = state_data.get("findings", [])
        state.http_endpoints = state_data.get("http_endpoints", {})
        state.forms = state_data.get("forms", {})
        state.evidence = state_data.get("evidence", {})

        # Restore hypotheses into state.hypotheses
        from agent.assessment_state import HypothesisStatus, VulnerabilityHypothesis
        for h_id, h_dict in state_data.get("hypotheses", {}).items():
            st_val = h_dict.get("status", "untested")
            try:
                st_enum = HypothesisStatus(st_val)
            except Exception:
                st_enum = HypothesisStatus.UNTESTED
            state.hypotheses[h_id] = VulnerabilityHypothesis(
                id=h_dict.get("id", h_id),
                target=h_dict.get("target", "127.0.0.1"),
                service=h_dict.get("service", "http"),
                port=h_dict.get("port", 80),
                vulnerability_type=h_dict.get("vulnerability_type", "unknown"),
                rationale=h_dict.get("rationale", ""),
                status=st_enum,
                evidence_ids=h_dict.get("evidence_ids", [])
            )

        # Restore services
        for s_key, s_dict in state_data.get("services", {}).items():
            state.services[s_key] = ServiceRecord(
                host=s_dict["host"],
                port=s_dict["port"],
                protocol=s_dict["protocol"],
                service=s_dict["service"],
                version=s_dict.get("version", "UNKNOWN"),
                banner=s_dict.get("banner", ""),
                evidence_ids=s_dict.get("evidence_ids", [])
            )

        # Restore capabilities
        for c_id, c_dict in cap_data.get("capabilities", {}).items():
            state.capabilities[c_id] = Capability(
                capability_id=c_dict["capability_id"],
                capability_type=CapabilityType(c_dict["capability_type"]),
                target_scope=c_dict["target_scope"],
                source_evidence_ids=c_dict.get("source_evidence_ids", []),
                metadata=c_dict.get("metadata", {}),
                verified=c_dict.get("verified", True)
            )

        # Restore decision records
        for d_dict in state_data.get("decision_records", []):
            state.decision_records.append(DecisionRecord(
                decision_id=d_dict.get("decision_id", f"DEC-{uuid.uuid4().hex[:8].upper()}"),
                iteration=d_dict["iteration"],
                source=DecisionSource(d_dict["source"]),
                selected_tool=d_dict["selected_tool"],
                target=d_dict["target"],
                arguments=d_dict.get("arguments", {}),
                hypothesis_id=d_dict.get("hypothesis_id"),
                candidate_id=d_dict.get("candidate_id"),
                evidence_ids=d_dict.get("evidence_ids", []),
                capability_context=d_dict.get("capability_context", []),
                confidence=d_dict.get("confidence", 1.0),
                override_reason=d_dict.get("override_reason", ""),
                timestamp=d_dict.get("timestamp", time.time())
            ))

        # 2. Reconstruct AttackGraph
        graph = AttackGraph()
        for n_id, n_dict in graph_data.get("nodes", {}).items():
            node = GraphNode(
                node_id=n_dict["node_id"],
                kind=NodeKind(n_dict["kind"]),
                label=n_dict["label"],
                status=NodeStatus(n_dict["status"]),
                evidence_ids=n_dict.get("evidence_ids", []),
                metadata=n_dict.get("metadata", {})
            )
            graph.nodes[n_id] = node
            graph._label_index[node.label] = n_id

        for e_dict in graph_data.get("edges", []):
            graph.edges.append(GraphEdge(
                edge_id=e_dict.get("edge_id", f"edge-{uuid.uuid4().hex[:8]}"),
                from_node_id=e_dict["from_node_id"],
                to_node_id=e_dict["to_node_id"],
                kind=EdgeKind(e_dict["kind"]),
                label=e_dict.get("label", ""),
                evidence_ids=e_dict.get("evidence_ids", []),
                metadata=e_dict.get("metadata", {})
            ))

        # 3. Reconstruct HypothesisEngine
        hyp_engine = HypothesisEngine()
        hyp_engine._refuted_hypotheses = set(hyp_data.get("refuted_ids", []))
        hyp_engine._proposals_generated = hyp_data.get("proposals_generated", 0)
        hyp_engine._proposals_executed = hyp_data.get("proposals_executed", 0)

        # 4. Reconstruct SessionStore
        from state.session_store import AuthenticationState, CSRFToken
        session_store = state.get_session_store()
        for s_id, s_dict in sess_data.get("sessions", {}).items():
            cookies = {c_name: Cookie(**c_data) for c_name, c_data in s_dict.get("cookies", {}).items()}
            tokens = {t_name: BearerToken(**t_data) for t_name, t_data in s_dict.get("bearer_tokens", {}).items()}
            csrf = {tok_name: CSRFToken(**tok_data) for tok_name, tok_data in s_dict.get("csrf_tokens", {}).items()}
            auth_st_val = s_dict.get("authentication_state")
            auth_st = AuthenticationState(auth_st_val) if auth_st_val else (AuthenticationState.AUTHENTICATED if s_dict.get("is_authenticated") else AuthenticationState.UNAUTHENTICATED)
            session = Session(
                session_id=s_dict["session_id"],
                target_origin=s_dict["target_origin"],
                role=s_dict.get("role", "default"),
                authentication_state=auth_st,
                cookies=cookies,
                bearer_tokens=tokens,
                csrf_tokens=csrf
            )
            session_store.sessions[s_id] = session

        # 5. Reconstruct Budget
        budget_obj = BudgetSnapshot(**budget_data)

        return state, graph, hyp_engine, session_store, budget_obj, checkpoint
