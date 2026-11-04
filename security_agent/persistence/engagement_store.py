"""
Phase 18 Persistent Engagement Store & Lifecycle Manager.
Supports atomic checkpointing, portable export/import, crash resilience, concurrency locking, and decision-relevant ResumeContextBuilder.
"""

from __future__ import annotations

import sys
if sys.platform == "win32":
    import msvcrt
    fcntl = None  # type: ignore
else:
    import fcntl
    msvcrt = None  # type: ignore
import json
import os
import shutil
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from security_agent.agent.assessment_state import AssessmentState
from security_agent.intelligence.action_history import ActionHistoryStore
from security_agent.intelligence.attack_graph import AttackGraph
from security_agent.intelligence.branches import BranchManager
from security_agent.intelligence.failure_memory import FailureAwareMemory
from security_agent.persistence.checkpoint import AtomicCheckpoint, CheckpointError
from security_agent.persistence.integrity import StateIntegrity, StateIntegrityError
from security_agent.persistence.migration import CURRENT_SCHEMA_VERSION, SchemaMigrator
from security_agent.persistence.state_serializer import StateSerializer


class EngagementStoreError(Exception):
    """Raised when engagement store operations fail."""
    pass


class EngagementLockError(EngagementStoreError):
    """Raised when concurrent writer access is detected or lock acquisition fails."""
    pass


@dataclass
class EngagementMetadata:
    engagement_id: str
    target_scope: List[str]
    created_at: float
    updated_at: float
    schema_version: str
    engine_version: str
    checkpoint_count: int = 0
    latest_content_hash: str = ""
    status: str = "ACTIVE"


class EngagementLock:
    """Provides non-blocking file-based concurrency locking for engagement workspaces."""

    def __init__(self, lock_file_path: Path):
        self.lock_file = lock_file_path
        self._fd: Optional[int] = None

    def acquire(self):
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(str(self.lock_file), os.O_CREAT | os.O_RDWR)
        try:
            if sys.platform == "win32":
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBRLCK, 1)
            else:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as e:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
            raise EngagementLockError(f"Cannot acquire lock on {self.lock_file}: another writer is active.") from e

    def release(self):
        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


class ResumeContextBuilder:
    """
    Builds a compact, decision-relevant context representation for LLM and controller
    without dumping redundant raw transcript history.
    """

    @classmethod
    def build_resume_context(
        cls,
        state: AssessmentState,
        graph: AttackGraph,
        branch_mgr: BranchManager,
        failure_mem: FailureAwareMemory,
        budget: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Constructs decision-critical payload for resumed agent turn."""
        frontier_nodes = []
        for n_id, n in graph.nodes.items():
            if n.status.value in ("DISCOVERED", "IN_PROGRESS"):
                frontier_nodes.append({"id": n_id, "kind": n.kind.value, "label": n.label})

        active_branches = []
        for b_id, b in branch_mgr.branches.items():
            if b.status.value == "ACTIVE":
                active_branches.append({"branch_id": b_id, "name": b.name, "target": b.target, "roi": b.roi})

        return {
            "engagement_id": getattr(state, "engagement_id", "default"),
            "target": state.context.target,
            "scope": list(state.context.scope),
            "phase": state.current_phase.value,
            "objective_status": state.objective_status.value,
            "active_capabilities": list(state.capabilities.keys()) if hasattr(state, "capabilities") else [],
            "credentials_available": list(state.credentials.keys()) if hasattr(state, "credentials") else [],
            "frontier_nodes": frontier_nodes,
            "active_branches": active_branches,
            "recent_failures_count": len(getattr(failure_mem, "failure_records", {})),
            "budget_remaining": {
                "iterations_left": max(0, budget.get("max_iterations", 100) - budget.get("iterations_used", 0)),
                "tool_calls_left": max(0, budget.get("max_tool_calls", 200) - budget.get("tool_calls_used", 0)),
            },
        }


class EngagementStore:
    """High-level persistent engagement store managing workspaces, checkpoints, and archives."""

    def __init__(self, base_dir: str | Path = "data/engagements"):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_eng_dir(self, engagement_id: str) -> Path:
        return self.base_dir / engagement_id

    def list_engagements(self) -> List[EngagementMetadata]:
        """Lists all registered persistent engagements."""
        results = []
        for child in self.base_dir.iterdir():
            if child.is_dir():
                meta_file = child / "manifest.json"
                if meta_file.exists():
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            results.append(
                                EngagementMetadata(
                                    engagement_id=data.get("engagement_id", child.name),
                                    target_scope=data.get("target_scope", []),
                                    created_at=data.get("created_at", 0.0),
                                    updated_at=data.get("updated_at", 0.0),
                                    schema_version=data.get("schema_version", CURRENT_SCHEMA_VERSION),
                                    engine_version=data.get("engine_version", "1.0.0"),
                                    checkpoint_count=data.get("checkpoint_count", 0),
                                    latest_content_hash=data.get("latest_content_hash", ""),
                                    status=data.get("status", "ACTIVE"),
                                )
                            )
                    except Exception:
                        pass
        return sorted(results, key=lambda x: x.updated_at, reverse=True)

    def checkpoint(
        self,
        engagement_id: str,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        history: Optional[ActionHistoryStore] = None,
        failure_mem: Optional[FailureAwareMemory] = None,
        branch_mgr: Optional[BranchManager] = None,
        budget_info: Optional[Dict[str, Any]] = None,
        attribution_info: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """
        Creates an atomic checkpoint for the engagement.
        Returns: (checkpoint_path, content_hash)
        """
        eng_dir = self._get_eng_dir(engagement_id)
        eng_dir.mkdir(parents=True, exist_ok=True)

        lock = EngagementLock(eng_dir / ".lock")
        lock.acquire()
        try:
            payload = StateSerializer.serialize_state(
                state=state,
                graph=graph,
                history=history,
                failure_mem=failure_mem,
                branch_mgr=branch_mgr,
                engagement_id=engagement_id,
                budget_info=budget_info,
                attribution_info=attribution_info,
            )

            # 1. Save numbered checkpoint file
            chk_dir = eng_dir / "checkpoints"
            chk_dir.mkdir(parents=True, exist_ok=True)
            existing_count = len(list(chk_dir.glob("checkpoint_*.json")))
            chk_idx = existing_count + 1
            chk_file = chk_dir / f"checkpoint_{chk_idx:04d}.json"
            final_path, content_hash = AtomicCheckpoint.write_atomic(chk_file, payload)

            # 2. Update latest.json
            latest_file = eng_dir / "latest.json"
            AtomicCheckpoint.write_atomic(latest_file, payload)

            # 3. Update manifest.json
            manifest_file = eng_dir / "manifest.json"
            manifest_data = {
                "engagement_id": engagement_id,
                "target_scope": list(state.context.scope) if hasattr(state, "context") else [],
                "created_at": getattr(state, "created_at", time.time()),
                "updated_at": time.time(),
                "schema_version": CURRENT_SCHEMA_VERSION,
                "engine_version": "1.0.0",
                "checkpoint_count": chk_idx,
                "latest_content_hash": content_hash,
                "status": "ACTIVE",
            }
            AtomicCheckpoint.write_atomic(manifest_file, manifest_data)

            return (final_path, content_hash)
        finally:
            lock.release()

    def load(
        self,
        engagement_id: str,
        checkpoint_num: Optional[int] = None,
        verify_hash: bool = True,
    ) -> Tuple[AssessmentState, AttackGraph, ActionHistoryStore, FailureAwareMemory, BranchManager, Dict[str, Any]]:
        """
        Loads engagement state from latest.json or a specific checkpoint.
        Returns: (state, graph, history, failure_mem, branch_mgr, raw_payload)
        """
        eng_dir = self._get_eng_dir(engagement_id)
        if not eng_dir.exists():
            raise EngagementStoreError(f"Engagement {engagement_id} does not exist.")

        if checkpoint_num is not None:
            chk_file = eng_dir / "checkpoints" / f"checkpoint_{checkpoint_num:04d}.json"
        else:
            chk_file = eng_dir / "latest.json"

        if not chk_file.exists():
            raise EngagementStoreError(f"Checkpoint file {chk_file} not found.")

        payload = AtomicCheckpoint.read_checkpoint(chk_file, verify_integrity=verify_hash)
        state, graph, history, failure_mem, branch_mgr = StateSerializer.deserialize_state(payload, verify_hash=verify_hash)
        return state, graph, history, failure_mem, branch_mgr, payload

    def delete_engagement(self, engagement_id: str) -> bool:
        """Deletes engagement directory safely."""
        eng_dir = self._get_eng_dir(engagement_id)
        if eng_dir.exists():
            shutil.rmtree(eng_dir)
            return True
        return False

    def export_engagement(
        self,
        engagement_id: str,
        export_zip_path: str | Path,
    ) -> str:
        """
        Exports full engagement workspace to a portable zip archive containing:
          - manifest.json
          - state.json
          - graph.json
          - evidence.json
          - findings.json
          - actions.json
          - credentials.json
          - sessions.json
          - integrity.json
        """
        eng_dir = self._get_eng_dir(engagement_id)
        latest_file = eng_dir / "latest.json"
        if not latest_file.exists():
            raise EngagementStoreError(f"Engagement {engagement_id} has no checkpoints to export.")

        payload = AtomicCheckpoint.read_checkpoint(latest_file, verify_integrity=True)
        dest_zip = Path(export_zip_path).resolve()
        dest_zip.parent.mkdir(parents=True, exist_ok=True)

        # Decompose into inspectable modular components
        ast_data = payload.get("assessment_state", {})
        components = {
            "manifest.json": {
                "engagement_id": engagement_id,
                "schema_version": payload.get("schema_version", CURRENT_SCHEMA_VERSION),
                "engine_version": payload.get("engine_version", "1.0.0"),
                "timestamp": payload.get("timestamp", time.time()),
            },
            "state.json": {
                "target": ast_data.get("target"),
                "scope": ast_data.get("scope"),
                "phase": ast_data.get("phase"),
                "objective_status": ast_data.get("objective_status"),
                "verification_success": ast_data.get("verification_success"),
            },
            "graph.json": payload.get("attack_graph", {}),
            "evidence.json": ast_data.get("evidence", {}),
            "findings.json": ast_data.get("findings", {}),
            "actions.json": payload.get("action_history", []),
            "credentials.json": ast_data.get("credentials", {}),
            "sessions.json": ast_data.get("sessions", {}),
            "branches.json": payload.get("branches", {}),
            "budget.json": payload.get("budget", {}),
        }

        # Calculate modular file hashes
        file_hashes = {}
        for fname, fcontent in components.items():
            file_hashes[fname] = StateIntegrity.compute_hash(fcontent)

        integrity_manifest = {
            "content_hash": payload.get("content_hash", ""),
            "component_hashes": file_hashes,
        }
        components["integrity.json"] = integrity_manifest

        with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for fname, fcontent in components.items():
                zf.writestr(fname, json.dumps(fcontent, indent=2, sort_keys=True))

        return str(dest_zip)

    def import_engagement(
        self,
        import_zip_path: str | Path,
        override_engagement_id: Optional[str] = None,
    ) -> str:
        """
        Imports a portable engagement zip archive, verifies modular SHA-256 hashes,
        and constructs local engagement directory.
        """
        src_zip = Path(import_zip_path).resolve()
        if not src_zip.exists():
            raise EngagementStoreError(f"Import file {src_zip} does not exist.")

        with zipfile.ZipFile(src_zip, "r") as zf:
            names = set(zf.namelist())
            if "integrity.json" not in names or "manifest.json" not in names:
                raise EngagementStoreError("Corrupted archive: missing manifest.json or integrity.json")

            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            integrity = json.loads(zf.read("integrity.json").decode("utf-8"))
            component_hashes = integrity.get("component_hashes", {})

            # Verify component hashes
            for fname, exp_h in component_hashes.items():
                if fname in names:
                    raw_bytes = zf.read(fname)
                    parsed = json.loads(raw_bytes.decode("utf-8"))
                    computed_h = StateIntegrity.compute_hash(parsed)
                    if computed_h != exp_h:
                        raise StateIntegrityError(f"Tampered component {fname} detected during import! Expected {exp_h}, got {computed_h}")

            eng_id = override_engagement_id or manifest.get("engagement_id", f"imported-eng-{int(time.time())}")
            eng_dir = self._get_eng_dir(eng_id)
            eng_dir.mkdir(parents=True, exist_ok=True)

            # Recombine payload
            state_d = json.loads(zf.read("state.json").decode("utf-8"))
            graph_d = json.loads(zf.read("graph.json").decode("utf-8"))
            evi_d = json.loads(zf.read("evidence.json").decode("utf-8"))
            find_d = json.loads(zf.read("findings.json").decode("utf-8"))
            act_d = json.loads(zf.read("actions.json").decode("utf-8"))
            cred_d = json.loads(zf.read("credentials.json").decode("utf-8"))
            sess_d = json.loads(zf.read("sessions.json").decode("utf-8"))
            branch_d = json.loads(zf.read("branches.json").decode("utf-8")) if "branches.json" in names else {}
            budget_d = json.loads(zf.read("budget.json").decode("utf-8")) if "budget.json" in names else {}

            rebuilt_ast = dict(state_d)
            rebuilt_ast["evidence"] = evi_d
            rebuilt_ast["findings"] = find_d
            rebuilt_ast["credentials"] = cred_d
            rebuilt_ast["sessions"] = sess_d
            rebuilt_ast["capabilities"] = {}

            payload = {
                "schema_version": manifest.get("schema_version", CURRENT_SCHEMA_VERSION),
                "engine_version": manifest.get("engine_version", "1.0.0"),
                "engagement_id": eng_id,
                "timestamp": manifest.get("timestamp", time.time()),
                "assessment_state": rebuilt_ast,
                "attack_graph": graph_d,
                "action_history": act_d,
                "failure_memory": [],
                "branches": branch_d,
                "budget": budget_d,
            }

            latest_file = eng_dir / "latest.json"
            final_path, content_hash = AtomicCheckpoint.write_atomic(latest_file, payload)

            manifest_file = eng_dir / "manifest.json"
            AtomicCheckpoint.write_atomic(manifest_file, {
                "engagement_id": eng_id,
                "target_scope": state_d.get("scope", []),
                "created_at": time.time(),
                "updated_at": time.time(),
                "schema_version": manifest.get("schema_version", CURRENT_SCHEMA_VERSION),
                "engine_version": "1.0.0",
                "checkpoint_count": 1,
                "latest_content_hash": content_hash,
                "status": "ACTIVE",
            })

            return eng_id
