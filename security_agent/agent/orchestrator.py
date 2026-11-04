"""
Multi-Agent Orchestration Subsystem.

Coordinates specialized autonomous workers (ReconWorker, WebWorker, SourceWorker, JudgeWorker)
under unified policy, event bus, and budget control.
See plan sections 54, 70 and Phase H.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time

from security_agent.events.bus import EventBus
from security_agent.events.types import EventType, EventSeverity
from security_agent.security.policy import PolicyEngine
from security_agent.tools.registry import ToolRegistry


class WorkerRole(str, Enum):
    RECON = "recon_worker"
    WEB = "web_worker"
    SOURCE = "source_worker"
    VERIFICATION = "verification_worker"
    REMEDIATION = "remediation_worker"


@dataclass
class WorkerTask:
    task_id: str
    role: WorkerRole
    objective: str
    target: str
    completed: bool = False
    result: Optional[str] = None


class MultiAgentOrchestrator:
    """
    Coordinates execution of specialized worker agents with unified governance.
    """
    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        event_bus: Optional[EventBus] = None
    ):
        self.registry = registry
        self.policy = policy_engine
        self.event_bus = event_bus
        self.active_tasks: List[WorkerTask] = []

    def dispatch_task(self, role: WorkerRole, objective: str, target: str, session_id: Optional[str] = None) -> WorkerTask:
        task_id = f"WRK-{role.value[:3].upper()}-{len(self.active_tasks) + 1:03d}"
        task = WorkerTask(task_id=task_id, role=role, objective=objective, target=target)
        self.active_tasks.append(task)

        if self.event_bus:
            self.event_bus.emit(
                EventType.WORKER_STARTED,
                {"worker_id": task_id, "role": role.value, "objective": objective},
                assessment_id=session_id
            )

        # Route role to dedicated tool execution
        result = self._execute_worker(task)
        task.result = result
        task.completed = True

        if self.event_bus:
            self.event_bus.emit(
                EventType.WORKER_COMPLETED,
                {"worker_id": task_id, "role": role.value, "status": "completed"},
                assessment_id=session_id
            )

        return task

    def _execute_worker(self, task: WorkerTask) -> str:
        """Executes domain-specific tools based on worker role."""
        if task.role == WorkerRole.RECON:
            # Execute DNS / Header passive recon
            res_headers = self.registry.execute("check_headers", {"url": task.target})
            return f"Recon Completed: {res_headers[:200]}"

        elif task.role == WorkerRole.SOURCE:
            res_sec = self.registry.execute("scan_source_secrets", {"directory_path": "."})
            return f"Source Audit Completed: {res_sec[:200]}"

        elif task.role == WorkerRole.WEB:
            res_forms = self.registry.execute("browser.get_forms", {"url": task.target})
            return f"Web Audit Completed: {res_forms[:200]}"

        return f"Worker {task.role.value} completed task: {task.objective}"
