"""
Headless coding runs for CI and scripts (roadmap item F4): `buzzard exec "<task>"`.

There is no person to approve anything, so nothing is approved unless a flag allows it:
`--allow-edits` (file edits), `--allow-commands` (shell commands, which the completion gate needs
to run the tests) or `--yes` (everything, including MCP and git tools). Permission rules from the
user and project still apply first, and `--plan` keeps the run read-only. Every denied request is
listed in the output so a CI log shows exactly what was refused.

Exit codes: 0 completed, 1 failed or rejected by the gate, 2 invalid usage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.run_session import ALLOW, DENY, ApprovalRequest, RunOutcome, RunSession

EDIT_TOOLS = frozenset({
    "file_edit", "file.edit", "file_write", "file.write", "file_move", "multi_edit", "apply_patch", "workspace_rewind",
})
COMMAND_TOOLS = frozenset({
    "terminal.execute", "terminal_execute", "shell_execute", "process_start", "process_stop",
})


@dataclass
class HeadlessPolicy:
    allow_edits: bool = False
    allow_commands: bool = False
    allow_all: bool = False
    denied: List[Dict[str, Any]] = field(default_factory=list)

    def decide(self, request: ApprovalRequest) -> str:
        allowed = (
            self.allow_all
            or (self.allow_edits and request.tool_name in EDIT_TOOLS)
            or (self.allow_commands and request.tool_name in COMMAND_TOOLS)
        )
        if allowed:
            return ALLOW
        shown = {key: str(value)[:200] for key, value in request.arguments.items()}
        self.denied.append({"tool": request.tool_name, "arguments": shown})
        return DENY


def exit_code_for(outcome: RunOutcome) -> int:
    return 0 if outcome.status == "completed" and not outcome.error else 1


def run_headless(
    task: str,
    workspace: Path,
    policy: HeadlessPolicy,
    attempts: int = 1,
    plan: bool = False,
    model: Optional[str] = None,
    provider_factory: Optional[Any] = None,
    max_iterations: int = 25,
) -> Dict[str, Any]:
    """Runs one coding task without a UI and returns a JSON-ready result."""
    from core.config import load_merged_config
    from storage.db import StorageManager
    from tools.filesystem import set_active_workspace
    from tools.registry import create_authoritative_registry

    root = Path(set_active_workspace(str(workspace)))
    config = {**load_merged_config(), "workspace": str(root)}
    if provider_factory is not None:
        provider = provider_factory(config)
    else:
        from model.factory import get_model_provider
        provider = get_model_provider(model_name=model, config=config)
    session = RunSession(
        provider=provider, registry=create_authoritative_registry(), storage=StorageManager(),
        config=config, ask_approval=policy.decide, max_iterations=max_iterations,
    )
    session.plan_mode = plan
    outcome = session.run(task, target="localhost", scope=["localhost", "127.0.0.1"], attempts=attempts)
    return {
        "status": outcome.status,
        "exitCode": exit_code_for(outcome),
        "finalAnswer": outcome.final_answer,
        "error": outcome.error,
        "evidenceReport": outcome.evidence_report,
        "evidenceBundle": outcome.evidence_bundle,
        "approvals": {"granted": session.approvals_granted, "denied": session.approvals_denied},
        "deniedRequests": policy.denied,
        "model": str(getattr(provider, "model_name", "unknown")),
        "workspace": str(root),
    }


def render_text(result: Dict[str, Any]) -> str:
    lines = [f"Status: {result['status']}"]
    if result.get("finalAnswer"):
        lines += ["", result["finalAnswer"]]
    if result.get("evidenceReport"):
        lines += ["", result["evidenceReport"].replace("**", "")]
    if result.get("error"):
        lines += ["", f"Error: {result['error']}"]
    if result.get("deniedRequests"):
        lines += ["", "Refused (no approval flag allowed them):"]
        lines += [f"  - {item['tool']}: {json.dumps(item['arguments'])[:200]}" for item in result["deniedRequests"]]
    return "\n".join(lines)
