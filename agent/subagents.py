"""
Subagents for Buzzard Code: focused helpers with limited permissions.

The main coding agent calls delegate_task(role, task). A child AgentLoop then works on that
task alone and returns a short report. Roles:

- explore: reads code and git history to answer a question. Read-only.
- review:  reads the diff and code to find problems. Read-only.
- test:    reads code and runs commands, such as the test suite. Cannot edit files.
- code:    reads and edits files. Cannot run commands or touch git.

Permissions are enforced by code, not by the prompt: the child loop is given a registry that
contains only its role's tools, so any other tool call fails as unknown. Commands and edits
still ask the user for approval, plan mode still refuses them, and the user's Esc stops the
child too. A subagent cannot start another subagent, and its work does not count as
verified: the main agent's completion gate still runs the tests at the end.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional

from tools.registry import ToolCategory, ToolRegistry

logger = logging.getLogger(__name__)

READ_TOOLS: FrozenSet[str] = frozenset({
    "directory_list", "file_search", "file_read", "file_view",
    "code_symbols", "code_references", "code_related", "related_tests",
    "lsp_definition", "lsp_references", "lsp_diagnostics",
    "git_status", "git_diff", "git_log",
})
MAX_TASK_CHARS = 4000
MAX_REPORT_CHARS = 6000
SUBAGENT_MAX_ITERATIONS = 12


@dataclass(frozen=True)
class SubagentRole:
    name: str
    summary: str
    tools: FrozenSet[str]
    instructions: str


ROLES: Dict[str, SubagentRole] = {
    "explore": SubagentRole(
        "explore", "read-only investigation of code and history", READ_TOOLS,
        "Investigate and answer the question. You cannot change files or run commands. "
        "Report the relevant files, symbols and line numbers, and what you concluded.",
    ),
    "review": SubagentRole(
        "review", "read-only review of the current changes", READ_TOOLS,
        "Review the current uncommitted changes (start with git_diff). You cannot change files. "
        "Report concrete bugs, missing tests and risks, each with file and line, most serious first. "
        "Say plainly if you found nothing.",
    ),
    "test": SubagentRole(
        "test", "runs tests and commands; cannot edit files", READ_TOOLS | {"terminal.execute"},
        "Run the commands needed to answer the task, such as the test suite. You cannot edit files. "
        "Report each command you ran, its exit code, and the failures with their causes.",
    ),
    "code": SubagentRole(
        "code", "edits files; cannot run commands or use git", READ_TOOLS | {"file_edit", "file_write", "todo_write"},
        "Make the requested change with minimal, surgical edits. You cannot run commands, so do "
        "not claim tests pass. Report each file you changed and why.",
    ),
}

_state_lock = threading.Lock()
_parent: Optional[Any] = None
_child_running = False


def set_parent_loop(loop: Optional[Any]) -> None:
    """Called by AgentLoop.run so delegate_task can reach the running main agent."""
    global _parent
    with _state_lock:
        _parent = loop


def build_role_registry(source: ToolRegistry, role: SubagentRole) -> ToolRegistry:
    """A registry holding only the role's tools, so nothing else can be dispatched."""
    registry = ToolRegistry()
    for name in role.tools:
        for candidate in (name, source.TOOL_ALIASES.get(name, name)):
            definition = source.definitions.get(candidate)
            if definition is not None:
                registry.register_definition(definition)
    return registry


def _report(result: Dict[str, Any], role: str, model: Optional[str] = None) -> str:
    messages = result.get("messages", []) if isinstance(result, dict) else []
    used: List[str] = []
    for message in messages:
        for call in message.get("tool_calls") or []:
            name = (call.get("function") or {}).get("name")
            if name and name not in used:
                used.append(name)
    answers = [str(m.get("content") or "") for m in messages if m.get("role") == "assistant"]
    final = next((text for text in reversed(answers) if text.strip()), "(the subagent gave no report)")
    status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
    header = f"[Subagent '{role}' finished: {status}. Tools used: {', '.join(used) or 'none'}.{f' Model: {model}.' if model else ''} Its work is not verified until the completion gate runs.]"
    return f"{header}\n{final}"[:MAX_REPORT_CHARS]


def delegate_task(role: str, task: str) -> str:
    """
    Hands a focused task to a subagent with limited permissions and returns its report.
    Arguments:
        role: explore, review, test or code.
        task: What the subagent should do, with the files or context it needs.
    """
    global _child_running
    role_name = str(role or "").strip().lower()
    task_text = str(task or "").strip()
    if role_name not in ROLES:
        return f"Error: role must be one of {', '.join(ROLES)}."
    if not task_text:
        return "Error: describe the task for the subagent."
    if len(task_text) > MAX_TASK_CHARS:
        return f"Error: keep the task under {MAX_TASK_CHARS} characters."
    with _state_lock:
        parent = _parent
        if parent is None:
            return "Error: subagents are only available while the main agent is running a task."
        if _child_running:
            return "Error: a subagent cannot start another subagent."
        _child_running = True
    try:
        if parent.stop_event.is_set():
            return "Error: the task was stopped."
        child = _make_child(parent, ROLES[role_name])
        goal = f"[{role_name} subagent] {ROLES[role_name].instructions}\n\nTask: {task_text}"
        result = child.run(task_goal=goal, target=parent.run_target or "workspace", scope=parent.run_scope)
        report = _report(result, role_name, str(getattr(child.provider, "model_name", "")) or None)
        if child.last_error:
            report += f"\n[Subagent error: {child.last_error}]"
        return report
    except Exception as error:  # a broken child must not take the main agent down with it
        logger.exception("Subagent '%s' failed", role_name)
        return f"Error: the {role_name} subagent failed: {error}"
    finally:
        with _state_lock:
            _child_running = False


_routed_providers: Dict[str, Any] = {}


def subagent_model_spec(config: Dict[str, Any]) -> Optional[str]:
    """The `subagent_model` setting ("provider/model" or a model name), if any."""
    model = config.get("model")
    spec = model.get("subagent") if isinstance(model, dict) else None
    spec = spec or config.get("subagent_model")
    return spec.strip() if isinstance(spec, str) and spec.strip() else None


def subagent_provider(parent: Any) -> Any:
    """
    Model routing (roadmap F5): subagents use `subagent_model` when it is set, so a cheaper model can
    do the reading-heavy work. Falls back to the main model if the routed one cannot be created.
    """
    spec = subagent_model_spec(parent.config)
    if spec is None:
        return parent.provider
    if spec in _routed_providers:
        return _routed_providers[spec]
    try:
        from model.factory import get_model_provider, resolve_provider_and_model

        provider_name, model_name = resolve_provider_and_model(spec, parent.config)
        main = parent.config.get("model") if isinstance(parent.config.get("model"), dict) else {}
        routed_model = {"provider": provider_name, "name": model_name}
        if str(main.get("provider", "")).lower() == provider_name and main.get("endpoint"):
            routed_model["endpoint"] = main["endpoint"]  # never send one provider's endpoint to another
        provider = get_model_provider(provider_name=provider_name, model_name=model_name,
                                      config={**parent.config, "model": routed_model})
    except Exception as error:  # a bad routing setting must not break subagents
        logger.warning("Could not use subagent model %r, using the main model: %s", spec, error)
        return parent.provider
    _routed_providers[spec] = provider
    return provider


def _make_child(parent: Any, role: SubagentRole) -> Any:
    from agent.loop import AgentLoop

    child = AgentLoop(
        provider=subagent_provider(parent),
        registry=build_role_registry(parent.registry, role),
        storage_manager=parent.storage,
        max_iterations=SUBAGENT_MAX_ITERATIONS,
        config={**parent.config, "subagent_role": role.name},
        approval_callback=parent.approval_callback,
        stop_event=parent.stop_event,
        quiet=True,
    )
    child.ui_active = parent.ui_active
    child.embedded_ui = getattr(parent, "embedded_ui", False)
    return child


def role_tool_names(role_name: str) -> FrozenSet[str]:
    return ROLES[role_name].tools


def register_subagent_tools(registry: ToolRegistry) -> None:
    roles = "; ".join(f"{role.name}: {role.summary}" for role in ROLES.values())
    registry.register(
        name="delegate_task",
        description=(
            "Hands a focused task to a subagent with limited permissions and returns its report. "
            f"Roles: {roles}. Arguments: role (str), task (str)."
        ),
        func=delegate_task,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=1800,
    )
