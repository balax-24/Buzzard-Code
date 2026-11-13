"""Private Git-ref checkpoints for coding workspaces."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any


_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_MAX_TURN = 100_000
_TIMEOUT_SECONDS = 30


class CheckpointError(ValueError):
    """A workspace checkpoint cannot be created or restored safely."""


def _git_environment(index_path: Path | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
        environment.pop(name, None)
    if index_path is not None:
        environment["GIT_INDEX_FILE"] = str(index_path)
    return environment


def _git(root: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    git_binary = shutil.which("git")
    if git_binary is None:
        raise CheckpointError("Git is required for workspace checkpoints.")
    try:
        result = subprocess.run(
            [git_binary, "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SECONDS,
            env=env if env is not None else _git_environment(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CheckpointError(f"Git checkpoint command failed: {error}") from error
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise CheckpointError(f"Git checkpoint command failed: {message}")
    return result.stdout.strip()


def _repository_root(workspace: str | Path) -> tuple[Path, Path]:
    supplied_root = Path(workspace).resolve(strict=True)
    if not supplied_root.is_dir():
        raise CheckpointError("Workspace must be an existing directory.")
    root = Path(_git(supplied_root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    git_directory = Path(_git(root, "rev-parse", "--absolute-git-dir")).resolve(strict=True)
    return root, git_directory


def _validate_session_turn(session_id: str, turn: int) -> None:
    if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
        raise CheckpointError("session_id must contain only letters, digits, '_' or '-' (up to 80 characters).")
    if not isinstance(turn, int) or isinstance(turn, bool) or not 0 <= turn <= _MAX_TURN:
        raise CheckpointError(f"turn must be an integer from 0 to {_MAX_TURN}.")


def _create_commit(root: Path, message: str) -> str:
    head = _git(root, "rev-parse", "--verify", "HEAD")
    with tempfile.TemporaryDirectory(prefix="buzzard-checkpoint-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        environment = _git_environment(index_path)
        _git(root, "read-tree", head, env=environment)
        _git(root, "add", "-A", "--", ".", env=environment)
        tree = _git(root, "write-tree", env=environment)
        commit_environment = _git_environment(index_path)
        commit_environment.update({
            "GIT_AUTHOR_NAME": "Buzzard Checkpoint",
            "GIT_AUTHOR_EMAIL": "checkpoint@localhost",
            "GIT_COMMITTER_NAME": "Buzzard Checkpoint",
            "GIT_COMMITTER_EMAIL": "checkpoint@localhost",
        })
        return _git(
            root,
            "-c",
            "commit.gpgsign=false",
            "commit-tree",
            tree,
            "-p",
            head,
            "-m",
            message,
            env=commit_environment,
        )


def create_workspace_checkpoint(
    workspace: str | Path,
    session_id: str,
    turn: int,
) -> str:
    """Snapshot the index and working tree into a private ref without touching HEAD or index."""
    _validate_session_turn(session_id, turn)
    root, _git_directory = _repository_root(workspace)
    commit = _create_commit(root, f"Buzzard checkpoint {session_id} turn {turn}")
    ref = f"refs/buzzard/checkpoints/{session_id}/turn-{turn:06d}"
    _git(root, "update-ref", ref, commit)
    return ref


def list_workspace_checkpoints(workspace: str | Path, session_id: str) -> list[dict[str, Any]]:
    """List the numbered snapshots for one task session."""
    _validate_session_turn(session_id, 0)
    root, _git_directory = _repository_root(workspace)
    prefix = f"refs/buzzard/checkpoints/{session_id}/"
    output = _git(root, "for-each-ref", "--format=%(refname)%09%(objectname)", prefix)
    checkpoints: list[dict[str, Any]] = []
    for line in output.splitlines():
        reference, separator, object_id = line.partition("\t")
        match = re.fullmatch(re.escape(prefix) + r"turn-(\d{6})", reference)
        if separator and match:
            checkpoints.append({"turn": int(match.group(1)), "ref": reference, "commit": object_id})
    return sorted(checkpoints, key=lambda checkpoint: checkpoint["turn"])


def _untracked_paths(root: Path) -> list[str]:
    output = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    return [path for path in output.split("\0") if path]


def _safe_workspace_path(root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute() or any(part in {"..", ""} for part in candidate.parts):
        raise CheckpointError(f"Git returned an unsafe workspace path: {relative_path!r}.")
    destination = root / candidate
    current = root
    for part in candidate.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise CheckpointError(f"Refusing a workspace path beneath symlink: {relative_path!r}.")
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise CheckpointError(f"Workspace path escapes the repository: {relative_path!r}.") from error
    return destination


def restore_workspace_checkpoint(workspace: str | Path, session_id: str, turn: int) -> dict[str, Any]:
    """Restore files and index from a task snapshot, keeping the current tree in a recovery ref."""
    _validate_session_turn(session_id, turn)
    root, _git_directory = _repository_root(workspace)
    ref = f"refs/buzzard/checkpoints/{session_id}/turn-{turn:06d}"
    try:
        commit = _git(root, "rev-parse", "--verify", ref)
    except CheckpointError as error:
        raise CheckpointError(f"No workspace checkpoint exists for task {session_id!r}, turn {turn}.") from error
    safety_ref = f"refs/buzzard/recovery/{session_id}/before-rewind-{uuid.uuid4().hex}"
    safety_commit = _create_commit(root, f"Buzzard recovery before rewind to turn {turn}")
    _git(root, "update-ref", safety_ref, safety_commit)

    # Untracked non-ignored files cannot be overwritten safely by read-tree. They are present
    # in the recovery commit and may also be present in the requested checkpoint.
    removed_count = 0
    try:
        for relative_path in _untracked_paths(root):
            path = _safe_workspace_path(root, relative_path)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise CheckpointError(f"Cannot safely rewind non-file untracked path: {relative_path!r}.")
            path.unlink()
            removed_count += 1

        _git(root, "read-tree", "--reset", "-u", commit)
    except Exception as error:
        # The safety ref contains every staged, unstaged and untracked file from before rewind.
        # Restore it if the requested tree cannot be applied.
        try:
            _git(root, "read-tree", "--reset", "-u", safety_commit)
        except CheckpointError as error:
            raise CheckpointError(
                f"Rewind failed and Git could not restore the safety snapshot {safety_ref}: {error}"
            ) from error
        if isinstance(error, CheckpointError):
            raise
        raise CheckpointError(f"Could not restore checkpoint turn {turn}: {error}") from error

    return {
        "turn": turn,
        "checkpoint_ref": ref,
        "recovery_ref": safety_ref,
        "recovered_untracked_files": removed_count,
        "message": (
            f"Restored workspace to turn {turn}. The branch was not moved; current files are preserved "
            f"in recovery ref {safety_ref}."
        ),
    }


def register_checkpoint_tools(registry: Any) -> None:
    """Register read-only checkpoint listing and approval-gated workspace rewind."""
    from tools.registry import ToolCategory

    def checkpoint_list(session_id: str = "") -> str:
        if not session_id:
            return "TOOL ERROR: checkpoint listing requires a task session."
        checkpoints = list_workspace_checkpoints(_workspace(), session_id)
        if not checkpoints:
            return "No workspace checkpoints exist for this task."
        return "Workspace checkpoints:\n" + "\n".join(
            f"- turn {item['turn']}: {item['ref']}" for item in checkpoints
        )

    def workspace_rewind(
        turn: int,
        session_id: str = "",
        conversation_messages: list[dict[str, Any]] | None = None,
        checkpoint_history: dict[int, list[dict[str, Any]]] | None = None,
        current_assistant_message: dict[str, Any] | None = None,
        tool_call_id: str = "",
    ) -> str:
        if not session_id:
            return "TOOL ERROR: workspace rewind requires a task session."
        if conversation_messages is None or checkpoint_history is None:
            return "TOOL ERROR: conversation rewind is only available during an active coding run."
        target_history = checkpoint_history.get(turn)
        if target_history is None:
            return f"TOOL ERROR: turn {turn} has no retained conversation snapshot in this run."

        pending_call: dict[str, Any] | None = None
        if current_assistant_message is not None:
            pending_call = deepcopy(current_assistant_message)
            calls = pending_call.get("tool_calls") or []
            if tool_call_id:
                pending_call["tool_calls"] = [call for call in calls if call.get("id") == tool_call_id]

        result = restore_workspace_checkpoint(_workspace(), session_id, turn)
        conversation_messages[:] = deepcopy(target_history)
        if pending_call is not None:
            conversation_messages.append(pending_call)
        for future_turn in [saved_turn for saved_turn in checkpoint_history if saved_turn > turn]:
            del checkpoint_history[future_turn]
        return result["message"]

    registry.register(
        name="checkpoint_list",
        description="Lists workspace snapshots created during this task. No arguments are required.",
        func=checkpoint_list,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15,
    )
    registry.register(
        name="workspace_rewind",
        description="Restores files and index to a prior checkpoint from this task. The current tree is saved under a private recovery ref first. Requires approval. Arguments: turn (int).",
        func=workspace_rewind,
        category=ToolCategory.AUTOMATION,
        risk_level="HIGH",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=60,
        schema={
            "type": "object",
            "properties": {"turn": {"type": "integer"}},
            "required": ["turn"],
        },
    )


def _workspace() -> str:
    from tools.filesystem import get_active_workspace

    return get_active_workspace()
