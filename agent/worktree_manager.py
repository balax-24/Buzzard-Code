"""
Git Worktree Manager for Buzzard Code Multi-Agent Swarm.

Provides isolated filesystem workspaces for concurrent subagents using `git worktree`.
Allows parallel agents to edit, build, and test independently without file locks,
dirty-working-tree collisions, or merge races.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentWorktree:
    agent_id: str
    branch_name: str
    worktree_path: Path
    is_git_worktree: bool


class WorktreeManager:
    """
    Manages lifecycle of isolated workspaces for parallel subagents.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.worktrees_root = self.workspace_root / ".buzzard" / "worktrees"
        self.worktrees_root.mkdir(parents=True, exist_ok=True)
        self.active_worktrees: Dict[str, AgentWorktree] = {}

    def _is_git_repo(self) -> bool:
        return (self.workspace_root / ".git").exists()

    def create_worktree(self, agent_id: Optional[str] = None) -> AgentWorktree:
        """
        Creates an isolated worktree for a subagent.
        """
        uid = agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        branch_name = f"buzzard/{uid}"
        target_path = self.worktrees_root / uid

        if self._is_git_repo():
            try:
                # Remove if stale dir exists
                if target_path.exists():
                    shutil.rmtree(target_path, ignore_errors=True)

                # git worktree add -b <branch> <path> HEAD
                cmd = ["git", "worktree", "add", "-b", branch_name, str(target_path), "HEAD"]
                res = subprocess.run(
                    cmd,
                    cwd=str(self.workspace_root),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if res.returncode == 0 and target_path.exists():
                    wt = AgentWorktree(
                        agent_id=uid,
                        branch_name=branch_name,
                        worktree_path=target_path,
                        is_git_worktree=True,
                    )
                    self.active_worktrees[uid] = wt
                    return wt
                else:
                    logger.warning("git worktree add failed: %s; falling back to clone", res.stderr)
            except Exception as e:
                logger.warning("Worktree creation exception: %s; falling back to clone", e)

        # Fallback: lightweight copy excluding heavy directories
        target_path.mkdir(parents=True, exist_ok=True)
        ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", ".buzzard"}

        for item in self.workspace_root.iterdir():
            if item.name in ignore_dirs:
                continue
            dest = target_path / item.name
            if item.is_dir():
                shutil.copytree(item, dest, ignore=shutil.ignore_patterns(*ignore_dirs))
            else:
                shutil.copy2(item, dest)

        wt = AgentWorktree(
            agent_id=uid,
            branch_name=branch_name,
            worktree_path=target_path,
            is_git_worktree=False,
        )
        self.active_worktrees[uid] = wt
        return wt

    def merge_worktree(self, agent_id: str) -> bool:
        """
        Merges completed changes from an agent's worktree back into the main working tree.
        """
        wt = self.active_worktrees.get(agent_id)
        if not wt:
            return False

        if wt.is_git_worktree and self._is_git_repo():
            try:
                # Commit any uncommitted changes in the worktree
                subprocess.run(["git", "add", "."], cwd=str(wt.worktree_path), capture_output=True, timeout=10)
                diff_check = subprocess.run(["git", "diff", "--staged", "--quiet"], cwd=str(wt.worktree_path), timeout=5)
                if diff_check.returncode != 0:
                    subprocess.run(
                        ["git", "commit", "-m", f"subagent {agent_id} completed work"],
                        cwd=str(wt.worktree_path),
                        capture_output=True,
                        timeout=10,
                    )

                # Merge back into main workspace branch
                res = subprocess.run(
                    ["git", "merge", "--no-ff", wt.branch_name, "-m", f"Merge subagent {agent_id}"],
                    cwd=str(self.workspace_root),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                return res.returncode == 0
            except Exception as e:
                logger.error("Failed to merge worktree %s: %e", agent_id, e)
                return False
        else:
            # File copy merge
            ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", ".buzzard"}
            for root, dirs, files in os.walk(str(wt.worktree_path)):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                rel_root = Path(root).relative_to(wt.worktree_path)
                for f in files:
                    src_f = Path(root) / f
                    dest_f = self.workspace_root / rel_root / f
                    dest_f.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_f, dest_f)
            return True

    def cleanup_worktree(self, agent_id: str) -> None:
        """Removes the worktree and cleans up temporary branches."""
        wt = self.active_worktrees.pop(agent_id, None)
        if not wt:
            return

        if wt.is_git_worktree and self._is_git_repo():
            try:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(wt.worktree_path)],
                    cwd=str(self.workspace_root),
                    capture_output=True,
                    timeout=20,
                )
                subprocess.run(
                    ["git", "branch", "-D", wt.branch_name],
                    cwd=str(self.workspace_root),
                    capture_output=True,
                    timeout=10,
                )
            except Exception as e:
                logger.warning("Error cleaning git worktree %s: %s", agent_id, e)

        if wt.worktree_path.exists():
            shutil.rmtree(wt.worktree_path, ignore_errors=True)

    def cleanup_all(self) -> None:
        for aid in list(self.active_worktrees.keys()):
            self.cleanup_worktree(aid)
