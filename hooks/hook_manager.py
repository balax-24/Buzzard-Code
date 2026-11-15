"""
Hook Execution Engine for Buzzard Code.

Phase 5: Pre-commit, post-edit, and lifecycle hooks system.
Discovers and executes hook scripts in `.buzzard/hooks/`:
- `pre-edit`: Validates before files are touched.
- `post-edit`: Runs formatting or linting on modified files.
- `pre-commit`: Gate check before staging or committing changes.
- `post-verify`: Actions after verification evidence is gathered.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HookResult:
    hook_name: str
    executed: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.executed and self.exit_code == 0 and not self.error


class HookManager:
    """
    Manages and executes lifecycle hooks located in `.buzzard/hooks/`.
    """

    SUPPORTED_HOOKS = {"pre-edit", "post-edit", "pre-commit", "post-verify"}

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.hooks_dir = self.workspace_root / ".buzzard" / "hooks"
        self.hooks_dir.mkdir(parents=True, exist_ok=True)

    def get_hook_script(self, hook_name: str) -> Optional[Path]:
        """Finds executable hook script by name (.sh, .py, .bat, or extensionless)."""
        if hook_name not in self.SUPPORTED_HOOKS:
            return None

        candidates = [
            self.hooks_dir / hook_name,
            self.hooks_dir / f"{hook_name}.sh",
            self.hooks_dir / f"{hook_name}.py",
            self.hooks_dir / f"{hook_name}.cmd",
            self.hooks_dir / f"{hook_name}.bat",
        ]
        for c in candidates:
            if c.exists() and c.is_file():
                return c
        return None

    def register_hook(self, hook_name: str, script_content: str, is_python: bool = False) -> Path:
        """Helper to create a hook script programmatically."""
        ext = ".py" if is_python else (".cmd" if os.name == "nt" else ".sh")
        target = self.hooks_dir / f"{hook_name}{ext}"
        target.write_text(script_content, encoding="utf-8")
        try:
            target.chmod(0o755)
        except Exception:
            pass
        return target

    def run_hook(self, hook_name: str, target_files: Optional[List[str]] = None, timeout_seconds: int = 30) -> HookResult:
        """
        Executes the requested hook if present.
        Returns HookResult with execution details.
        """
        script = self.get_hook_script(hook_name)
        if not script:
            return HookResult(hook_name=hook_name, executed=False)

        cmd: List[str] = []
        if script.suffix == ".py":
            cmd = [sys.executable, str(script)]
        elif script.suffix in (".sh", "") and os.name != "nt":
            cmd = ["bash", str(script)]
        else:
            cmd = [str(script)]

        if target_files:
            cmd.extend(target_files)

        env = dict(os.environ)
        env["BUZZARD_WORKSPACE"] = str(self.workspace_root)
        env["BUZZARD_HOOK"] = hook_name
        if target_files:
            env["BUZZARD_TARGET_FILES"] = ",".join(target_files)

        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.workspace_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            return HookResult(
                hook_name=hook_name,
                executed=True,
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
            )
        except subprocess.TimeoutExpired:
            return HookResult(
                hook_name=hook_name,
                executed=True,
                exit_code=-1,
                error=f"Hook '{hook_name}' timed out after {timeout_seconds}s",
            )
        except Exception as e:
            return HookResult(
                hook_name=hook_name,
                executed=True,
                exit_code=-1,
                error=str(e),
            )
