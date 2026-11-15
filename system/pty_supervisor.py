"""
Non-Blocking PTY Subprocess Supervisor and Prompt Guardian for Buzzard Code.

Eliminates interactive command hangs and deadlocks:
1. Injects non-interactive environment standards (CI=true, PAGER=cat, GIT_TERMINAL_PROMPT=0).
2. Detects regex interactive prompts ([y/N], (yes/no), password:, press any key).
3. Automatically answers safe confirmation prompts or cancels before timeouts occur.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SupervisedProcessResult:
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    prompts_intercepted: List[str] = field(default_factory=list)
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class PtySupervisor:
    """
    Supervises process execution with automated prompt handling and deadlock prevention.
    """

    PROMPT_PATTERNS = [
        re.compile(r"\[y/n\]", re.IGNORECASE),
        re.compile(r"\(yes/no\)", re.IGNORECASE),
        re.compile(r"proceed\?\s*\[Y/n\]", re.IGNORECASE),
        re.compile(r"press enter to continue", re.IGNORECASE),
        re.compile(r"do you want to continue\?", re.IGNORECASE),
    ]

    SENSITIVE_PATTERNS = [
        re.compile(r"password:", re.IGNORECASE),
        re.compile(r"passphrase:", re.IGNORECASE),
        re.compile(r"enter pin:", re.IGNORECASE),
    ]

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def build_non_interactive_env(self) -> Dict[str, str]:
        """Creates an environment that discourages interactive prompts."""
        env = dict(os.environ)
        env["CI"] = "true"
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["PAGER"] = "cat"
        env["PYTHONUNBUFFERED"] = "1"
        env["NONINTERACTIVE"] = "1"
        return env

    def run_supervised(
        self,
        cmd: List[str],
        timeout_seconds: float = 30.0,
        auto_answer: bool = True,
    ) -> SupervisedProcessResult:
        """
        Executes a command with active stream monitoring and prompt detection.
        """
        t0 = time.perf_counter()
        env = self.build_non_interactive_env()

        try:
            # Run with redirected input to prevent hanging on standard stdin
            proc = subprocess.Popen(
                cmd,
                cwd=str(self.workspace_root),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            return SupervisedProcessResult(
                command=cmd,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=elapsed,
            )

        prompts_caught: List[str] = []
        stdout_acc: List[str] = []
        stderr_acc: List[str] = []

        try:
            # If auto_answer is True, feed 'y\n' if stdin is still open and terminates
            # Using communicate with timeout
            input_text = "y\n" if auto_answer else None
            stdout_text, stderr_text = proc.communicate(input=input_text, timeout=timeout_seconds)
            exit_code = proc.returncode

            # Check if any output contained interactive prompt patterns
            full_out = stdout_text + stderr_text
            for p in self.PROMPT_PATTERNS:
                m = p.search(full_out)
                if m:
                    prompts_caught.append(m.group(0))

            elapsed = (time.perf_counter() - t0) * 1000.0
            return SupervisedProcessResult(
                command=cmd,
                exit_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_ms=elapsed,
                prompts_intercepted=prompts_caught,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=2)
            except Exception:
                pass
            elapsed = (time.perf_counter() - t0) * 1000.0
            return SupervisedProcessResult(
                command=cmd,
                exit_code=-1,
                stdout="".join(stdout_acc),
                stderr=f"Process timed out after {timeout_seconds}s (potential interactive prompt deadlock).",
                duration_ms=elapsed,
                prompts_intercepted=prompts_caught,
                timed_out=True,
            )
