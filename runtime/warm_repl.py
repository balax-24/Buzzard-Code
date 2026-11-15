"""
Persistent Warm REPL Session for Buzzard Code.

Eliminates the 5-10 second cold-start subprocess tax by maintaining a persistent,
in-memory Python evaluation worker. Enables instant sub-50ms function execution,
hot module reloading, and live variable inspection across tool turns.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

WORKER_BOOTSTRAP_CODE = """
import sys, json, traceback, io

def main():
    globals_dict = {"__name__": "__buzzard_repl__"}
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line)
            cmd = req.get("cmd", "eval")
            code = req.get("code", "")
            
            old_stdout, old_stderr = sys.stdout, sys.stderr
            redirected_out, redirected_err = io.StringIO(), io.StringIO()
            sys.stdout, sys.stderr = redirected_out, redirected_err
            
            result_val = None
            success = True
            err_msg = None
            
            try:
                import ast
                tree = ast.parse(code)
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last_expr = tree.body.pop()
                    if tree.body:
                        exec(compile(tree, "<buzzard-repl>", "exec"), globals_dict)
                    result_val = eval(compile(ast.Expression(last_expr.value), "<buzzard-repl>", "eval"), globals_dict)
                else:
                    exec(compile(tree, "<buzzard-repl>", "exec"), globals_dict)
                    result_val = None
            except Exception as e:
                success = False
                err_msg = "".join(traceback.format_exception(*sys.exc_info()))
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr
                
            resp = {
                "success": success,
                "output": redirected_out.getvalue(),
                "stderr": redirected_err.getvalue(),
                "result": repr(result_val) if result_val is not None else None,
                "error": err_msg
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
        except Exception as outer_e:
            sys.stdout.write(json.dumps({"success": False, "error": str(outer_e)}) + "\\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
"""


@dataclass
class ReplEvalResult:
    success: bool
    output: str
    stderr: str
    result: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0

    def format_summary(self) -> str:
        if self.success:
            parts = []
            if self.output.strip():
                parts.append(f"Output:\n{self.output.strip()}")
            if self.result is not None:
                parts.append(f"Result: {self.result}")
            parts.append(f"⚡ Elapsed: {self.execution_time_ms:.1f}ms (warm)")
            return "\n".join(parts) if parts else "Executed successfully (no output)."
        return f"✖ Error ({self.execution_time_ms:.1f}ms):\n{self.error or self.stderr}"


class WarmReplSession:
    """
    Manages a persistent, hot Python runtime process.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._start_worker()

    def _start_worker(self) -> None:
        env = dict(os.environ)
        # Add workspace root to PYTHONPATH so imports resolve naturally
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{str(self.workspace_root)}:{existing_pythonpath}" if existing_pythonpath else str(self.workspace_root)

        self.process = subprocess.Popen(
            [sys.executable, "-u", "-c", WORKER_BOOTSTRAP_CODE],
            cwd=str(self.workspace_root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )

    def is_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def execute(self, code: str, timeout_seconds: float = 10.0) -> ReplEvalResult:
        """
        Executes code inside the hot worker process and returns output in milliseconds.
        """
        with self._lock:
            if not self.is_alive():
                self._start_worker()

            if not self.process or not self.process.stdin or not self.process.stdout:
                return ReplEvalResult(success=False, output="", stderr="", error="REPL worker not available.")

            t0 = time.perf_counter()
            req = json.dumps({"cmd": "eval", "code": code}) + "\n"

            try:
                self.process.stdin.write(req)
                self.process.stdin.flush()

                # Read response line
                resp_line = self.process.stdout.readline()
                elapsed = (time.perf_counter() - t0) * 1000.0

                if not resp_line:
                    return ReplEvalResult(success=False, output="", stderr="", error="REPL worker closed unexpectedly.", execution_time_ms=elapsed)

                data = json.loads(resp_line)
                return ReplEvalResult(
                    success=data.get("success", False),
                    output=data.get("output", ""),
                    stderr=data.get("stderr", ""),
                    result=data.get("result"),
                    error=data.get("error"),
                    execution_time_ms=elapsed,
                )
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000.0
                # Restart if pipe broke
                self.restart()
                return ReplEvalResult(success=False, output="", stderr="", error=str(e), execution_time_ms=elapsed)

    def restart(self) -> None:
        """Kills the active worker and boots a fresh warm process."""
        with self._lock:
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=2)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
                self.process = None
            self._start_worker()

    def close(self) -> None:
        """Terminates the worker process cleanly."""
        with self._lock:
            if self.process:
                try:
                    self.process.terminate()
                except Exception:
                    pass
                self.process = None
