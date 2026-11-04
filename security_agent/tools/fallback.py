"""
Fallback execution engine for the security arsenal.

Every hacking capability in this agent maps to a CHAIN of strategies.
The engine tries strategy A first; if it fails (binary missing, nonzero
exit, empty output, exception, time-out) it moves to strategy B, then C,
and so on. The result the model sees always includes the full chain trace
so it knows exactly what worked, what failed, and why.

Strategy contract:
    def strategy(runner, kwargs) -> (ok: bool, summary: str, detail: str)
Returning ok=False advances the chain. Raising an exception is also a
failure and is captured. A strategy may also return (True, summary, detail)
to stop the chain immediately.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

OUTPUT_CAP = 6000

# Capabilities whose chain must run EVERY strategy (pipeline semantics),
# not stop at the first success. Results are concatenated in chain order.
RUN_ALL_CAPABILITIES = {"wifi_recover"}

Strategy = Callable[["FallbackRunner", Dict[str, Any]], Tuple[bool, str, str]]


def _cap(text: str, limit: int = OUTPUT_CAP) -> str:
    text = (text or "").strip()
    if len(text) > limit:
        return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
    return text


def is_failed_result(res: Dict[str, Any]) -> bool:
    """Heuristics for deciding a sandbox command result is a failure."""
    if res.get("exit_code", 0) not in (0, None):
        return True
    combined = (str(res.get("stdout", "")) + " " + str(res.get("stderr", ""))).lower()
    for needle in ("command not found", "not found", "no such file", "not recognized",
                   "could not resolve", "connection refused", "permission denied",
                   "unknown command", "timed out", "sh: "):
        if needle in combined:
            return True
    return False


def find_wordlist(*candidates: str) -> Optional[str]:
    """Return the first existing wordlist from a candidate list."""
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


class FallbackRunner:
    """Tries a chain of strategies for one capability and reports the trace."""

    def __init__(self, sandbox: Any = None, timeout: float = 120.0):
        self.sandbox = sandbox
        self.timeout = timeout

    def tool_available(self, name: str) -> bool:
        exe = name.split()[0]
        if self.sandbox is not None and hasattr(self.sandbox, "execute"):
            if hasattr(self.sandbox, "image"):
                res = self.sandbox.execute(f"which {exe} 2>/dev/null || command -v {exe} 2>/dev/null", timeout=5.0)
                return res.get("exit_code") == 0 and bool((res.get("stdout") or "").strip())
            return True
        return shutil.which(exe) is not None

    def run_cmd(self, command: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Execute a shell command through the sandbox (or locally)."""
        if self.sandbox is None:
            from security_agent.sandbox.container import get_sandbox
            self.sandbox = get_sandbox()
            
        if self.sandbox is not None and hasattr(self.sandbox, "execute"):
            return self.sandbox.execute(command, timeout=timeout or self.timeout)
        try:
            res = subprocess.run(command, shell=True, capture_output=True,
                                 text=True, timeout=timeout or self.timeout)
            return {"exit_code": res.returncode, "stdout": res.stdout,
                    "stderr": res.stderr, "sandboxed": False}
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stdout": "", "stderr": "timed out", "sandboxed": False}
        except Exception as e:
            return {"exit_code": 1, "stdout": "", "stderr": str(e), "sandboxed": False}

    def run(
        self,
        capability: str,
        strategies: List[Tuple[str, Strategy]],
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the strategy chain. Returns a structured, model-readable result.

        Result keys:
          capability, ok, winner, elapsed_s,
          chain: [{strategy, status (OK/FAIL), summary, detail}],
          output: combined output of the winning strategy,
          advice: suggested next capability when everything fails
        """
        kwargs = kwargs or {}
        chain: List[Dict[str, Any]] = []
        started = time.time()
        winner = None
        last_detail = ""

        run_all = capability in RUN_ALL_CAPABILITIES
        for name, func in strategies:
            entry: Dict[str, Any] = {"strategy": name, "status": "FAIL", "summary": "", "detail": ""}
            try:
                ok, summary, detail = func(self, kwargs)
                entry["summary"] = _cap(summary, 1500)
                entry["detail"] = _cap(detail, OUTPUT_CAP)
                if ok:
                    entry["status"] = "OK"
                    winner = name
                    chain.append(entry)
                    if not run_all:
                        break
                    continue
            except Exception as e:
                entry["detail"] = _cap(f"{type(e).__name__}: {e}", 2000)
            last_detail = entry["detail"] or entry["summary"]
            chain.append(entry)

        elapsed = round(time.time() - started, 2)
        if winner:
            if run_all:
                ok_parts = [f"[{e['strategy']}]\n{e['detail']}" for e in chain if e["status"] == "OK"]
                combined = "\n\n".join(ok_parts) if ok_parts else chain[-1]["detail"]
            else:
                combined = chain[-1]["detail"]
            return {
                "capability": capability,
                "ok": True,
                "winner": winner,
                "elapsed_s": elapsed,
                "chain": chain,
                "output": combined,
                "advice": "",
            }

        tried = ", ".join(e["strategy"] for e in chain)
        return {
            "capability": capability,
            "ok": False,
            "winner": None,
            "elapsed_s": elapsed,
            "chain": chain,
            "output": last_detail,
            "advice": (
                f"All {len(chain)} strategies failed ({tried}). "
                f"Last error: {_cap(last_detail, 500)}. "
                f"Try changing targets/parameters, or run a different capability."
            ),
        }

    def format_result(self, result: Dict[str, Any]) -> str:
        """Render a fallback result the way the agent loop / CLI displays it."""
        lines = [f"[CAPABILITY: {result['capability']}]"]
        for entry in result["chain"]:
            lines.append(f"  [CHAIN] {entry['strategy']} -> {entry['status']}"
                         + (f" ({entry['summary']})" if entry["summary"] else ""))
        lines.append(f"[ELAPSED] {result['elapsed_s']}s")
        if result["ok"]:
            lines.append(f"[WINNER] {result['winner']}")
            lines.append("[RESULT]")
            lines.append(result["output"])
        else:
            lines.append("[RESULT] ALL STRATEGIES FAILED")
            lines.append("[ADVICE] " + result["advice"])
        return "\n".join(lines)


def strategy_from_cmd(
    name: str,
    build_cmd: Callable[[Dict[str, Any]], str],
    min_stdout: int = 1,
    timeout: float = 120.0,
) -> Strategy:
    """Wrap a shell command as a chain strategy with failure heuristics."""
    def _strat(runner: FallbackRunner, kwargs: Dict[str, Any]) -> Tuple[bool, str, str]:
        if not runner.tool_available(name.split()[0]):
            return False, f"binary '{name.split()[0]}' not installed", ""
        cmd = build_cmd(kwargs)
        res = runner.run_cmd(cmd, timeout=timeout)
        out = (res.get("stdout") or "").strip()
        err = (res.get("stderr") or "").strip()
        if is_failed_result(res):
            return False, f"exit={res.get('exit_code')}", (out + "\n" + err).strip()[:OUTPUT_CAP]
        if len(out) < min_stdout:
            return False, "empty output", (out + "\n" + err).strip()[:OUTPUT_CAP]
        return True, f"exit={res.get('exit_code')}, {len(out)} chars", out
    return _strat
