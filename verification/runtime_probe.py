"""
Agentic Runtime State Probe and Execution Inspector for Buzzard Code.

Provides DAP-style runtime inspection to eliminate agent debugging blindness:
1. Traces live function calls and step-by-step local variables.
2. Captures exact call stack frames, variable states, and exception boundaries.
3. Eliminates repetitive 'add print statements -> test -> revert' loops.
"""

from __future__ import annotations

import inspect
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class FrameSnapshot:
    function_name: str
    filename: str
    line_number: int
    local_variables: Dict[str, str] = field(default_factory=dict)


@dataclass
class RuntimeSnapshot:
    success: bool
    return_value: Optional[str] = None
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    frames: List[FrameSnapshot] = field(default_factory=list)
    call_sequence: List[str] = field(default_factory=list)

    def format_diagnostic_report(self) -> str:
        lines = [
            f"🔍 RUNTIME EXECUTION PROBE REPORT: {'✔ SUCCESS' if self.success else '✖ EXCEPTION CAUGHT'}"
        ]
        if self.return_value is not None:
            lines.append(f"  • Return Value: {self.return_value}")
        if self.exception_type:
            lines.append(f"  • Exception: {self.exception_type}: {self.exception_message}")

        if self.frames:
            lines.append("\n  • Active Stack Frames & Locals at Point of Failure:")
            for idx, f in enumerate(reversed(self.frames[-4:])):
                lines.append(f"    [{idx}] {f.function_name}() at {Path(f.filename).name}:{f.line_number}")
                for var_name, var_val in f.local_variables.items():
                    if not var_name.startswith("__"):
                        lines.append(f"        - {var_name} = {var_val}")

        return "\n".join(lines)


class RuntimeProbe:
    """
    Executes and traces functions with deep frame and variable inspection.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def probe_callable(self, func: Callable, *args, **kwargs) -> RuntimeSnapshot:
        """
        Executes a callable with live frame tracing and variable capture.
        """
        frames: List[FrameSnapshot] = []
        calls: List[str] = []

        def _tracer(frame, event, arg):
            if event == "call":
                calls.append(frame.f_code.co_name)
            elif event in ("return", "exception"):
                # Capture variables safely
                locals_safe = {}
                for k, v in list(frame.f_locals.items())[:15]:
                    if not k.startswith("__"):
                        try:
                            s = repr(v)
                            locals_safe[k] = s[:120] + "..." if len(s) > 120 else s
                        except Exception:
                            locals_safe[k] = "<unprintable>"

                frames.append(
                    FrameSnapshot(
                        function_name=frame.f_code.co_name,
                        filename=frame.f_code.co_filename,
                        line_number=frame.f_lineno,
                        local_variables=locals_safe,
                    )
                )
            return _tracer

        old_trace = sys.gettrace()
        sys.settrace(_tracer)

        ret_val = None
        exc_type = None
        exc_msg = None
        success = True

        try:
            ret_val = func(*args, **kwargs)
        except Exception as e:
            success = False
            exc_type = type(e).__name__
            exc_msg = str(e)
            # Add traceback frame
            tb = sys.exc_info()[2]
            while tb:
                f = tb.tb_frame
                locals_safe = {k: repr(v)[:100] for k, v in list(f.f_locals.items())[:10] if not k.startswith("__")}
                frames.append(
                    FrameSnapshot(
                        function_name=f.f_code.co_name,
                        filename=f.f_code.co_filename,
                        line_number=tb.tb_lineno,
                        local_variables=locals_safe,
                    )
                )
                tb = tb.tb_next
        finally:
            sys.settrace(old_trace)

        return RuntimeSnapshot(
            success=success,
            return_value=repr(ret_val) if ret_val is not None else None,
            exception_type=exc_type,
            exception_message=exc_msg,
            frames=frames,
            call_sequence=calls[:20],
        )

    def probe_code_snippet(self, code: str, context_vars: Optional[Dict[str, Any]] = None) -> RuntimeSnapshot:
        """
        Compiles and probes an arbitrary code snippet.
        """
        ns = dict(context_vars or {})
        ns["__name__"] = "__buzzard_probe__"

        def _runner():
            compiled = compile(code, "<buzzard_probe>", "exec")
            exec(compiled, ns)
            return ns.get("__result__")

        return self.probe_callable(_runner)
