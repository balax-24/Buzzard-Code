"""
Compact Terminal-Native Tool Activity Card Widgets for Buzzard Code TUI.
Renders real-time security verification pipelines (Policy, Scope, Sandbox),
execution timelines, and compact output summaries using box-drawing characters.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Dict, Any, List, Optional
from textual.widget import Widget
from textual.app import ComposeResult
from rich.text import Text

from tui.models import ToolCallCardData, redact_sensitive_data


class ToolActivityCard(Widget):
    """
    Compact terminal-native card rendering a security tool execution timeline.
    Layout (Running):
      ┌─ nmap ──────────────────────────────────────────────
      │  127.0.0.1
      │
      │  ✓ policy     ✓ scope     ✓ sandbox
      │  ● running                         3.2s
      └────────────────────────────────────────────────────

    Layout (Completed):
      ┌─ nmap ──────────────────────────────────────────────
      │  ✓ completed                         8.4s
      │
      │  3 open ports (22/tcp, 80/tcp, 443/tcp)
      └────────────────────────────────────────────────────

    Layout (Blocked):
      ┌─ tool blocked ──────────────────────────────────────
      │  ✕ policy denied
      │  Reason: target outside authorized scope
      └────────────────────────────────────────────────────
    """

    DEFAULT_CSS = """
    ToolActivityCard {
        margin: 0 0 1 0;
        padding: 0;
        background: transparent;
        height: auto;
    }
    """

    def __init__(
        self,
        tool_name: str,
        target: str = "",
        arguments: Optional[Dict[str, Any]] = None,
        tool_call_id: Optional[str] = None,
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.tool_name = tool_name
        self.target = target or ""
        self.arguments = arguments or {}
        self.tool_call_id = tool_call_id or f"tc-{uuid.uuid4().hex[:8]}"

        self.start_time: float = time.time()
        self.duration_seconds: Optional[float] = None
        self.status: str = "VALIDATING"  # VALIDATING, RUNNING, COMPLETED, FAILED, BLOCKED
        self.stdout: str = ""
        self.stderr: str = ""
        self.exit_code: Optional[int] = None
        self.stages: List[Dict[str, Any]] = []
        self.block_reason: str = ""

        # Default stage initialization
        self.update_stage("VALIDATING", "Validating action...")

    def update_stage(self, stage: str, text: Optional[str] = None) -> None:
        """Update or append an execution lifecycle stage."""
        # Events without a call id resolve to the latest card, which may already be finished
        if self.status in ("COMPLETED", "FAILED", "BLOCKED"):
            return
        stage_upper = stage.upper()
        default_text = text or stage

        if "POLICY_ALLOWED" in stage_upper:
            default_text = text or "✓ Policy allowed"
        elif "POLICY_DENIED" in stage_upper:
            default_text = text or "✕ Policy denied"
            self.status = "BLOCKED"
            if text and ":" in text:
                self.block_reason = text.split(":", 1)[1].strip()
        elif "SCOPE_AUTHORIZED" in stage_upper:
            default_text = text or "✓ Scope authorized"
        elif "SCOPE_VIOLATION" in stage_upper or "OUT_OF_SCOPE" in stage_upper:
            default_text = text or "✕ Scope violation"
            self.status = "BLOCKED"
        elif "SANDBOX_READY" in stage_upper:
            default_text = text or "✓ Docker sandbox"
        elif "AWAITING_APPROVAL" in stage_upper:
            default_text = text or "⚠ Approval required"
        elif "APPROVAL_APPROVED" in stage_upper:
            default_text = text or "✓ Operator approved"
        elif "APPROVAL_REJECTED" in stage_upper:
            default_text = text or "✕ Operator denied"
            self.status = "BLOCKED"
        elif "RUNNING" in stage_upper:
            default_text = text or "● Running in sandbox..."
            self.status = "RUNNING"

        self.stages.append({
            "stage": stage,
            "text": default_text,
            "time": time.time(),
        })
        self.refresh(layout=True)

    def set_completed(self, payload: Dict[str, Any]) -> None:
        self.status = "COMPLETED"
        self.duration_seconds = payload.get("duration_seconds")
        if self.duration_seconds is None and self.start_time:
            self.duration_seconds = round(time.time() - self.start_time, 2)
        self.stdout = payload.get("stdout", "")
        self.stderr = payload.get("stderr", "")
        self.exit_code = payload.get("exit_code", 0)
        self.stages.append({
            "stage": "COMPLETED",
            "text": f"✓ Completed in {self.duration_seconds}s",
            "time": time.time(),
        })
        self.refresh(layout=True)

    def set_failed(self, payload: Dict[str, Any]) -> None:
        self.status = "FAILED"
        self.duration_seconds = payload.get("duration_seconds")
        if self.duration_seconds is None and self.start_time:
            self.duration_seconds = round(time.time() - self.start_time, 2)
        self.stdout = payload.get("stdout", "")
        self.stderr = payload.get("stderr", "") or payload.get("error", "")
        self.exit_code = payload.get("exit_code", 1)
        self.stages.append({
            "stage": "FAILED",
            "text": f"✕ Failed (code {self.exit_code})",
            "time": time.time(),
        })
        self.refresh(layout=True)

    def render(self) -> Text:
        """Renders one transcript entry: a status dot, the call, then an indented result."""
        t = Text()
        status_styles = {
            "COMPLETED": "bold #10b981",
            "FAILED": "bold #ef4444",
            "BLOCKED": "bold #ef4444",
        }
        t.append("● ", style=status_styles.get(self.status, "bold #06b6d4"))
        t.append(self.tool_name, style="bold #f1f5f9")
        primary = self._primary_argument()
        if primary:
            t.append(f"({primary})", style="#94a3b8")
        if self.duration_seconds is not None and self.status in ("COMPLETED", "FAILED"):
            t.append(f"  {self.duration_seconds:.1f}s", style="#64748b")
        t.append("\n")

        if self.status == "BLOCKED":
            self._append_result_lines(t, [f"Denied: {self.block_reason or 'blocked by policy'}"], "#f87171")
        elif self.status == "FAILED":
            output = (self.stderr or self.stdout or "").strip().splitlines()
            self._append_result_lines(t, [f"Failed (exit {self.exit_code})", *output[:5]], "#f87171")
        elif self.status == "COMPLETED":
            self._append_result_lines(t, self._extract_clean_summary(), "#cbd5e1")
        else:
            latest = self.stages[-1].get("text", "") if self.stages else ""
            self._append_result_lines(t, [latest or "Working..."], "#64748b")
        return t

    def _primary_argument(self) -> str:
        if self.arguments:
            for key in ("command", "path", "query", "url", "cmd", "target"):
                if key in self.arguments:
                    return str(self.arguments[key])[:100]
        return self.target or ""

    def _append_result_lines(self, t: Text, lines: List[str], style: str) -> None:
        """Shows up to 12 lines under the call, colouring unified diff lines."""
        for index, line in enumerate(lines[:12]):
            t.append("  ⎿  " if index == 0 else "     ", style="#64748b")
            if line.startswith("+") and not line.startswith("+++"):
                t.append(line + "\n", style="#34d399")
            elif line.startswith("-") and not line.startswith("---"):
                t.append(line + "\n", style="#f87171")
            else:
                t.append(line + "\n", style=style)
        if len(lines) > 12:
            t.append(f"     ... {len(lines) - 12} more lines\n", style="#64748b")

    def _extract_clean_summary(self) -> List[str]:
        """Extract a readable summary or truncated stdout for terminal display."""
        raw = (self.stdout or "").strip()
        if not raw:
            return []
        lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
        return lines


# -----------------------------------------------------------------------------
# Backwards Compatibility: ToolCallCard
# -----------------------------------------------------------------------------
class ToolCallCard(Widget):
    """
    Legacy card rendering an executed security or browser tool.
    Preserved for backward compatibility.
    """

    DEFAULT_CSS = """
    ToolCallCard {
        margin: 1 0;
        padding: 0;
        background: transparent;
    }
    """

    def __init__(self, data: ToolCallCardData, id: str | None = None):
        super().__init__(id=id)
        self.data = data

    def render(self) -> Text:
        t = Text()
        stat = (getattr(self.data, "status", "") or "").upper()
        icon = "✓" if stat == "SUCCESS" else ("●" if stat == "RUNNING" else "✕")
        style = "bold #10b981" if stat == "SUCCESS" else ("bold #06b6d4" if stat == "RUNNING" else "bold #ef4444")
        t.append(f"  {icon} ", style=style)
        t.append(f"{self.data.tool_name} ", style="bold #a78bfa")
        dur = getattr(self.data, "duration_seconds", None)
        if dur is not None and dur > 0:
            t.append(f"({dur:.2f}s) ", style="#64748b")
        if getattr(self.data, "arguments", None):
            t.append(f"{json.dumps(self.data.arguments)} ", style="#94a3b8")
        return t
