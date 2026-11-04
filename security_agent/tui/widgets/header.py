"""
Compact Persistent Header Widget for Buzzard Code TUI.
Displays brand identity, reactive operational states, active model, and provider.
Follows minimal, information-dense, modern terminal design principles.
"""

from __future__ import annotations

from typing import Optional
from textual.widget import Widget
from textual.app import ComposeResult
from rich.text import Text

from security_agent.tui.models import AppMode


class BuzzardHeader(Widget):
    """
    Compact persistent header for Buzzard Code.
    Layout:
      BUZZARD  ● READY                         qwythos:latest · Ollama
      ────────────────────────────────────────────────────────────────
    """

    DEFAULT_CSS = """
    BuzzardHeader {
        dock: top;
        height: 2;
        background: #0d0e15;
        color: #e2e8f0;
        padding: 0 1;
        margin: 0;
    }
    """

    def __init__(
        self,
        model_name: str = "qwythos:latest",
        provider_name: str = "Ollama",
        mode: str = "Autonomous",
        status: str = "READY",
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.model_name = model_name
        self.provider_name = provider_name
        self.mode = mode
        self.status = status

    def update_state(
        self,
        status: str | None = None,
        model_name: str | None = None,
        provider_name: str | None = None,
        mode: str | None = None,
    ) -> None:
        if status is not None:
            self.status = status
        if model_name is not None:
            self.model_name = model_name
        if provider_name is not None:
            self.provider_name = provider_name
        if mode is not None:
            self.mode = mode
        self.refresh()

    def render(self) -> Text:
        st = (self.status or "READY").upper()

        # State pill configuration per specification:
        # ● READY, ◉ THINKING, ◉ EXECUTING, ⚠ APPROVAL, ✕ ERROR, ■ STOPPED
        if "READY" in st or "IDLE" in st or "COMPLETE" in st:
            state_symbol = "●"
            state_label = "READY"
            state_style = "bold #10b981"  # Emerald green
        elif "THINK" in st:
            state_symbol = "◉"
            state_label = "THINKING"
            state_style = "bold #a78bfa"  # Violet
        elif "PLAN" in st:
            state_symbol = "◉"
            state_label = "PLANNING"
            state_style = "bold #a78bfa"
        elif "RUN" in st or "EXEC" in st or "VALIDAT" in st:
            state_symbol = "◉"
            state_label = "EXECUTING"
            state_style = "bold #06b6d4"  # Cyan
        elif "APPROV" in st:
            state_symbol = "⚠"
            state_label = "APPROVAL"
            state_style = "bold #f59e0b"  # Amber
        elif "KILL" in st or "STOP" in st:
            state_symbol = "■"
            state_label = "STOPPED"
            state_style = "bold #94a3b8"  # Slate
        elif "FAIL" in st or "ERR" in st or "BLOCK" in st or "DENI" in st:
            state_symbol = "✕"
            state_label = "ERROR"
            state_style = "bold #ef4444"  # Red
        else:
            state_symbol = "●"
            state_label = st
            state_style = "bold #a78bfa"

        t = Text()

        # Left: Brand and Reactive State
        t.append("BUZZARD", style="bold #c084fc")
        t.append("  ")
        t.append(f"{state_symbol} {state_label}", style=state_style)

        # Right: Model and Provider
        prov_disp = self.provider_name.capitalize() if self.provider_name else "Local"
        right_info = f"{self.model_name} · {prov_disp}"

        # Sizing and spacing
        width = self.size.width if self.size.width > 0 else 80
        left_len = len(t.plain)
        right_len = len(right_info)
        padding_spaces = max(2, width - left_len - right_len - 2)

        t.append(" " * padding_spaces)
        t.append(right_info, style="#94a3b8")

        # Hairline separator rule on row 2
        rule_width = max(10, width - 2)
        t.append("\n")
        t.append("─" * rule_width, style="#1e1f2e")

        return t


# -----------------------------------------------------------------------------
# Backwards Compatibility: QwythosHeader
# -----------------------------------------------------------------------------
class QwythosHeader(Widget):
    """
    Top-level status and metadata header for Qwythos prototype.
    Preserved for backward compatibility.
    """

    DEFAULT_CSS = """
    QwythosHeader {
        dock: top;
        height: 2;
        background: #0d0e15;
        color: #e2e8f0;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        model_name: str = "qwythos:latest",
        mode: AppMode = AppMode.CHAT,
        session_id: str = "session-01",
        target_scope: str = "127.0.0.1",
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.model_name = model_name
        self.mode = mode
        self.session_id = session_id
        self.target_scope = target_scope
        self.status_text = "READY"

    def update_state(
        self,
        model_name: str | None = None,
        mode: AppMode | None = None,
        session_id: str | None = None,
        target_scope: str | None = None,
        status: str | None = None,
    ) -> None:
        if model_name is not None:
            self.model_name = model_name
        if mode is not None:
            self.mode = mode
        if session_id is not None:
            self.session_id = session_id
        if target_scope is not None:
            self.target_scope = target_scope
        if status is not None:
            self.status_text = status
        self.refresh()

    def render(self) -> Text:
        t = Text()
        t.append("BUZZARD ", style="bold #c084fc")
        t.append("│ ", style="#262738")
        t.append(f"{self.model_name} ", style="#94a3b8")
        t.append("│ ", style="#262738")
        t.append(f"{self.mode.value} ", style="bold #10b981")
        t.append("│ ", style="#262738")
        t.append(f"Scope: {self.target_scope} ", style="#06b6d4")
        t.append("│ ", style="#262738")
        t.append(f"● {self.status_text}", style="bold #e2e8f0")
        return t
