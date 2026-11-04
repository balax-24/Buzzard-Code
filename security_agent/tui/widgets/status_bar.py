"""
Persistent Compact Status Bar Widget for Buzzard Code TUI.
Displays Provider health, Docker Sandbox enforcement, Scope, Session, and Mode.
Responsive to narrow and wide terminal viewports.
"""

from __future__ import annotations

from textual.widget import Widget
from rich.text import Text

from security_agent.agent.assessment_state import AssessmentState, AssessmentPhase, ObjectiveStatus


class BuzzardStatusBar(Widget):
    """
    Persistent compact bottom status bar for Buzzard Code.
    Target:
      ● Ollama   ● Docker   Scope: localhost   Model: qwythos:latest   Session: 01J...   Mode: Autonomous
    Failure state:
      ● Ollama   ✕ Docker   Scope: localhost
    """

    DEFAULT_CSS = """
    BuzzardStatusBar {
        dock: bottom;
        height: 1;
        background: #0d0e15;
        color: #94a3b8;
        padding: 0 1;
        margin: 0;
    }
    """

    def __init__(
        self,
        provider_name: str = "Ollama",
        provider_online: bool = True,
        docker_available: bool = True,
        scope: str = "localhost, 127.0.0.1",
        session_id: str = "idle",
        model_name: str = "qwythos:latest",
        mode: str = "Autonomous",
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.provider_name = provider_name
        self.provider_online = provider_online
        self.docker_available = docker_available
        self.scope = scope
        self.session_id = session_id
        self.model_name = model_name
        self.mode = mode
        self.hint = "/help"
        self.usage_text = ""

    def update_metrics(
        self,
        provider_name: str | None = None,
        provider_online: bool | None = None,
        docker_available: bool | None = None,
        scope: str | None = None,
        session_id: str | None = None,
        model_name: str | None = None,
        mode: str | None = None,
        hint: str | None = None,
        usage_text: str | None = None,
    ) -> None:
        if usage_text is not None:
            self.usage_text = usage_text
        if provider_name is not None:
            self.provider_name = provider_name
        if provider_online is not None:
            self.provider_online = provider_online
        if docker_available is not None:
            self.docker_available = docker_available
        if scope is not None:
            self.scope = scope
        if session_id is not None:
            self.session_id = session_id
        if model_name is not None:
            self.model_name = model_name
        if mode is not None:
            self.mode = mode
        if hint is not None:
            self.hint = hint
        self.refresh()

    def render(self) -> Text:
        t = Text()
        width = self.size.width if self.size.width > 0 else 80

        # 1. Provider indicator: ● Ollama or ✕ Ollama
        prov_sym = "●" if self.provider_online else "✕"
        prov_style = "bold #10b981" if self.provider_online else "bold #ef4444"
        t.append(f"{prov_sym} ", style=prov_style)
        t.append(f"{self.provider_name}   ", style="bold #e2e8f0")

        # Token and context meter stays visible at every width
        if self.usage_text:
            t.append(f"{self.usage_text}   ", style="bold #fbbf24")

        # 2. Docker Sandbox indicator: ● Docker or ✕ Docker
        dock_sym = "●" if self.docker_available else "✕"
        dock_style = "bold #10b981" if self.docker_available else "bold #ef4444"
        t.append(f"{dock_sym} ", style=dock_style)
        t.append("Docker   ", style="bold #e2e8f0")

        # 3. Scope
        scope_disp = self.scope
        if len(scope_disp) > 20 and width < 100:
            scope_disp = scope_disp[:18] + ".."
        t.append(f"Scope: {scope_disp}   ", style="#06b6d4")

        # 4. Optional wider fields (Model, Session, Mode) if screen allows
        if width >= 100:
            t.append(f"Model: {self.model_name}   ", style="#a78bfa")
            short_sess = self.session_id
            if len(short_sess) > 12:
                short_sess = short_sess[:10] + ".."
            t.append(f"Session: {short_sess}   ", style="#64748b")
            t.append(f"Mode: {self.mode}   ", style="#94a3b8")

        # 5. Right-aligned hint if space allows
        current_len = len(t.plain)
        hint_str = self.hint
        if width - current_len > len(hint_str) + 3:
            padding = width - current_len - len(hint_str) - 2
            t.append(" " * max(1, padding))
            t.append(hint_str, style="#64748b")

        return t


# -----------------------------------------------------------------------------
# Backwards Compatibility: QwythosStatusBar
# -----------------------------------------------------------------------------
class QwythosStatusBar(Widget):
    DEFAULT_CSS = """
    QwythosStatusBar {
        dock: bottom;
        height: 1;
        background: #0d0e15;
        color: #94a3b8;
        border-top: solid #1e1f2e;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        phase: str = "DISCOVERY",
        turn: int = 1,
        max_turns: int = 40,
        tools_used: int = 0,
        nodes: int = 0,
        findings: int = 0,
        capabilities: int = 0,
        objective_status: str = "OBJECTIVE_UNREACHED",
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.phase = phase
        self.turn = turn
        self.max_turns = max_turns
        self.tools_used = tools_used
        self.nodes = nodes
        self.findings = findings
        self.capabilities = capabilities
        self.objective_status = objective_status

    def update_metrics(
        self,
        phase: str | None = None,
        turn: int | None = None,
        max_turns: int | None = None,
        tools_used: int | None = None,
        nodes: int | None = None,
        findings: int | None = None,
        capabilities: int | None = None,
        objective_status: str | None = None,
    ) -> None:
        if phase is not None:
            self.phase = phase
        if turn is not None:
            self.turn = turn
        if max_turns is not None:
            self.max_turns = max_turns
        if tools_used is not None:
            self.tools_used = tools_used
        if nodes is not None:
            self.nodes = nodes
        if findings is not None:
            self.findings = findings
        if capabilities is not None:
            self.capabilities = capabilities
        if objective_status is not None:
            self.objective_status = objective_status
        self.refresh()

    def render(self) -> Text:
        t = Text()
        t.append(f"Phase: {self.phase} ", style="bold #89b4fa")
        t.append("│ ", style="#262738")
        t.append(f"Turn: {self.turn}/{self.max_turns} ", style="#e2e8f0")
        t.append("│ ", style="#262738")
        t.append(f"Tools: {self.tools_used} ", style="#06b6d4")
        t.append("│ ", style="#262738")
        t.append(f"Findings: {self.findings} ", style="bold #f59e0b" if self.findings > 0 else "#e2e8f0")
        t.append("│ ", style="#262738")
        t.append(f"Objective: {self.objective_status}", style="bold #10b981")
        return t
