"""
Interactive Modal Dialogs for Buzzard Code TUI.
Provides terminal-native, keyboard-first modal dialogs for:
- Security Action Approval Gate ([Y] Allow, [N] Deny, [A] Always Allow)
- Interactive Model Selector (/model keyboard palette)
- Comprehensive Help Reference
"""

from __future__ import annotations

import json
from typing import Dict, Any, List, Optional
from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import Static, Button, OptionList
from textual.widgets.option_list import Option
from textual.binding import Binding
from rich.text import Text


class ApprovalModal(ModalScreen[bool]):
    """
    Security action approval gate modal.
    Per specification:
    ┌─ ACTION REQUIRES APPROVAL ────────────────────────────────┐
    │                                                            │
    │  Tool       nmap                                           │
    │  Target     192.168.1.20                                   │
    │  Scope      authorized network                             │
    │                                                            │
    │  Policy     ✓                                               │
    │  Sandbox    ✓                                               │
    │                                                            │
    │  Allow this action?                                         │
    │                                                            │
    │  [Y] Allow    [N] Deny    [A] Always allow this session    │
    └────────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    ApprovalModal {
        align: center middle;
        background: rgba(13, 14, 21, 0.88);
    }
    #approval_container {
        width: 90%;
        max-width: 100;
        height: auto;
        background: #13141f;
        border: solid #8b5cf6;
        padding: 1 2;
    }
    #approval_buttons {
        margin-top: 1;
        height: 3;
        align: center middle;
    }
    #approval_buttons Button {
        margin: 0 1;
        min-width: 14;
    }
    """

    BINDINGS = [
        Binding("y", "approve", "Allow", show=True),
        Binding("n", "deny", "Deny", show=True),
        Binding("d", "deny", "Deny", show=False),
        Binding("escape", "deny", "Deny", show=False),
    ]

    def __init__(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        target: str = "",
        policy_reason: str = "",
        scope_status: str = "authorized network",
        sandbox_env: str = "Docker Sandbox",
        risk_class: str = "R2",
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.tool_name = tool_name
        self.arguments = arguments
        self.target = target or str(arguments.get("target") or "localhost")
        self.policy_reason = policy_reason or "Verification required"
        self.scope_status = scope_status or "authorized network"
        self.sandbox_env = sandbox_env or "Docker Sandbox"
        self.risk_class = risk_class
        self.decision: bool = False

    def compose(self) -> ComposeResult:
        with Vertical(id="approval_container"):
            # Header
            header_text = Text("┌─ ACTION REQUIRES APPROVAL ", style="bold #f59e0b")
            header_text.append("─" * 38, style="#3b3d54")
            yield Static(header_text)

            # Details
            details = Text()
            details.append("\n  Tool       ", style="#94a3b8")
            details.append(f"{self.tool_name}\n", style="bold #c084fc")

            # Target and scope describe network actions; a local edit or command has neither
            if any(self.arguments.get(key) for key in ("target", "host", "url")):
                details.append("  Target     ", style="#94a3b8")
                details.append(f"{self.target}\n", style="bold #f1f5f9")

                details.append("  Scope      ", style="#94a3b8")
                details.append(f"{self.scope_status}\n", style="#06b6d4")
            details.append("\n")

            details.append("  Policy     ", style="#94a3b8")
            details.append("✓  ", style="bold #10b981")
            details.append(f"({self.policy_reason})\n", style="#64748b")

            details.append("  Sandbox    ", style="#94a3b8")
            is_isolated = "no isolation" not in self.sandbox_env.lower()
            details.append("✓  " if is_isolated else "⚠  ", style="bold #10b981" if is_isolated else "bold #f59e0b")
            details.append(f"({self.sandbox_env})\n\n", style="#64748b")

            for label, value in self._action_preview():
                details.append(f"  {label}\n", style="#94a3b8")
                details.append(f"{value}\n\n", style="bold #f1f5f9")

            details.append("  Allow this action?", style="bold #f1f5f9")
            yield Static(details)

            # Action Buttons
            with Horizontal(id="approval_buttons"):
                yield Button("[Y] Allow", variant="success", id="btn_approve")
                yield Button("[N] Deny", variant="error", id="btn_deny")

            footer_rule = Text("└" + "─" * 64, style="#3b3d54")
            yield Static(footer_rule)

    def _action_preview(self) -> List[tuple]:
        """The operator must see exactly what will run or change before approving it."""
        args = self.arguments or {}
        preview = []
        for key, label in (("command", "Command"), ("path", "File")):
            if args.get(key):
                preview.append((label, f"    {args[key]}"))
        if args.get("old_str") is not None or args.get("new_str") is not None:
            removed = "\n".join(f"    - {line}" for line in str(args.get("old_str", "")).splitlines()[:12])
            added = "\n".join(f"    + {line}" for line in str(args.get("new_str", "")).splitlines()[:12])
            preview.append(("Change", f"{removed}\n{added}"))
        elif args.get("content") is not None:
            lines = str(args["content"]).splitlines()
            shown = "\n".join(f"    {line}" for line in lines[:12])
            more = f"\n    ... {len(lines) - 12} more lines" if len(lines) > 12 else ""
            preview.append(("Content", shown + more))
        elif not preview and args:
            preview.append(("Arguments", "    " + str(args)[:400]))
        return preview

    def action_approve(self) -> None:
        self.decision = True
        self.dismiss(True)

    def action_deny(self) -> None:
        self.decision = False
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_approve":
            self.action_approve()
        elif event.button.id == "btn_deny":
            self.action_deny()


class ModelSwitchModal(ModalScreen[Optional[str]]):
    """
    Compact keyboard-driven model selector modal.
    Per specification:
    ┌ SELECT MODEL ─────────────────────────────────────────────┐
    │                                                            │
    │  ● qwythos:latest       Ollama                            │
    │    k3-sec:latest        Ollama                            │
    │    mistral:7b           Ollama                            │
    │                                                            │
    │  ↑↓ Navigate     Enter Select     Esc Cancel               │
    └────────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    ModelSwitchModal {
        align: center middle;
        background: rgba(13, 14, 21, 0.88);
    }
    #model_container {
        width: 64;
        height: auto;
        background: #13141f;
        border: solid #8b5cf6;
        padding: 1 2;
    }
    #model_options {
        height: auto;
        max-height: 12;
        background: #0d0e15;
        border: solid #1e1f2e;
        margin: 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    MODELS = ["qwythos:latest", "k3-sec:latest", "mistral:7b"]

    def __init__(
        self,
        available_models: Optional[List[str]] = None,
        active_model: str = "qwythos:latest",
        provider_name: str = "Ollama",
        id: str | None = None,
    ):
        super().__init__(id=id)
        if available_models:
            self.models_list = available_models
        else:
            self.models_list = list(self.MODELS)
        if active_model and active_model not in self.models_list:
            self.models_list.insert(0, active_model)
        self.active_model = active_model
        self.provider_name = provider_name

    def compose(self) -> ComposeResult:
        with Vertical(id="model_container"):
            header_text = Text("┌ SELECT MODEL ", style="bold #c084fc")
            header_text.append("─" * 46, style="#3b3d54")
            yield Static(header_text)

            options = []
            for m in self.models_list:
                bullet = "●" if m == self.active_model else " "
                prov = self.provider_name.capitalize()
                line = f"  {bullet} {m:<28} {prov}"
                options.append(Option(prompt=line, id=m))

            self.option_list = OptionList(*options, id="model_options")
            yield self.option_list

            footer_text = Text("  ↑↓ Navigate     Enter Select     Esc Cancel", style="#64748b")
            yield Static(footer_text)

            footer_rule = Text("└" + "─" * 60, style="#3b3d54")
            yield Static(footer_rule)

    def on_mount(self) -> None:
        self.option_list.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        selected_model = str(event.option.id)
        self.dismiss(selected_model)

    def action_cancel(self) -> None:
        self.dismiss(None)


class BuzzardHelpModal(ModalScreen[None]):
    """
    Compact terminal-native help reference modal.
    """

    DEFAULT_CSS = """
    BuzzardHelpModal {
        align: center middle;
        background: rgba(13, 14, 21, 0.88);
    }
    #help_container {
        width: 76;
        height: 26;
        background: #13141f;
        border: solid #8b5cf6;
        padding: 1 2;
    }
    #help_scroll {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_modal", "Close", show=True),
        Binding("q", "dismiss_modal", "Close", show=False),
        Binding("enter", "dismiss_modal", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help_container"):
            header = Text("⚡ Buzzard Code — Commands & Keybindings", style="bold #c084fc")
            yield Static(header)

            with VerticalScroll(id="help_scroll"):
                t = Text()
                t.append("\nNavigation & Controls\n", style="bold #f1f5f9")
                t.append("  Enter          ", style="bold #a78bfa")
                t.append("Submit prompt or execute command\n", style="#94a3b8")
                t.append("  Up / Down      ", style="bold #a78bfa")
                t.append("Cycle command history\n", style="#94a3b8")
                t.append("  Ctrl+C         ", style="bold #a78bfa")
                t.append("Cancel running operation / double-press to exit\n", style="#94a3b8")
                t.append("  Ctrl+D / /exit ", style="bold #a78bfa")
                t.append("Exit cleanly\n", style="#94a3b8")
                t.append("  F1 / /help     ", style="bold #a78bfa")
                t.append("Open this help reference\n", style="#94a3b8")
                t.append("  Escape         ", style="bold #a78bfa")
                t.append("Dismiss open modal dialogs\n", style="#94a3b8")

                t.append("\nSecurity & Model Commands\n", style="bold #f1f5f9")
                t.append("  /model [name]  ", style="bold #06b6d4")
                t.append("Interactive model selector or switch model\n", style="#94a3b8")
                t.append("  /models        ", style="bold #06b6d4")
                t.append("List available local and cloud models\n", style="#94a3b8")
                t.append("  /status        ", style="bold #06b6d4")
                t.append("View active runtime and session status\n", style="#94a3b8")
                t.append("  /tools         ", style="bold #06b6d4")
                t.append("List registered security tools and sandbox checks\n", style="#94a3b8")
                t.append("  /scope         ", style="bold #06b6d4")
                t.append("View or manage authorized IP/hostname scope\n", style="#94a3b8")
                t.append("  /permissions   ", style="bold #06b6d4")
                t.append("Inspect active policy and autonomy boundaries\n", style="#94a3b8")
                t.append("  /sandbox       ", style="bold #06b6d4")
                t.append("Inspect Docker sandbox container health\n", style="#94a3b8")
                t.append("  /doctor        ", style="bold #06b6d4")
                t.append("Run comprehensive environment diagnostics\n", style="#94a3b8")
                t.append("  /kill          ", style="bold #ef4444")
                t.append("Emergency stop (disarms tool execution)\n", style="#94a3b8")
                t.append("  /resume        ", style="bold #10b981")
                t.append("Disarm kill switch or resume task\n", style="#94a3b8")
                t.append("  /clear         ", style="bold #06b6d4")
                t.append("Clear conversation view\n", style="#94a3b8")
                yield Static(t)

            with Horizontal(id="help_buttons"):
                yield Button("Close (Esc)", variant="primary", id="close_help")

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


# -----------------------------------------------------------------------------
# Backwards Compatibility Modals
# -----------------------------------------------------------------------------
class HelpModal(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        with Vertical(id="help_container"):
            yield Static("⚡ Qwythos / Buzzard Code Help\nUse /help for commands.")
            yield Button("Close (Esc)", variant="primary", id="close_help")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


class CrashRecoveryModal(ModalScreen[str]):
    def __init__(self, checkpoint_id: str, id: str | None = None):
        super().__init__(id=id)
        self.checkpoint_id = checkpoint_id

    def compose(self) -> ComposeResult:
        with Vertical(id="recovery_container"):
            yield Static(f"⚠️ Unfinished session detected: {self.checkpoint_id}\nResume with full state?")
            with Horizontal():
                yield Button("Resume", variant="success", id="btn_resume")
                yield Button("New", variant="default", id="btn_new")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_resume":
            self.dismiss("RESUME")
        else:
            self.dismiss("NEW")
