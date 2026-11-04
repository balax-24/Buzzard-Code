"""
Ctrl+P Command Palette Modal for Qwythos TUI.
Allows quick fuzzy searching and execution of commands.
"""

from __future__ import annotations

from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option


COMMANDS = [
    ("Switch Mode: CHAT", "/mode chat"),
    ("Switch Mode: INVESTIGATE", "/mode investigate"),
    ("Switch Mode: BROWSER", "/mode browser"),
    ("Switch Mode: ASSIST", "/mode assist"),
    ("Switch Mode: REVIEW", "/mode review"),
    ("Save Checkpoint", "/checkpoint"),
    ("List Saved Sessions", "/sessions"),
    ("Show Attack Graph", "/graph"),
    ("Show Hypotheses", "/hypotheses"),
    ("Show Verified Findings", "/findings"),
    ("Show Capabilities", "/capabilities"),
    ("Show Immutable Evidence", "/evidence"),
    ("Show Layered Memory (L0-L8)", "/memory"),
    ("Export Assessment Report", "/report md"),
    ("Run System Diagnostics", "/doctor"),
    ("Run Toolchain Check", "/toolcheck"),
    ("Clear Conversation", "/clear"),
    ("Show System Status", "/status"),
    ("Exit Qwythos TUI", "/quit"),
]


class CommandPaletteModal(ModalScreen[str | None]):
    DEFAULT_CSS = """
    CommandPaletteModal {
        align: center middle;
    }
    #palette_container {
        width: 60;
        height: 20;
        background: #1e1e2e;
        border: thick #89b4fa;
        padding: 1;
    }
    #palette_input {
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="palette_container"):
            yield Static("⚡ **Command Palette** (Type to filter, Enter to select, Esc to cancel)")
            self.input_widget = Input(placeholder="Search commands...", id="palette_input")
            yield self.input_widget
            self.options_widget = OptionList(
                *[Option(prompt=label, id=cmd) for label, cmd in COMMANDS],
                id="palette_options",
            )
            yield self.options_widget

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.lower()
        self.options_widget.clear_options()
        filtered = [
            Option(prompt=label, id=cmd)
            for label, cmd in COMMANDS
            if query in label.lower() or query in cmd.lower()
        ]
        for opt in filtered:
            self.options_widget.add_option(opt)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        selected_cmd = str(event.option.id)
        self.dismiss(selected_cmd)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if self.options_widget.option_count > 0:
            opt = self.options_widget.get_option_at_index(0)
            self.dismiss(str(opt.id))
        else:
            self.dismiss(None)
