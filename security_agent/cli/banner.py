"""The BUZZARD CODE wordmark, shared by the setup wizard and the terminal UI."""

from __future__ import annotations

from typing import List

from rich.text import Text

_BUZZARD = [
    "██████╗ ██╗   ██╗███████╗███████╗ █████╗ ██████╗ ██████╗ ",
    "██╔══██╗██║   ██║╚══███╔╝╚══███╔╝██╔══██╗██╔══██╗██╔══██╗",
    "██████╔╝██║   ██║  ███╔╝   ███╔╝ ███████║██████╔╝██║  ██║",
    "██╔══██╗██║   ██║ ███╔╝   ███╔╝  ██╔══██║██╔══██╗██║  ██║",
    "██████╔╝╚██████╔╝███████╗███████╗██║  ██║██║  ██║██████╔╝",
    "╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ",
]
_CODE = [
    " ██████╗ ██████╗ ██████╗ ███████╗",
    "██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    "██║     ██║   ██║██║  ██║█████╗  ",
    "██║     ██║   ██║██║  ██║██╔══╝  ",
    "╚██████╗╚██████╔╝██████╔╝███████╗",
    " ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
]
_LINE_STYLES = ["#e9d5ff", "#d8b4fe", "#c084fc", "#a78bfa", "#8b5cf6", "#7c3aed"]
TAGLINE = "Understand. Plan. Build. Verify. Secure."
_SIDE_BY_SIDE_WIDTH = len(_BUZZARD[0]) + len(_CODE[0]) + 2
_STACKED_WIDTH = len(_BUZZARD[0])


def banner_lines(width: int) -> List[str]:
    """Picks the largest wordmark that fits, so narrow terminals never wrap it."""
    if width >= _SIDE_BY_SIDE_WIDTH:
        return [f"{left} {right}" for left, right in zip(_BUZZARD, _CODE)]
    if width >= _STACKED_WIDTH:
        return [*_BUZZARD, *_CODE]
    return ["BUZZARD CODE"]


def render_banner(width: int, indent: int = 1) -> Text:
    """Returns the wordmark and tagline with a vertical colour gradient."""
    lines = banner_lines(max(0, width - indent))
    text = Text()
    for index, line in enumerate(lines):
        style = "bold " + _LINE_STYLES[index % len(_LINE_STYLES)]
        text.append(" " * indent + line + "\n", style=style)
    text.append(" " * indent + TAGLINE + "\n", style="#94a3b8")
    return text
