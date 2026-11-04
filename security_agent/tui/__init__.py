"""
Buzzard & Qwythos Terminal User Interface (TUI) Package.
"""

from security_agent.tui.models import AppMode

def __getattr__(name: str):
    if name == "QwythosTUIApp":
        from security_agent.tui.app import QwythosTUIApp
        return QwythosTUIApp
    if name == "BuzzardTUIApp":
        from security_agent.tui.app import BuzzardTUIApp
        return BuzzardTUIApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["AppMode", "QwythosTUIApp", "BuzzardTUIApp"]
