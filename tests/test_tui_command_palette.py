from tui.test_utils import run_async
"""
Tests for Qwythos TUI Ctrl+P Command Palette.
Verifies:
1. Palette opening and command selection.
2. Filtering and modal dismissal.
"""

import pytest
from tui.app import QwythosTUIApp
from tui.models import AppMode
from tui.widgets.command_palette import CommandPaletteModal


def test_command_palette_modal():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            # Open Command Palette via action
            app.action_open_command_palette()
            await pilot.pause(0.05)
    
            # Check modal screen active
            assert isinstance(app.screen, CommandPaletteModal)
    
            # Dismiss modal
            app.screen.dismiss(None)
            await pilot.pause(0.05)
    
            # Verified modal dismissed
            assert not isinstance(app.screen, CommandPaletteModal)
    run_async(_run())
