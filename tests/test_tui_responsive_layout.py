from tui.test_utils import run_async
"""
Tests for TUI Responsive Layout and Sidebar Toggling.
Verifies:
1. F2 toggles left sidebar class.
2. Layout adjusts seamlessly.
"""

import pytest
from tui.app import QwythosTUIApp


def test_tui_responsive_sidebar_toggle():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            sidebar = app.query_one("#left_sidebar")
            assert not sidebar.has_class("hidden")
    
            # Toggle sidebar
            app.action_toggle_sidebar()
            await pilot.pause(0.05)
            assert sidebar.has_class("hidden")
    
            # Toggle again
            app.action_toggle_sidebar()
            await pilot.pause(0.05)
            assert not sidebar.has_class("hidden")
    run_async(_run())
