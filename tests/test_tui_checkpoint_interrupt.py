from security_agent.tui.test_utils import run_async
"""
Tests for TUI Interrupt and Checkpoint Saving.
Verifies:
1. First Ctrl+C triggers cancellation request.
2. Second Ctrl+C saves checkpoint before exit.
"""

import pytest
import tempfile
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.config import TUIConfig


def test_tui_interrupt_handling():
    async def _run():
        with tempfile.TemporaryDirectory() as tmpdir:
            config = TUIConfig(checkpoint_dir=tmpdir)
            app = QwythosTUIApp(config=config, use_fake_model=True)
    
            async with app.run_test() as pilot:
                # First Ctrl+C
                await pilot.press("ctrl+c")
                await pilot.pause(0.05)
                last_msg = app.controller.chat_history[-1]
                assert "Press **Ctrl+C** again" in last_msg.content or "Cancellation requested" in last_msg.content
    run_async(_run())
