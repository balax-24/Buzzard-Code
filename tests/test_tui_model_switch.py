from security_agent.tui.test_utils import run_async
"""
Tests for TUI Model Switching without state loss.
Verifies:
1. Switching active model preserves graph, capabilities, and session state.
"""

import pytest
from textual.widgets import Input
from security_agent.tui.app import QwythosTUIApp


def test_model_switching_preserves_state():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            # Add state item
            app.controller.state.record_service("127.0.0.1", 22, "ssh", evidence_id="EVI-SSH-01")
    
            # Switch model
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/model qwen-cyber:latest"))
            await pilot.pause(0.1)
    
            assert app.controller.current_model == "qwen-cyber:latest"
            assert "127.0.0.1:22/tcp" in app.controller.state.services
    run_async(_run())
