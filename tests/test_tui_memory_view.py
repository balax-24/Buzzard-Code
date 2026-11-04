from security_agent.tui.test_utils import run_async
"""
Tests for Layered Memory (L0-L8) Panel Widget.
Verifies:
1. Rehydration context rendering in MemoryPanel.
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.memory_panel import MemoryPanel


def test_memory_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(MemoryPanel)
    
            # Record failure constraint in memory
            app.controller.memory_mgr.record_failure("127.0.0.1:8080", "sqlmap", "WAF_BLOCKED")
            panel.refresh_panel()
    
            assert "WAF_BLOCKED" in panel.raw_text
            assert "ACTIVE INVESTIGATION STATE" in panel.raw_text
    run_async(_run())
