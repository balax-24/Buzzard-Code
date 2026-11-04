from security_agent.tui.test_utils import run_async
"""
Tests for Verified Findings Panel Widget.
Verifies:
1. Display of confirmed vulnerabilities with severity badges.
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.findings_panel import FindingsPanel


def test_findings_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(FindingsPanel)
    
            # Add verified finding
            app.controller.state.findings.append({
                "title": "Authentication Bypass via SQLi",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED"
            })
            panel.refresh_panel()
    
            assert "CRITICAL" in panel.raw_text
            assert "Authentication Bypass via SQLi" in panel.raw_text
    run_async(_run())
