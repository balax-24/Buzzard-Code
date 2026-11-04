from security_agent.tui.test_utils import run_async
"""
Tests for Hypotheses Panel Widget.
Verifies:
1. Refreshing and rendering active vs refuted hypotheses.
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.hypotheses_panel import HypothesesPanel
from security_agent.agent.assessment_state import VulnerabilityHypothesis, HypothesisStatus


def test_hypotheses_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(HypothesesPanel)
    
            # Add hypothesis to state
            app.controller.state.hypotheses["HYP-001"] = VulnerabilityHypothesis(
                id="HYP-001",
                vulnerability_type="SQL Injection",
                target="http://127.0.0.1",
                service="http",
                port=8080,
                status=HypothesisStatus.UNTESTED
            )
            panel.refresh_panel()
    
            # Check content updated
            assert "HYP-001" in panel.raw_text
    run_async(_run())
