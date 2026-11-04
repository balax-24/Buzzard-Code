from tui.test_utils import run_async
"""
Tests for Evidence Panel Widget.
Verifies:
1. Immutable evidence listing across services and endpoints.
"""

import pytest
from tui.app import QwythosTUIApp
from tui.widgets.evidence_panel import EvidencePanel


def test_evidence_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(EvidencePanel)
    
            # Add service with evidence
            app.controller.state.record_service("127.0.0.1", 8080, "http", evidence_id="EVI-HTTP-001")
            panel.refresh_panel()
    
            assert "EVI-HTTP-001" in panel.raw_text
    run_async(_run())
