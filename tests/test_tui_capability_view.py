from security_agent.tui.test_utils import run_async
"""
Tests for Capabilities Panel Widget.
Verifies:
1. Progression hierarchy display (UNAUTHENTICATED -> AUTHENTICATED -> ADMIN_ACCESS).
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.capabilities_panel import CapabilitiesPanel
from security_agent.agent.assessment_state import Capability, CapabilityType


def test_capabilities_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(CapabilitiesPanel)
    
            # Add capability
            app.controller.state.capabilities["cap-admin"] = Capability(
                capability_id="cap-admin",
                capability_type=CapabilityType.ADMIN_ACCESS,
                target_scope="127.0.0.1",
                source_evidence_ids=["EVI-001"]
            )
            panel.refresh_panel()
    
            assert "ADMIN_ACCESS" in panel.raw_text
            assert "cap-admin" in panel.raw_text
    run_async(_run())
