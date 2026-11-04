from tui.test_utils import run_async
"""
Tests for TUI Session Checkpoint and Resumption.
Verifies:
1. Saving checkpoint via /checkpoint.
2. Resuming checkpoint via /resume.
"""

import pytest
import tempfile
from tui.app import QwythosTUIApp
from tui.config import TUIConfig


def test_session_save_and_resume():
    async def _run():
        with tempfile.TemporaryDirectory() as tmpdir:
            config = TUIConfig(checkpoint_dir=tmpdir)
            app = QwythosTUIApp(config=config, use_fake_model=True)
    
            async with app.run_test() as pilot:
                # 1. Add state items
                app.controller.state.record_service("target.local", 443, "https", evidence_id="EVI-SSL-01")
    
                # 2. Save checkpoint
                app.chat_input.value = "/checkpoint"
                await pilot.press("enter")
                await pilot.pause(0.1)
    
                saved_chk_id = app.controller.last_checkpoint_id
                assert saved_chk_id is not None
    
                # 3. Create clean app and resume
                resume_app = QwythosTUIApp(config=config, use_fake_model=True, resume_session_id=saved_chk_id)
                async with resume_app.run_test() as pilot2:
                    assert "target.local:443/tcp" in resume_app.controller.state.services
                    assert resume_app.controller.last_checkpoint_id == saved_chk_id
    run_async(_run())
