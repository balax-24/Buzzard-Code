import pytest
from security_agent.tui.test_utils import run_async
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.branches_panel import BranchesPanel
from security_agent.intelligence.branches import BranchPriority


def test_branches_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)

        async with app.run_test() as pilot:
            panel = app.query_one(BranchesPanel)

            # Create branch
            app.controller.branch_mgr.create_branch("API Surface", "http://127.0.0.1:8080/api", BranchPriority.HIGH)
            panel.refresh_panel()

            assert "API Surface" in panel.raw_text
    run_async(_run())
