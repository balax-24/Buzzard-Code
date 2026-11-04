from tui.test_utils import run_async
"""
Tests for Live Attack Graph Tree Panel.
Verifies:
1. Tree node expansion and updating when services/endpoints are added.
"""

import pytest
from tui.app import QwythosTUIApp
from tui.widgets.graph_panel import AttackGraphTree
from intelligence.attack_graph import AttackGraph


def test_attack_graph_tree_widget():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            tree = app.query_one(AttackGraphTree)
    
            # Update state with services
            app.controller.state.record_service("127.0.0.1", 8080, "http", evidence_id="EVI-001")
            app.controller.graph.sync_from_state(app.controller.state)
            tree.update_graph(app.controller.graph)
    
            assert tree.tree_widget.root is not None
            assert len(tree.tree_widget.root.children) >= 1
    run_async(_run())
