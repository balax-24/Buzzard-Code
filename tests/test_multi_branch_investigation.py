"""
Tests for Phase 12 Multi-Path Investigation Branching Engine.
Verifies:
1. Branch creation, priority ranking, and branch switching.
2. Branch serialization and deserialization.
"""

import pytest
from intelligence.branches import (
    BranchManager,
    BranchPriority,
    BranchStatus,
)


def test_multi_branch_lifecycle():
    bm = BranchManager()

    # 1. Create 3 distinct attack branches
    b_web = bm.create_branch(name="Web Application", target="http://127.0.0.1:8080", priority=BranchPriority.HIGH, tool_budget=30)
    b_ssh = bm.create_branch(name="SSH Service", target="127.0.0.1:22", priority=BranchPriority.LOW, tool_budget=10)
    b_api = bm.create_branch(name="Internal API", target="http://127.0.0.1:8080/api/v1", priority=BranchPriority.MEDIUM, tool_budget=20)

    assert len(bm.branches) == 3
    assert bm.active_branch_id == b_web.branch_id

    # 2. Switch branch to API
    switched = bm.switch_branch(b_api.branch_id)
    assert switched is not None
    assert bm.get_active_branch().name == "Internal API"

    # 3. Serialize and restore branch manager
    data = bm.to_dict()
    restored_bm = BranchManager.from_dict(data)

    assert len(restored_bm.branches) == 3
    assert restored_bm.active_branch_id == b_api.branch_id
    assert restored_bm.get_active_branch().name == "Internal API"
    assert restored_bm.branches[b_web.branch_id].tool_calls_allocated == 30
