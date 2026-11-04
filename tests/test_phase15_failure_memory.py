"""
Phase 15 Tests: Failure-Aware Action Memory.
Verifies failure recording, condition mapping, and capability-triggered unblocking.
"""

from intelligence.failure_memory import FailureAwareMemory, FailureConditionType
from intelligence.action_identity import ActionIdentity


def test_auth_failure_blocks_action_until_capability_acquired():
    mem = FailureAwareMemory()
    
    # Action fails with HTTP 401
    rec = mem.record_failure(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/admin/users"},
        target="127.0.0.1",
        status_code=401,
        error_message="Unauthorized: Token required",
    )
    assert rec.condition_type == FailureConditionType.REQUIRES_AUTH
    
    canon_key = ActionIdentity.generate_canonical_key("http_request", {"url": "http://127.0.0.1:8080/admin/users"}, "127.0.0.1").canonical_key

    # 1. Check with ANONYMOUS capability -> blocked
    is_blocked, reason = mem.is_action_blocked(canon_key, current_capabilities={"ANONYMOUS"})
    assert is_blocked is True
    assert "Missing AUTHENTICATED capability" in reason

    # 2. Acquire AUTHENTICATED capability -> unblocked
    unblocked = mem.notify_capability_acquired("AUTHENTICATED")
    assert canon_key in unblocked

    is_blocked, reason = mem.is_action_blocked(canon_key, current_capabilities={"AUTHENTICATED"})
    assert is_blocked is False


def test_admin_privilege_failure():
    mem = FailureAwareMemory()
    mem.record_failure(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/superadmin"},
        target="127.0.0.1",
        status_code=403,
        error_message="Forbidden: Requires admin role",
    )
    canon_key = ActionIdentity.generate_canonical_key("http_request", {"url": "http://127.0.0.1:8080/superadmin"}, "127.0.0.1").canonical_key

    # Authenticated regular user is still blocked
    is_blocked, _ = mem.is_action_blocked(canon_key, current_capabilities={"AUTHENTICATED"})
    assert is_blocked is True

    # Admin unblocks
    mem.notify_capability_acquired("ADMIN_PRIVILEGE")
    is_blocked, _ = mem.is_action_blocked(canon_key, current_capabilities={"ADMIN_PRIVILEGE", "AUTHENTICATED"})
    assert is_blocked is False
