"""
Tests for multi-role browser context isolation and session boundaries.
"""

from state.session_store import SessionStore, Cookie
from browser import BrowserEngine


def test_browser_multi_role_session_isolation():
    store = SessionStore()

    # Create admin session
    admin_sess = store.create_session(target_origin="target.local", role="admin")
    admin_sess.add_cookie(Cookie(name="session_token", value="ADMIN_SECRET_KEY", domain="target.local"))

    # Create unprivileged user session
    user_sess = store.create_session(target_origin="target.local", role="user")
    user_sess.add_cookie(Cookie(name="session_token", value="USER_SECRET_KEY", domain="target.local"))

    engine = BrowserEngine(headless=True)
    engine.launch()

    admin_ctx = engine.new_context(role="admin", target_origin="http://target.local")
    user_ctx = engine.new_context(role="user", target_origin="http://target.local")

    admin_ctx.inject_session_store(store, "http://target.local", role="admin")
    user_ctx.inject_session_store(store, "http://target.local", role="user")

    # Contexts must have distinct IDs and roles
    assert admin_ctx.role == "admin"
    assert user_ctx.role == "user"
    assert admin_ctx.context_id != user_ctx.context_id

    # Verify session store isolation
    admin_auth = store.get_request_auth_context("http://target.local", role="admin")
    user_auth = store.get_request_auth_context("http://target.local", role="user")

    assert admin_auth["cookies"]["session_token"] == "ADMIN_SECRET_KEY"
    assert user_auth["cookies"]["session_token"] == "USER_SECRET_KEY"

    admin_ctx.close()
    user_ctx.close()
    engine.close()
