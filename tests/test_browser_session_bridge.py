"""
Tests for BrowserContext <-> SessionStore bi-directional synchronization.
"""

from state.session_store import SessionStore, Cookie, BearerToken
from browser import BrowserContext


def test_browser_session_injection_and_export():
    store = SessionStore()
    sess = store.create_session(target_origin="target.local", role="admin")
    sess.add_cookie(Cookie(name="admin_session", value="tok_sec_999", domain="target.local", path="/"))
    sess.add_bearer_token(BearerToken(token="jwt_secret_token_abc", origin="target.local"))

    ctx = BrowserContext(role="admin", target_origin="http://target.local")

    # Inject store into context
    ctx.inject_session_store(store, "http://target.local/admin")

    # Export cookies back to store
    exported_sess = ctx.export_cookies_to_session_store(store, "http://target.local/admin", role="admin", evidence_id="EVI-EXP-01")
    assert exported_sess.session_id == sess.session_id
    assert "admin_session" in exported_sess.cookies
    assert exported_sess.cookies["admin_session"].value == "tok_sec_999"
    assert "EVI-EXP-01" in exported_sess.source_evidence_ids
