"""
Tests for form structure extraction, CSRF detection, and login classification.
"""

from security_agent.browser.dom import DOMReducer


def test_form_discovery_and_classification():
    html = """
    <html>
    <body>
        <!-- Login Form without CSRF -->
        <form id="auth_box" action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Sign In" />
        </form>

        <!-- Profile Update Form with CSRF -->
        <form id="profile_form" action="/user/update" method="POST">
            <input type="hidden" name="csrfmiddlewaretoken" value="abc123csrf" />
            <input type="email" name="email" value="admin@local" />
            <input type="file" name="avatar" />
            <button type="submit">Save</button>
        </form>
    </body>
    </html>
    """

    snap = DOMReducer.reduce(html, url="http://target.local/")

    assert len(snap.forms) == 2

    # Form 1
    f1 = snap.forms[0]
    assert f1.form_id == "auth_box"
    assert f1.is_login_form is True
    assert f1.has_csrf is False

    # Form 2
    f2 = snap.forms[1]
    assert f2.form_id == "profile_form"
    assert f2.is_login_form is False
    assert f2.has_csrf is True
    assert any(fld.type == "file" for fld in f2.fields)
