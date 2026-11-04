"""
Tests for DOMSnapshot structure, field extraction, and serialization.
"""

from security_agent.browser.dom import (
    FormField,
    FormRecord,
    LinkRecord,
    ScriptRecord,
    APICandidate,
    WebSocketEndpoint,
    DOMSnapshot,
    DOMReducer,
)


def test_dom_snapshot_structure_and_serialization():
    sample_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Portal - Dashboard</title>
        <script src="/static/app.js"></script>
        <script>
            fetch('/api/v1/user/profile');
            const ws = new WebSocket('ws://localhost:8080/notifications');
        </script>
    </head>
    <body>
        <h1>Welcome, Administrator</h1>
        <a href="/admin/settings">Admin Settings</a>
        <a href="https://external.com/docs" target="_blank">Docs</a>
        
        <form id="search_form" action="/search" method="GET">
            <input type="text" name="q" placeholder="Search..." required />
            <button type="submit">Search</button>
        </form>

        <form id="transfer_form" action="/transfer" method="POST">
            <input type="hidden" name="csrf_token" value="sec_12345" />
            <input type="number" name="amount" value="100" />
            <input type="text" name="recipient" />
            <button type="submit">Transfer</button>
        </form>
    </body>
    </html>
    """

    snap = DOMReducer.reduce(
        html_content=sample_html,
        url="http://localhost:8080/dashboard",
        status_code=200,
        evidence_ids=["EVI-SNAP-01"]
    )

    assert snap.title == "Vulnerable Portal - Dashboard"
    assert snap.url == "http://localhost:8080/dashboard"
    assert len(snap.forms) == 2
    assert len(snap.links) == 2
    assert any(a.url == "http://localhost:8080/api/v1/user/profile" for a in snap.api_candidates)
    assert any("ws://localhost:8080/notifications" in w.url for w in snap.websockets)

    # Verify form 1
    f1 = snap.forms[0]
    assert f1.form_id == "search_form"
    assert f1.method == "GET"
    assert f1.action == "http://localhost:8080/search"
    assert f1.has_csrf is False

    # Verify form 2
    f2 = snap.forms[1]
    assert f2.form_id == "transfer_form"
    assert f2.method == "POST"
    assert f2.has_csrf is True

    # Test discovered URLs helper
    discovered = snap.get_discovered_urls()
    assert "http://localhost:8080/admin/settings" in discovered
    assert "http://localhost:8080/search" in discovered
    assert "http://localhost:8080/api/v1/user/profile" in discovered

    # Test to_dict
    data = snap.to_dict()
    assert data["url"] == "http://localhost:8080/dashboard"
    assert len(data["forms"]) == 2
