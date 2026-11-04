from agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord
from intelligence.hypothesis_engine import HypothesisEngine
from browser.dom import DOMReducer


def test_browser_hypothesis_proposals():
    html = """
    <html>
    <body>
        <!-- Authentication Form -->
        <form id="login_form" action="http://target.local:8080/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Sign In</button>
        </form>

        <!-- File Upload Form -->
        <form id="upload_form" action="http://target.local:8080/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file" />
            <button type="submit">Upload</button>
        </form>

        <!-- Insecure State Changing Form without CSRF -->
        <form id="delete_form" action="http://target.local:8080/account/delete" method="POST">
            <button type="submit">Delete Account</button>
        </form>

        <script>
            const ws = new WebSocket("ws://target.local:8080/notifications");
        </script>
    </body>
    </html>
    """

    state = AssessmentState(context=AssessmentContext(target="target.local"))
    state.services["target.local:8080/tcp"] = ServiceRecord(
        host="target.local",
        port=8080,
        protocol="tcp",
        service="http"
    )

    snap = DOMReducer.reduce(html, url="http://target.local:8080/", evidence_ids=["EVI-SNAP-01"])
    state.record_dom_snapshot(snap)

    engine = HypothesisEngine()
    proposals = engine.propose_next_actions(state, max_proposals=20)

    vuln_types = [p.vulnerability_type for p in proposals]

    # Verify auth bypass hypothesis proposed for login form
    assert "auth_bypass_sqli" in vuln_types
    # Verify file upload hypothesis proposed
    assert "unrestricted_file_upload" in vuln_types
    # Verify csrf hypothesis proposed
    assert "csrf" in vuln_types
    # Verify websocket hijacking hypothesis proposed
    assert "websocket_hijacking" in vuln_types
