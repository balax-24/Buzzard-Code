"""
Tests for evidence ingestion and state convergence loops with browser observations.
"""

from security_agent.agent.assessment_state import AssessmentState, AssessmentContext
from security_agent.agent.tool_executor import ToolExecutionResult
from security_agent.intelligence.evidence_ingestor import EvidenceIngestor


def test_browser_evidence_ingestion_and_state_convergence():
    state = AssessmentState(context=AssessmentContext(target="target.local"))
    ingestor = EvidenceIngestor()

    browser_html = """
    <html>
    <head><title>Admin Panel</title></head>
    <body>
        <a href="/admin/users">User Management</a>
        <a href="/admin/logs">System Logs</a>
        <form id="backup_form" action="/admin/backup" method="POST">
            <input type="text" name="dest" value="/var/backups" />
            <button type="submit">Backup</button>
        </form>
    </body>
    </html>
    """

    res = ToolExecutionResult(
        success=True,
        tool_name="browser.snapshot",
        arguments={"url": "http://target.local/admin"},
        raw_output=browser_html,
        exit_code=0
    )

    item = ingestor.ingest(
        tool_result=res,
        state=state
    )

    assert item.status == "VERIFIED"
    assert "snapshot_id" in item.structured_data
    assert len(state.dom_snapshots) == 1
    assert len(state.forms) == 1
    assert any("admin/backup" in ep for ep in state.http_endpoints)
    assert any("admin/users" in ep for ep in state.http_endpoints)
    assert any("admin/logs" in ep for ep in state.http_endpoints)
