"""
Tests for AttackGraph application-surface nodes: PAGE, FORM, API_ENDPOINT, WEBSOCKET, and edges.
"""

from agent.assessment_state import AssessmentState, AssessmentContext, ServiceRecord
from intelligence.attack_graph import AttackGraph, NodeKind, EdgeKind
from browser.dom import DOMReducer


def test_attack_graph_application_surface_expansion():
    html = """
    <html>
    <head>
        <script>
            fetch('/api/v1/metrics');
            const ws = new WebSocket('ws://target.local:8080/events');
        </script>
    </head>
    <body>
        <form id="admin_form" action="/admin/execute" method="POST">
            <input type="text" name="cmd" />
            <button type="submit">Run</button>
        </form>
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

    snap = DOMReducer.reduce(html, url="http://target.local:8080/dashboard", evidence_ids=["EVI-SNAP-01"])
    state.record_dom_snapshot(snap)

    graph = AttackGraph()
    graph.sync_from_state(state)

    # Verify PAGE node
    page_nodes = graph.get_nodes_by_kind(NodeKind.PAGE)
    assert len(page_nodes) >= 1
    assert any("http://target.local:8080/dashboard" in p.label for p in page_nodes)

    # Verify FORM node
    form_nodes = graph.get_nodes_by_kind(NodeKind.FORM)
    assert len(form_nodes) >= 1
    assert any("admin_form" in f.label for f in form_nodes)

    # Verify API_ENDPOINT node
    api_nodes = graph.get_nodes_by_kind(NodeKind.API_ENDPOINT)
    assert len(api_nodes) >= 1
    assert any("metrics" in a.label for a in api_nodes)

    # Verify WEBSOCKET node
    ws_nodes = graph.get_nodes_by_kind(NodeKind.WEBSOCKET)
    assert len(ws_nodes) >= 1
    assert any("events" in w.label for w in ws_nodes)

    # Check edges
    edges = list(graph.edges)
    assert any(e.kind == EdgeKind.REVEALS for e in edges)
    assert any(e.kind == EdgeKind.CALLS for e in edges)
