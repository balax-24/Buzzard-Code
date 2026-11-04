"""
Phase 15 Tests: Surface Coverage Engine.
Verifies calculation of authorized surface coverage metrics.
"""

from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus, EdgeKind
from intelligence.frontier import FrontierEngine


def test_surface_coverage_calculation():
    graph = AttackGraph()

    # 3 services discovered
    h = graph.add_node(NodeKind.HOST, "127.0.0.1")
    s1 = graph.add_node(NodeKind.SERVICE, "127.0.0.1:80", parent_id=h.node_id, edge_kind=EdgeKind.DISCOVERED_ON)
    s2 = graph.add_node(NodeKind.SERVICE, "127.0.0.1:443", parent_id=h.node_id, edge_kind=EdgeKind.DISCOVERED_ON)
    s3 = graph.add_node(NodeKind.SERVICE, "127.0.0.1:8080", parent_id=h.node_id, edge_kind=EdgeKind.DISCOVERED_ON)

    # Mark 2 as explored/exhausted
    s1.status = NodeStatus.EXPLORED
    s2.status = NodeStatus.EXHAUSTED
    # s3 remains PENDING

    rep = FrontierEngine.calculate_surface_coverage(graph)
    # Total assets = 1 host + 3 services = 4 assets
    # Investigated = s1 (EXPLORED), s2 (EXHAUSTED) -> 2 explored services (+ host if investigated)
    assert rep.total_discovered_assets >= 3
    assert rep.unexplored_assets_count >= 1
    assert 0.0 < rep.coverage_percentage <= 100.0
