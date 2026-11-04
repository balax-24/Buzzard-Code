"""
Phase 15 Tests: Attack Graph Frontier Engine.
Verifies node lifecycle stages and retrieval of reachable unexplored assets.
"""

from security_agent.intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus, EdgeKind
from security_agent.intelligence.frontier import FrontierEngine, FrontierStage


def test_frontier_stage_classification():
    graph = AttackGraph()
    
    # 1. Discovered host
    h1 = graph.add_node(NodeKind.HOST, "127.0.0.1")
    # 2. Open service (Reachable, unexplored)
    s1 = graph.add_node(NodeKind.SERVICE, "127.0.0.1:80", parent_id=h1.node_id, edge_kind=EdgeKind.DISCOVERED_ON)
    # 3. Endpoint with active hypothesis
    ep1 = graph.add_node(NodeKind.ENDPOINT, "http://127.0.0.1:80/login", parent_id=s1.node_id, edge_kind=EdgeKind.ENDPOINT_OF)
    hyp1 = graph.add_node(NodeKind.HYPOTHESIS, "SQLi on /login", parent_id=ep1.node_id, edge_kind=EdgeKind.SPAWNS)
    # 4. Verified finding
    f1 = graph.add_node(NodeKind.FINDING, "SQLi Confirmed", parent_id=ep1.node_id, edge_kind=EdgeKind.EXPLOITS)
    # 5. Exhausted service
    s2 = graph.add_node(NodeKind.SERVICE, "127.0.0.1:22", parent_id=h1.node_id, edge_kind=EdgeKind.DISCOVERED_ON)
    s2.status = NodeStatus.EXHAUSTED

    # Assert stages
    assert FrontierEngine.classify_node_stage(s1, graph, set()) == FrontierStage.REACHABLE
    assert FrontierEngine.classify_node_stage(ep1, graph, set()) == FrontierStage.VERIFIED
    assert FrontierEngine.classify_node_stage(s2, graph, set()) == FrontierStage.EXHAUSTED

    # Get unexplored reachable nodes
    unexplored = FrontierEngine.get_unexplored_reachable_nodes(graph, set())
    unexplored_ids = [n.node_id for n in unexplored]
    assert s1.node_id in unexplored_ids
    assert s2.node_id not in unexplored_ids
