import pytest
from security_agent.agent.assessment_state import AssessmentContext, AssessmentState
from security_agent.intelligence.attack_graph import AttackGraph, NodeKind
from security_agent.persistence.engagement_store import EngagementStore

def test_attack_graph_persistence_and_sync(tmp_path):
    store = EngagementStore(base_dir=tmp_path)
    state = AssessmentState(context=AssessmentContext(target="target-g", scope=["target-g"]))
    graph = AttackGraph()
    graph.add_node(NodeKind.HOST, "192.168.1.10")
    graph.add_node(NodeKind.SERVICE, "192.168.1.10:80/tcp")

    store.checkpoint("eng-g", state, graph=graph)
    _, loaded_graph, _, _, _, _ = store.load("eng-g")

    assert len(loaded_graph.nodes) == 2
    assert "192.168.1.10" in [n.label for n in loaded_graph.nodes.values()]
