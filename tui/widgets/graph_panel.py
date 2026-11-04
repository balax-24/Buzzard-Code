"""
Live Attack Graph Panel for Qwythos TUI.
Visualizes the active AttackGraph as an interactive Tree widget.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Tree, Static
from textual.containers import Vertical
from rich.text import Text

from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus


class AttackGraphTree(Widget):
    """
    Live Attack Graph Tree view widget.
    """

    DEFAULT_CSS = """
    AttackGraphTree {
        height: 100%;
        background: #181825;
        border-right: heavy #313244;
        padding: 0 1;
    }
    """

    def __init__(self, graph: AttackGraph | None = None, id: str | None = None):
        super().__init__(id=id)
        self.graph = graph or AttackGraph()

    def compose(self) -> ComposeResult:
        self.tree_widget: Tree[dict] = Tree("🎯 Attack Surface", id="attack_graph_tree")
        self.tree_widget.root.expand()
        self.rebuild_tree()
        yield self.tree_widget

    def rebuild_tree(self) -> None:
        if not hasattr(self, "tree_widget"):
            return
        self.tree_widget.root.remove_children()

        # Group nodes by kind
        hosts = [n for n in self.graph.nodes.values() if n.kind == NodeKind.HOST]
        services = [n for n in self.graph.nodes.values() if n.kind == NodeKind.SERVICE]
        endpoints = [n for n in self.graph.nodes.values() if n.kind == NodeKind.ENDPOINT]
        capabilities = [n for n in self.graph.nodes.values() if n.kind == NodeKind.CAPABILITY]
        findings = [n for n in self.graph.nodes.values() if n.kind == NodeKind.FINDING]
        hypotheses = [n for n in self.graph.nodes.values() if n.kind == NodeKind.HYPOTHESIS]

        # Hosts & Services
        for h in hosts:
            h_branch = self.tree_widget.root.add(f"🌐 Host: {h.label}", data={"node": h})
            h_branch.expand()
            for s in services:
                s_branch = h_branch.add(f"🔌 Service: {s.label}", data={"node": s})
                s_branch.expand()
                for ep in endpoints:
                    s_branch.add_leaf(f"🔗 {ep.label}", data={"node": ep})

        # Findings
        if findings:
            f_branch = self.tree_widget.root.add(f"🚨 Verified Findings ({len(findings)})")
            f_branch.expand()
            for f in findings:
                f_branch.add_leaf(f"• {f.label}", data={"node": f})

        # Capabilities
        if capabilities:
            c_branch = self.tree_widget.root.add(f"🔑 Capabilities ({len(capabilities)})")
            c_branch.expand()
            for cap in capabilities:
                c_branch.add_leaf(f"• {cap.label}", data={"node": cap})

        # Hypotheses
        if hypotheses:
            hyp_branch = self.tree_widget.root.add(f"💡 Hypotheses ({len(hypotheses)})")
            for hyp in hypotheses:
                hyp_branch.add_leaf(f"• {hyp.label}", data={"node": hyp})

    def update_graph(self, graph: AttackGraph) -> None:
        self.graph = graph
        self.rebuild_tree()
