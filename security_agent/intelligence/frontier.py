"""
Phase 15: Attack Graph Frontier & Surface Coverage Engine.

Exposes an explicit 7-stage lifecycle frontier over the AttackGraph:
  DISCOVERED -> UNEXPLORED -> REACHABLE -> HYPOTHESIZED -> VALIDATED -> VERIFIED -> EXHAUSTED

Enables frontier-based planning so that the agent systematically targets
unexplored and reachable surfaces rather than re-probing exhausted assets.
Also computes authorized surface coverage metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from security_agent.intelligence.attack_graph import AttackGraph, GraphNode, NodeKind, NodeStatus


class FrontierStage(str, Enum):
    DISCOVERED = "DISCOVERED"       # Node exists in graph
    UNEXPLORED = "UNEXPLORED"       # Node has not been probed yet
    REACHABLE = "REACHABLE"         # Node has an accessible path and required capabilities
    HYPOTHESIZED = "HYPOTHESIZED"   # Node has an active vulnerability hypothesis
    VALIDATED = "VALIDATED"         # Vulnerability hypothesis confirmed
    VERIFIED = "VERIFIED"           # Indepedently verified finding
    EXHAUSTED = "EXHAUSTED"         # Thoroughly probed; no further productive actions remain


@dataclass
class FrontierNodeView:
    """Detailed view of a graph node within the exploration frontier."""
    node_id: str
    label: str
    kind: NodeKind
    stage: FrontierStage
    priority: int = 5
    required_capabilities: List[str] = field(default_factory=list)
    available_capabilities: List[str] = field(default_factory=list)
    is_reachable: bool = True
    probes_conducted: int = 0
    hypotheses_count: int = 0
    findings_count: int = 0


@dataclass
class SurfaceCoverageReport:
    """Coverage metrics over authorized discovery and investigation surfaces."""
    total_discovered_assets: int
    unexplored_assets_count: int
    investigated_assets_count: int
    exhausted_assets_count: int
    coverage_percentage: float
    reachable_unexplored_count: int
    verified_findings_count: int


class FrontierEngine:
    """
    Computes graph frontier status, reachable unexplored assets, and surface coverage.
    """

    @classmethod
    def classify_node_stage(
        cls,
        node: GraphNode,
        graph: AttackGraph,
        current_capabilities: Set[str],
    ) -> FrontierStage:
        """Determines the exact frontier stage of a graph node."""
        if node.status == NodeStatus.EXHAUSTED:
            return FrontierStage.EXHAUSTED

        # Check outgoing edges from this node
        has_verified_finding = False
        has_hypothesis = False
        has_validated = False

        outgoing_edges = [e for e in graph.edges if e.from_node_id == node.node_id]
        for edge in outgoing_edges:
            target_node = graph.nodes.get(edge.to_node_id)
            if target_node:
                if target_node.kind == NodeKind.FINDING:
                    has_verified_finding = True
                elif target_node.kind == NodeKind.HYPOTHESIS:
                    has_hypothesis = True
                    if target_node.status == NodeStatus.EXPLORED:
                        has_validated = True

        if has_verified_finding:
            return FrontierStage.VERIFIED
        if has_validated:
            return FrontierStage.VALIDATED
        if has_hypothesis:
            return FrontierStage.HYPOTHESIZED

        if node.status == NodeStatus.PENDING:
            # Check reachability / capabilities
            req_caps = set(node.metadata.get("required_capabilities", []))
            if not req_caps or req_caps.issubset(current_capabilities):
                return FrontierStage.REACHABLE
            return FrontierStage.UNEXPLORED

        if node.status == NodeStatus.EXPLORED:
            return FrontierStage.EXHAUSTED

        return FrontierStage.DISCOVERED

    @classmethod
    def get_frontier_views(
        cls,
        graph: AttackGraph,
        current_capabilities: Optional[Set[str]] = None,
    ) -> List[FrontierNodeView]:
        """Returns frontier views for all nodes in the AttackGraph."""
        caps = current_capabilities or set()
        views: List[FrontierNodeView] = []

        for node in graph.nodes.values():
            stage = cls.classify_node_stage(node, graph, caps)
            req_caps = node.metadata.get("required_capabilities", [])
            is_reach = not req_caps or set(req_caps).issubset(caps)

            outgoing = [e for e in graph.edges if e.from_node_id == node.node_id]
            hyp_count = len([e for e in outgoing if graph.nodes.get(e.to_node_id) and graph.nodes.get(e.to_node_id).kind == NodeKind.HYPOTHESIS])
            finding_count = len([e for e in outgoing if graph.nodes.get(e.to_node_id) and graph.nodes.get(e.to_node_id).kind == NodeKind.FINDING])

            views.append(
                FrontierNodeView(
                    node_id=node.node_id,
                    label=node.label,
                    kind=node.kind,
                    stage=stage,
                    priority=node.metadata.get("priority", 5),
                    required_capabilities=req_caps,
                    available_capabilities=list(caps),
                    is_reachable=is_reach,
                    probes_conducted=node.metadata.get("probes_count", 0),
                    hypotheses_count=hyp_count,
                    findings_count=finding_count,
                )
            )

        return views

    @classmethod
    def get_unexplored_reachable_nodes(
        cls,
        graph: AttackGraph,
        current_capabilities: Optional[Set[str]] = None,
    ) -> List[GraphNode]:
        """Returns graph nodes that are discovered and reachable but not yet investigated."""
        caps = current_capabilities or set()
        candidates: List[GraphNode] = []

        for node in graph.nodes.values():
            if node.kind in (NodeKind.FINDING, NodeKind.CAPABILITY, NodeKind.SESSION):
                continue
            stage = cls.classify_node_stage(node, graph, caps)
            if stage in (FrontierStage.REACHABLE, FrontierStage.UNEXPLORED, FrontierStage.HYPOTHESIZED):
                candidates.append(node)

        # Sort by priority (higher priority first)
        candidates.sort(key=lambda n: n.metadata.get("priority", 5), reverse=True)
        return candidates

    @classmethod
    def calculate_surface_coverage(
        cls,
        graph: AttackGraph,
        current_capabilities: Optional[Set[str]] = None,
    ) -> SurfaceCoverageReport:
        """Calculates authorized surface coverage percentage across discovered assets."""
        caps = current_capabilities or set()
        views = cls.get_frontier_views(graph, caps)

        # Filter to actual asset nodes (Host, Service, Endpoint, Page, Form, API)
        asset_kinds = {
            NodeKind.HOST,
            NodeKind.SERVICE,
            NodeKind.ENDPOINT,
            NodeKind.PAGE,
            NodeKind.FORM,
            NodeKind.API_ENDPOINT,
            NodeKind.WEBSOCKET,
        }
        asset_views = [v for v in views if v.kind in asset_kinds]

        total_assets = len(asset_views)
        if total_assets == 0:
            return SurfaceCoverageReport(
                total_discovered_assets=0,
                unexplored_assets_count=0,
                investigated_assets_count=0,
                exhausted_assets_count=0,
                coverage_percentage=100.0,
                reachable_unexplored_count=0,
                verified_findings_count=0,
            )

        unexplored = sum(1 for v in asset_views if v.stage in (FrontierStage.UNEXPLORED, FrontierStage.REACHABLE))
        exhausted = sum(1 for v in asset_views if v.stage == FrontierStage.EXHAUSTED)
        investigated = total_assets - unexplored
        reachable_unexplored = sum(1 for v in asset_views if v.stage == FrontierStage.REACHABLE)
        verified_count = sum(1 for v in views if v.kind == NodeKind.FINDING or v.stage == FrontierStage.VERIFIED)

        cov_pct = (investigated / total_assets) * 100.0

        return SurfaceCoverageReport(
            total_discovered_assets=total_assets,
            unexplored_assets_count=unexplored,
            investigated_assets_count=investigated,
            exhausted_assets_count=exhausted,
            coverage_percentage=cov_pct,
            reachable_unexplored_count=reachable_unexplored,
            verified_findings_count=verified_count,
        )
