"""
Attack Graph — Persistent, recursive assessment work model.

The AttackGraph is the authoritative data structure that tracks:
  - AssetNodes  : discovered targets (hosts, services, endpoints)
  - FindingNodes: verified vulnerabilities / findings
  - AttackEdges : directed attack-path relationships between nodes

Key properties:
  1. Findings CREATE new work rather than terminating the assessment.
  2. The graph is the single source of truth for "what remains unexplored".
  3. The CompletionEngine queries the graph to determine whether assessment may stop.
  4. The HypothesisEngine queries the graph to propose next candidate actions.
  5. AssessmentState writes into the graph; the graph never writes back into state.

Node lifecycle:
  PENDING → IN_PROGRESS → EXPLORED (finding discovered) → CHILD_SPAWNED
                       ↘ EXHAUSTED  (no finding after full exploration)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Node / Edge types
# ---------------------------------------------------------------------------

class NodeKind(str, Enum):
    HOST            = "HOST"            # A network host or IP
    SERVICE         = "SERVICE"         # A network service (port + protocol)
    PORT            = "PORT"            # A specific transport port
    PROTOCOL        = "PROTOCOL"        # Protocol layer
    APPLICATION     = "APPLICATION"     # Application instance
    ENDPOINT        = "ENDPOINT"        # An HTTP endpoint / URL path
    PAGE            = "PAGE"            # A browser-rendered application page
    FORM            = "FORM"            # An HTML input form surface
    INPUT           = "INPUT"           # An individual input / parameter control
    SCRIPT          = "SCRIPT"          # A client-side JavaScript asset
    API             = "API"             # Formal API surface
    API_ENDPOINT    = "API_ENDPOINT"    # A discovered dynamic REST / GraphQL API endpoint
    WEBSOCKET       = "WEBSOCKET"       # A WebSocket duplex endpoint (ws://, wss://)
    NETWORK_REQUEST = "NETWORK_REQUEST" # A captured browser network request event
    FILE            = "FILE"            # Local/remote accessible file or config
    CREDENTIAL      = "CREDENTIAL"      # Extracted username/password/hash
    FINDING         = "FINDING"         # A verified vulnerability / security finding
    HYPOTHESIS      = "HYPOTHESIS"      # An unconfirmed hypothesis (not yet a finding)
    CAPABILITY      = "CAPABILITY"      # A verified operational capability (AUTHENTICATED, FILE_READ, etc.)
    SESSION         = "SESSION"         # An active authenticated session (cookie/bearer/csrf)
    BROWSER_SESSION = "BROWSER_SESSION" # An isolated browser automation context


class NodeStatus(str, Enum):
    PENDING     = "PENDING"      # Discovered, not yet investigated
    IN_PROGRESS = "IN_PROGRESS"  # Actively being investigated this iteration
    EXPLORED    = "EXPLORED"     # Fully investigated; may have produced children
    EXHAUSTED   = "EXHAUSTED"    # Fully investigated; no children spawned


class EdgeKind(str, Enum):
    DISCOVERED_ON      = "DISCOVERED_ON"      # SERVICE discovered on HOST
    ENDPOINT_OF        = "ENDPOINT_OF"        # ENDPOINT belongs to SERVICE
    EXPLOITS           = "EXPLOITS"           # FINDING exploits SERVICE/ENDPOINT
    ENABLES            = "ENABLES"            # FINDING/CAPABILITY enables further attack on another node
    INVALIDATES        = "INVALIDATES"        # FINDING invalidates a hypothesis
    SPAWNS             = "SPAWNS"             # A node spawns a child node for investigation
    GRANTS             = "GRANTS"             # FINDING or tool action grants a CAPABILITY
    REQUIRES           = "REQUIRES"           # Node or hypothesis requires a CAPABILITY
    AUTHENTICATED_BY   = "AUTHENTICATED_BY"   # Endpoint / request enabled by session
    LINKS_TO           = "LINKS_TO"           # Page links to another page/endpoint
    SUBMITS_TO         = "SUBMITS_TO"         # Form posts or submits to an action endpoint
    CALLS              = "CALLS"              # Script or page calls an API endpoint
    LOADS              = "LOADS"              # Page loads a script or resource
    REVEALS            = "REVEALS"            # Page or action reveals an endpoint / form / route
    REQUESTS           = "REQUESTS"           # Page initiates a network request
    REDIRECTS_TO       = "REDIRECTS_TO"       # Endpoint redirects to another endpoint


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """A single node in the attack graph."""
    node_id: str
    kind: NodeKind
    label: str                          # Human-readable label
    status: NodeStatus = NodeStatus.PENDING
    target: str = ""                    # Target host / IP / domain
    scope: str = ""                     # Target scope definition
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    discovered_at: float = field(default_factory=time.time)
    explored_at: Optional[float] = None
    priority: int = 50                  # 0 = highest, 100 = lowest
    exploration_attempts: int = 0
    max_exploration_attempts: int = 3   # After this, mark EXHAUSTED
    parent: Optional[str] = None        # Parent node_id
    depth: int = 0                      # Recursive tree depth

    def mark_in_progress(self) -> None:
        self.status = NodeStatus.IN_PROGRESS
        self.exploration_attempts += 1
        self.last_updated = time.time()

    def mark_explored(self) -> None:
        self.status = NodeStatus.EXPLORED
        self.explored_at = time.time()
        self.last_updated = time.time()

    def mark_exhausted(self) -> None:
        self.status = NodeStatus.EXHAUSTED
        self.explored_at = time.time()
        self.last_updated = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "status": self.status.value,
            "target": self.target,
            "scope": self.scope,
            "metadata": self.metadata,
            "evidence_ids": self.evidence_ids,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "discovered_at": self.discovered_at,
            "explored_at": self.explored_at,
            "priority": self.priority,
            "exploration_attempts": self.exploration_attempts,
            "parent": self.parent,
            "depth": self.depth,
        }


@dataclass
class GraphEdge:
    """A directed edge in the attack graph with complete evidence provenance."""
    edge_id: str
    from_node_id: str
    to_node_id: str
    kind: EdgeKind
    label: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    reason: str = ""

    @property
    def source(self) -> str:
        return self.from_node_id

    @property
    def destination(self) -> str:
        return self.to_node_id

    @property
    def relationship(self) -> EdgeKind:
        return self.kind

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "source": self.source,
            "destination": self.destination,
            "kind": self.kind.value,
            "relationship": self.relationship.value,
            "label": self.label,
            "evidence_ids": self.evidence_ids,
            "reason": self.reason,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }



# ---------------------------------------------------------------------------
# Attack Graph
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    Persistent, recursive attack work model.

    The graph grows during assessment:
      - nmap discovers ports → SERVICE nodes added (PENDING)
      - Probe fingerprints a service → SERVICE marked EXPLORED, ENDPOINT nodes spawn
      - Finding verified → FINDING node added, ENABLES edges created to derived children
      - Children = new PENDING nodes ready for the next iteration

    This ensures the loop continues as long as PENDING nodes remain.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}      # node_id → GraphNode
        self.edges: List[GraphEdge] = []
        self._label_index: Dict[str, str] = {}     # label → node_id (for dedup)

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def add_node(
        self,
        kind: NodeKind,
        label: str,
        metadata: Optional[Dict[str, Any]] = None,
        evidence_ids: Optional[List[str]] = None,
        priority: int = 50,
        parent_id: Optional[str] = None,
        edge_kind: EdgeKind = EdgeKind.SPAWNS,
        node_id: Optional[str] = None,
        target: str = "",
        scope: str = "",
        depth: Optional[int] = None,
    ) -> GraphNode:
        """
        Adds a node if it doesn't already exist (label-deduplicated).
        Optionally creates a parent → child edge with provenance tracking.
        Returns the (potentially existing) node.
        """
        if label in self._label_index:
            existing = self.nodes[self._label_index[label]]
            if evidence_ids:
                existing.evidence_ids.extend(e for e in evidence_ids if e not in existing.evidence_ids)
            if target and not existing.target:
                existing.target = target
            if scope and not existing.scope:
                existing.scope = scope
            existing.last_updated = time.time()
            return existing

        node_id = node_id or f"{kind.value}-{uuid.uuid4().hex[:8]}"

        computed_depth = 0
        if depth is not None:
            computed_depth = depth
        elif parent_id and parent_id in self.nodes:
            computed_depth = self.nodes[parent_id].depth + 1

        node = GraphNode(
            node_id=node_id,
            kind=kind,
            label=label,
            target=target,
            scope=scope,
            metadata=metadata or {},
            evidence_ids=list(evidence_ids or []),
            priority=priority,
            parent=parent_id,
            depth=computed_depth,
        )
        self.nodes[node_id] = node
        self._label_index[label] = node_id

        if parent_id and parent_id in self.nodes:
            self.add_edge(
                parent_id,
                node_id,
                edge_kind,
                evidence_ids=list(evidence_ids or []),
                reason=f"Spawned from parent {parent_id}",
            )

        return node

    def add_edge(
        self,
        from_id: str,
        to_id: str,
        kind: EdgeKind,
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        evidence_ids: Optional[List[str]] = None,
        reason: str = "",
    ) -> GraphEdge:
        """Adds a directed edge. Deduplicates by (from, to, kind)."""
        edge_eids = list(evidence_ids or [])
        if not edge_eids and from_id in self.nodes:
            edge_eids = list(self.nodes[from_id].evidence_ids)

        for e in self.edges:
            if e.from_node_id == from_id and e.to_node_id == to_id and e.kind == kind:
                if edge_eids:
                    for eid in edge_eids:
                        if eid not in e.evidence_ids:
                            e.evidence_ids.append(eid)
                if reason and not e.reason:
                    e.reason = reason
                return e
        edge = GraphEdge(
            edge_id=f"EDGE-{uuid.uuid4().hex[:8]}",
            from_node_id=from_id,
            to_node_id=to_id,
            kind=kind,
            label=label,
            evidence_ids=edge_eids,
            metadata=metadata or {},
            reason=reason,
        )
        self.edges.append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_node_by_label(self, label: str) -> Optional[GraphNode]:
        nid = self._label_index.get(label)
        return self.nodes.get(nid) if nid else None

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def pending_nodes(self, kind: Optional[NodeKind] = None) -> List[GraphNode]:
        """Returns all PENDING nodes, optionally filtered by kind, sorted by priority."""
        nodes = [n for n in self.nodes.values() if n.status == NodeStatus.PENDING]
        if kind is not None:
            nodes = [n for n in nodes if n.kind == kind]
        return sorted(nodes, key=lambda n: n.priority)

    def in_progress_nodes(self) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.status == NodeStatus.IN_PROGRESS]

    def explored_nodes(self, kind: Optional[NodeKind] = None) -> List[GraphNode]:
        nodes = [n for n in self.nodes.values() if n.status == NodeStatus.EXPLORED]
        if kind is not None:
            nodes = [n for n in nodes if n.kind == kind]
        return nodes

    def finding_nodes(self) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.kind == NodeKind.FINDING]

    def get_nodes_by_kind(self, kind: NodeKind) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def children_of(self, node_id: str) -> List[GraphNode]:
        """Returns all direct children of a node across all edge types."""
        child_ids: Set[str] = set()
        for e in self.edges:
            if e.from_node_id == node_id:
                child_ids.add(e.to_node_id)
        return [self.nodes[nid] for nid in child_ids if nid in self.nodes]

    def parents_of(self, node_id: str) -> List[GraphNode]:
        parent_ids: Set[str] = set()
        for e in self.edges:
            if e.to_node_id == node_id:
                parent_ids.add(e.from_node_id)
        return [self.nodes[nid] for nid in parent_ids if nid in self.nodes]

    def has_unexplored_work(self) -> bool:
        """Returns True if any PENDING or IN_PROGRESS nodes exist."""
        return any(
            n.status in (NodeStatus.PENDING, NodeStatus.IN_PROGRESS)
            for n in self.nodes.values()
        )

    def total_unexplored(self) -> int:
        return sum(
            1 for n in self.nodes.values()
            if n.status in (NodeStatus.PENDING, NodeStatus.IN_PROGRESS)
        )

    # ------------------------------------------------------------------
    # Integration helpers: sync from AssessmentState
    # ------------------------------------------------------------------

    def sync_from_state(self, state: Any) -> None:
        """
        Syncs canonical service / endpoint / hypothesis / finding data from
        AssessmentState into the graph, creating new PENDING nodes for anything
        not yet represented.
        """
        from security_agent.agent.assessment_state import ServiceState, HTTPState

        target = state.context.target
        target_host = target.split("://")[-1].split("/")[0].split(":")[0]

        # Ensure host node exists
        host_node = self.add_node(
            NodeKind.HOST, label=target_host,
            metadata={"target": target}, priority=10
        )

        # Services
        for s in state.services.values():
            if s.state != ServiceState.OPEN:
                continue
            svc_label = f"{s.host}:{s.port}/{s.protocol}"
            svc_node = self.add_node(
                NodeKind.SERVICE,
                label=svc_label,
                metadata={
                    "host": s.host, "port": s.port,
                    "protocol": s.protocol, "service": s.service,
                    "version": s.version,
                },
                evidence_ids=list(s.evidence_ids),
                priority=20,
                parent_id=host_node.node_id,
                edge_kind=EdgeKind.DISCOVERED_ON,
            )
            # If the service has been fully investigated, mark EXPLORED
            if s.investigated and svc_node.status == NodeStatus.PENDING:
                svc_node.mark_explored()

        # HTTP Endpoints
        for ep in state.http_endpoints.values():
            ep_state_str = ep.state.value if hasattr(ep.state, "value") else str(ep.state)
            if ep_state_str in ("REFUSED", "UNREACHABLE", "TIMEOUT"):
                continue
            svc_label = f"{ep.host}:{ep.port}/tcp"
            parent = self.get_node_by_label(svc_label)
            ep_label = f"HTTP:{ep.url}"
            self.add_node(
                NodeKind.ENDPOINT,
                label=ep_label,
                metadata={
                    "url": ep.url, "status_code": ep.status_code,
                    "title": ep.title, "server": ep.server_header,
                },
                evidence_ids=list(ep.evidence_ids),
                priority=30,
                parent_id=parent.node_id if parent else host_node.node_id,
                edge_kind=EdgeKind.ENDPOINT_OF,
            )

        # Hypotheses
        for hyp in state.hypotheses.values():
            hyp_label = f"HYP:{hyp.id}"
            svc_label = f"{hyp.target.split('://')[-1].split('/')[0].split(':')[0]}:{hyp.port}/tcp"
            parent = self.get_node_by_label(svc_label) or host_node
            self.add_node(
                NodeKind.HYPOTHESIS,
                label=hyp_label,
                metadata={
                    "hypothesis_id": hyp.id,
                    "vulnerability_type": hyp.vulnerability_type,
                    "target": hyp.target,
                    "port": hyp.port,
                    "verified": hyp.verified,
                    "status": hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
                },
                evidence_ids=list(hyp.evidence_ids),
                priority=40,
                parent_id=parent.node_id,
                edge_kind=EdgeKind.SPAWNS,
            )

        # Findings
        for f in state.findings:
            f_label = f"FINDING:{f.get('title', 'unknown')}"
            finding_node = self.add_node(
                NodeKind.FINDING,
                label=f_label,
                metadata={
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "evidence_ids": f.get("evidence_ids", []),
                },
                evidence_ids=f.get("evidence_ids", []),
                priority=60,
                parent_id=host_node.node_id,
                edge_kind=EdgeKind.EXPLOITS,
            )
            # A finding always marks itself EXPLORED (it is a result, not a task)
            if finding_node.status == NodeStatus.PENDING:
                finding_node.mark_explored()

            # Spawn new derived investigation nodes from a finding
            self._spawn_children_from_finding(finding_node, state)

        # Capabilities & Recursive reachability
        for cap in getattr(state, "capabilities", {}).values():
            if not getattr(cap, "verified", True):
                continue
            cap_type_val = (
                cap.capability_type.value
                if hasattr(cap.capability_type, "value")
                else str(cap.capability_type)
            )
            cap_label = f"CAP:{cap_type_val}:{cap.capability_id}"
            cap_node = self.add_node(
                NodeKind.CAPABILITY,
                label=cap_label,
                metadata=cap.to_dict() if hasattr(cap, "to_dict") else vars(cap),
                evidence_ids=list(cap.source_evidence_ids),
                priority=25,
                parent_id=host_node.node_id,
                edge_kind=EdgeKind.GRANTS,
            )
            if cap_node.status == NodeStatus.PENDING:
                cap_node.mark_explored()

            # Connect any finding node that contributed evidence to this capability
            for f_node in self.finding_nodes():
                if any(eid in f_node.evidence_ids for eid in cap.source_evidence_ids):
                    self.add_edge(
                        f_node.node_id,
                        cap_node.node_id,
                        EdgeKind.GRANTS,
                        label=f"Grants {cap_type_val}",
                        evidence_ids=list(cap.source_evidence_ids),
                    )

            # Unlocked endpoints / resources from capability metadata
            unlocked_endpoints = cap.metadata.get("unlocked_endpoints", [])
            for ep_spec in unlocked_endpoints:
                ep_url = ep_spec if isinstance(ep_spec, str) else ep_spec.get("url", "")
                if not ep_url:
                    continue
                ep_label = f"HTTP:{ep_url}"
                self.add_node(
                    NodeKind.ENDPOINT,
                    label=ep_label,
                    metadata={
                        "url": ep_url,
                        "unlocked_by_capability": cap.capability_id,
                        "capability_type": cap_type_val,
                    },
                    evidence_ids=list(cap.source_evidence_ids),
                    priority=25,
                    parent_id=cap_node.node_id,
                    edge_kind=EdgeKind.ENABLES,
                )

        # Active Authenticated Sessions
        session_store = getattr(state, "session_store", None)
        if session_store and hasattr(session_store, "sessions"):
            for sess in session_store.sessions.values():
                is_auth = sess.is_authenticated() if callable(getattr(sess, "is_authenticated", None)) else bool(getattr(sess, "is_authenticated", False))
                if not is_auth:
                    continue
                sess_label = f"SESSION:{sess.session_id}:{sess.role}"
                sess_node = self.add_node(
                    NodeKind.SESSION,
                    label=sess_label,
                    metadata=sess.to_safe_dict() if hasattr(sess, "to_safe_dict") else vars(sess),
                    evidence_ids=list(sess.source_evidence_ids),
                    priority=22,
                    parent_id=host_node.node_id,
                    edge_kind=EdgeKind.AUTHENTICATED_BY,
                )
                if sess_node.status == NodeStatus.PENDING:
                    sess_node.mark_explored()

                # Link session to matching CAPABILITY nodes
                for cap_n in self.get_nodes_by_kind(NodeKind.CAPABILITY):
                    if any(eid in cap_n.evidence_ids for eid in sess.source_evidence_ids):
                        self.add_edge(
                            sess_node.node_id,
                            cap_n.node_id,
                            EdgeKind.ENABLES,
                            label=f"Session {sess.session_id} enables {cap_n.label}",
                            evidence_ids=list(sess.source_evidence_ids),
                        )

        # Application Surface: DOM Snapshots & Pages
        dom_snapshots = getattr(state, "dom_snapshots", {})
        if dom_snapshots:
            for snap in dom_snapshots.values():
                snap_url = getattr(snap, "url", "")
                if not snap_url:
                    continue
                page_label = f"PAGE:{snap_url}"
                page_node = self.add_node(
                    NodeKind.PAGE,
                    label=page_label,
                    metadata=snap.to_dict() if hasattr(snap, "to_dict") else vars(snap),
                    evidence_ids=list(getattr(snap, "evidence_ids", [])),
                    priority=28,
                    parent_id=host_node.node_id,
                    edge_kind=EdgeKind.REVEALS,
                )

                # Connect Forms
                for frm in getattr(snap, "forms", []):
                    f_id = getattr(frm, "form_id", "form")
                    f_action = getattr(frm, "action", "")
                    frm_label = f"FORM:{f_id}:{f_action}"
                    frm_node = self.add_node(
                        NodeKind.FORM,
                        label=frm_label,
                        metadata=frm.to_dict() if hasattr(frm, "to_dict") else vars(frm),
                        evidence_ids=list(getattr(frm, "evidence_ids", [])),
                        priority=32,
                        parent_id=page_node.node_id,
                        edge_kind=EdgeKind.REVEALS,
                    )
                    if f_action:
                        act_ep_label = f"HTTP:{f_action}"
                        act_node = self.get_node_by_label(act_ep_label)
                        if act_node:
                            self.add_edge(
                                frm_node.node_id,
                                act_node.node_id,
                                EdgeKind.SUBMITS_TO,
                                label=f"Submits to {f_action}",
                                evidence_ids=list(getattr(frm, "evidence_ids", [])),
                            )

                # Connect Discovered API Endpoints
                for api in getattr(snap, "api_candidates", []):
                    api_url = getattr(api, "url", "")
                    if not api_url:
                        continue
                    api_label = f"API:{api_url}"
                    self.add_node(
                        NodeKind.API_ENDPOINT,
                        label=api_label,
                        metadata=api.to_dict() if hasattr(api, "to_dict") else vars(api),
                        evidence_ids=list(getattr(api, "evidence_ids", [])),
                        priority=30,
                        parent_id=page_node.node_id,
                        edge_kind=EdgeKind.CALLS,
                    )

                # Connect Discovered WebSockets
                for ws in getattr(snap, "websockets", []):
                    ws_url = getattr(ws, "url", "")
                    if not ws_url:
                        continue
                    ws_label = f"WS:{ws_url}"
                    self.add_node(
                        NodeKind.WEBSOCKET,
                        label=ws_label,
                        metadata=ws.to_dict() if hasattr(ws, "to_dict") else vars(ws),
                        evidence_ids=list(getattr(ws, "evidence_ids", [])),
                        priority=30,
                        parent_id=page_node.node_id,
                        edge_kind=EdgeKind.REVEALS,
                    )

        # Standalone Forms & WebSockets in AssessmentState
        state_forms = getattr(state, "forms", {})
        if state_forms:
            for f_key, frm in state_forms.items():
                f_id = getattr(frm, "form_id", f_key)
                f_action = getattr(frm, "action", "")
                frm_label = f"FORM:{f_id}:{f_action}"
                if frm_label not in self._label_index:
                    self.add_node(
                        NodeKind.FORM,
                        label=frm_label,
                        metadata=frm.to_dict() if hasattr(frm, "to_dict") else vars(frm),
                        evidence_ids=list(getattr(frm, "evidence_ids", [])),
                        priority=32,
                        parent_id=host_node.node_id,
                        edge_kind=EdgeKind.REVEALS,
                    )

        state_ws = getattr(state, "websockets", {})
        if state_ws:
            for w_key, ws in state_ws.items():
                ws_url = getattr(ws, "url", w_key)
                ws_label = f"WS:{ws_url}"
                if ws_label not in self._label_index:
                    self.add_node(
                        NodeKind.WEBSOCKET,
                        label=ws_label,
                        metadata=ws.to_dict() if hasattr(ws, "to_dict") else vars(ws),
                        evidence_ids=list(getattr(ws, "evidence_ids", [])),
                        priority=30,
                        parent_id=host_node.node_id,
                        edge_kind=EdgeKind.REVEALS,
                    )

    def _spawn_children_from_finding(self, finding_node: GraphNode, state: Any) -> None:
        """
        When a finding is verified, create new PENDING nodes for logical follow-on investigation:
          - POST_EXPLOITATION: privilege escalation, lateral movement, data extraction
          - RETEST: confirm finding is reproducible after potential patch
        """
        f_meta = finding_node.metadata
        severity = str(f_meta.get("severity", "")).upper()
        title = str(f_meta.get("title", ""))

        # Critical/High findings spawn post-exploitation work
        if severity in ("CRITICAL", "HIGH") or any(
            kw in title.lower()
            for kw in ("injection", "bypass", "rce", "execution", "admin", "root", "sqli")
        ):
            pe_label = f"POST_EXPLOIT:{finding_node.node_id}"
            if pe_label not in self._label_index:
                self.add_node(
                    NodeKind.ENDPOINT,
                    label=pe_label,
                    metadata={
                        "task": "post_exploitation",
                        "parent_finding": finding_node.node_id,
                        "description": f"Post-exploitation follow-on from: {title}",
                    },
                    priority=35,
                    parent_id=finding_node.node_id,
                    edge_kind=EdgeKind.ENABLES,
                )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_summary(self) -> str:
        """Returns a compact human-readable attack graph summary for LLM context."""
        pending   = self.pending_nodes()
        explored  = self.explored_nodes()
        findings  = self.finding_nodes()

        lines = [
            "=== ATTACK GRAPH SUMMARY ===",
            f"Total Nodes: {len(self.nodes)} | Pending: {len(pending)} | Explored: {len(explored)} | Findings: {len(findings)}",
        ]

        if pending:
            lines.append("\nUNEXPLORED NODES (next targets):")
            for n in pending[:8]:
                lines.append(f"  [{n.kind.value}] {n.label} (priority={n.priority})")
            if len(pending) > 8:
                lines.append(f"  ... and {len(pending) - 8} more")

        if findings:
            lines.append("\nVERIFIED FINDINGS:")
            for n in findings:
                lines.append(f"  [{n.metadata.get('severity', '?')}] {n.metadata.get('title', n.label)}")

        lines.append("============================")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }
