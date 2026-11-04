"""
Asset Graph and Attack Surface Modeling.

Maintains a graph representation of discovered hosts, services, web endpoints,
parameters, authentication mechanisms, and technology stack fingerprints.
Can operate standalone or as a synchronized derived projection over canonical AssessmentState.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agent.assessment_state import AssessmentState


class AssetType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FORM = "form"
    AUTH_MECHANISM = "auth_mechanism"
    DATABASE = "database"
    SECRET = "secret"
    FINDING = "finding"


@dataclass
class AssetNode:
    """Individual node in the target asset graph."""
    id: str
    type: AssetType
    name: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class AssetEdge:
    """Directed relationship between asset nodes."""
    source_id: str
    target_id: str
    relationship: str  # e.g., 'hosts', 'exposes', 'accepts', 'authenticates_via'


class AssetGraph:
    """
    In-memory and serializable graph representing the discovered attack surface.
    Acts as a derived, synchronized projection over canonical AssessmentState when bound.
    """
    def __init__(self, state: Optional[Any] = None):
        self._state: Optional[Any] = state
        self.nodes: Dict[str, AssetNode] = {}
        self.edges: List[AssetEdge] = []
        if state is not None:
            self.sync_from_state(state)

    def bind_state(self, state: Any) -> None:
        """Binds a canonical AssessmentState and performs initial synchronization."""
        self._state = state
        if state is not None:
            self.sync_from_state(state)

    @classmethod
    def from_state(cls, state: Any) -> "AssetGraph":
        """Factory constructor building an AssetGraph directly from AssessmentState."""
        return cls(state=state)

    def sync_from_state(self, state: Optional[Any] = None) -> None:
        """
        Idempotently synchronizes the AssetGraph from canonical AssessmentState.
        Guarantees that canonical state is the single source of truth.
        """
        st = state or self._state
        if st is None:
            return

        from agent.assessment_state import ServiceState

        # 1. Synchronize Target Host
        target = getattr(st.context, "target", "127.0.0.1") if hasattr(st, "context") else "127.0.0.1"
        clean_target = target.split("://")[-1].split("/")[0].split(":")[0]
        self._raw_add_host(clean_target)

        # 2. Synchronize Services
        services = getattr(st, "services", {})
        for s in services.values():
            if getattr(s, "state", None) == ServiceState.OPEN or str(getattr(s, "state", "")).lower() == "open":
                banner = s.version if getattr(s, "version", "UNKNOWN") != "UNKNOWN" else ""
                self._raw_add_service(
                    host=s.host,
                    port=s.port,
                    service_name=s.service or "service",
                    banner=banner
                )

        # 3. Synchronize HTTP Endpoints
        http_endpoints = getattr(st, "http_endpoints", {})
        for ep in http_endpoints.values():
            if hasattr(ep, "url") and ep.url:
                self._raw_add_endpoint(ep.url, method="GET", auth_required=False)

        # 4. Synchronize Findings
        findings = getattr(st, "findings", [])
        for f in findings:
            if isinstance(f, dict):
                title = f.get("title", "Finding")
                severity = f.get("severity", "medium")
                proof = f.get("proof", "") or f.get("description", "")
                target_url = target
                self._raw_add_finding(
                    host=clean_target,
                    endpoint_url=target_url,
                    vuln_class=title,
                    severity=str(severity).lower(),
                    evidence=str(proof)[:200]
                )

        # 5. Synchronize Session Secrets
        session_creds = getattr(st, "session_credentials", {})
        for k, v in session_creds.items():
            hint = v[:15] if isinstance(v, str) else str(v)
            self._raw_add_secret(clean_target, str(k), value_hint=hint)

    def _raw_add_host(self, host: str, ip: Optional[str] = None) -> AssetNode:
        node_id = f"host:{host}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.HOST,
                name=host,
                metadata={"ip": ip or ""}
            )
        return self.nodes[node_id]

    def _raw_add_service(self, host: str, port: int, service_name: str, banner: str = "") -> AssetNode:
        host_node = self._raw_add_host(host)
        node_id = f"service:{host}:{port}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.SERVICE,
                name=f"{service_name} on {port}",
                metadata={"port": port, "banner": banner}
            )
            # Avoid duplicate edge
            if not any(e.source_id == host_node.id and e.target_id == node_id and e.relationship == "hosts" for e in self.edges):
                self.edges.append(AssetEdge(source_id=host_node.id, target_id=node_id, relationship="hosts"))
        return self.nodes[node_id]

    def _raw_add_endpoint(self, url: str, method: str = "GET", auth_required: bool = False) -> AssetNode:
        node_id = f"endpoint:{method}:{url}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.ENDPOINT,
                name=f"{method} {url}",
                metadata={"url": url, "method": method, "auth_required": auth_required}
            )
        return self.nodes[node_id]

    def _raw_add_finding(self, host: str, endpoint_url: str, vuln_class: str,
                         severity: str = "medium", evidence: str = "",
                         technique: str = "") -> AssetNode:
        host_node = self._raw_add_host(host)
        ep_node = self._raw_add_endpoint(endpoint_url)
        node_id = f"finding:{endpoint_url}:{vuln_class}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.FINDING,
                name=f"{vuln_class} @ {endpoint_url}",
                metadata={
                    "vuln_class": vuln_class,
                    "severity": severity,
                    "evidence": evidence,
                    "technique": technique,
                },
                tags=["finding", vuln_class.lower()],
            )
            if not any(e.source_id == ep_node.id and e.target_id == node_id and e.relationship == "affected_by" for e in self.edges):
                self.edges.append(AssetEdge(source_id=ep_node.id, target_id=node_id, relationship="affected_by"))
        else:
            n = self.nodes[node_id]
            n.metadata["severity"] = severity
            if evidence:
                n.metadata["evidence"] = evidence
            if technique:
                n.metadata["technique"] = technique
        return self.nodes[node_id]

    def _raw_add_secret(self, host: str, secret_type: str, value_hint: str = "") -> AssetNode:
        host_node = self._raw_add_host(host)
        node_id = f"secret:{host}:{secret_type}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.SECRET,
                name=f"{secret_type} @ {host}",
                metadata={"secret_type": secret_type, "value_hint": value_hint},
                tags=["secret"],
            )
            if not any(e.source_id == host_node.id and e.target_id == node_id and e.relationship == "holds" for e in self.edges):
                self.edges.append(AssetEdge(source_id=host_node.id, target_id=node_id, relationship="holds"))
        return self.nodes[node_id]

    def add_host(self, host: str, ip: Optional[str] = None) -> AssetNode:
        return self._raw_add_host(host, ip=ip)

    def add_service(self, host: str, port: int, service_name: str, banner: str = "") -> AssetNode:
        """
        Record a service.
        If bound to a canonical AssessmentState, mutates canonical state first.
        """
        if self._state is not None:
            try:
                from agent.assessment_state import ServiceState
                self._state.record_service(
                    host=host,
                    port=port,
                    service=service_name,
                    banner=banner,
                    version=banner if banner else "UNKNOWN",
                    state=ServiceState.OPEN
                )
            except Exception:
                pass
        return self._raw_add_service(host, port, service_name, banner)

    def add_endpoint(self, url: str, method: str = "GET", auth_required: bool = False) -> AssetNode:
        """
        Record an HTTP endpoint.
        If bound to a canonical AssessmentState, mutates canonical state first.
        """
        if self._state is not None:
            try:
                from agent.assessment_state import HTTPState
                self._state.record_http_probe(
                    url=url,
                    state=HTTPState.RESPONDS,
                    status_code=200
                )
            except Exception:
                pass
        return self._raw_add_endpoint(url, method, auth_required)

    def add_parameter(self, endpoint_url: str, param_name: str, param_type: str = "query") -> AssetNode:
        ep_node = None
        for n in self.nodes.values():
            if n.type == AssetType.ENDPOINT and n.metadata.get("url") == endpoint_url:
                ep_node = n
                break
        if not ep_node:
            ep_node = self.add_endpoint(endpoint_url)

        node_id = f"param:{endpoint_url}:{param_name}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AssetNode(
                id=node_id,
                type=AssetType.PARAMETER,
                name=param_name,
                metadata={"param_type": param_type}
            )
            if not any(e.source_id == ep_node.id and e.target_id == node_id and e.relationship == "accepts" for e in self.edges):
                self.edges.append(AssetEdge(source_id=ep_node.id, target_id=node_id, relationship="accepts"))
        return self.nodes[node_id]

    def add_finding(self, host: str, endpoint_url: str, vuln_class: str,
                    severity: str = "medium", evidence: str = "",
                    technique: str = "") -> AssetNode:
        """
        Record a confirmed/observed vulnerability finding on an endpoint.
        If bound to a canonical AssessmentState, mutates canonical state first.
        """
        if self._state is not None:
            try:
                self._state.record_finding(
                    title=f"{vuln_class} @ {endpoint_url}",
                    severity=str(severity).upper(),
                    description=f"Recorded {vuln_class} vulnerability on {endpoint_url}",
                    proof=evidence
                )
            except Exception:
                pass
        return self._raw_add_finding(host, endpoint_url, vuln_class, severity, evidence, technique)

    def add_secret(self, host: str, secret_type: str, value_hint: str = "") -> AssetNode:
        """
        Record a discovered secret/credential on a host.
        If bound to a canonical AssessmentState, mutates canonical state first.
        """
        if self._state is not None:
            try:
                if hasattr(self._state, "session_credentials"):
                    self._state.session_credentials[secret_type] = value_hint
            except Exception:
                pass
        return self._raw_add_secret(host, secret_type, value_hint)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "name": n.name,
                    "metadata": n.metadata,
                    "tags": n.tags
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relationship": e.relationship
                }
                for e in self.edges
            ]
        }

    def summary(self) -> str:
        hosts = [n for n in self.nodes.values() if n.type == AssetType.HOST]
        endpoints = [n for n in self.nodes.values() if n.type == AssetType.ENDPOINT]
        params = [n for n in self.nodes.values() if n.type == AssetType.PARAMETER]
        findings = [n for n in self.nodes.values() if n.type == AssetType.FINDING]
        secrets = [n for n in self.nodes.values() if n.type == AssetType.SECRET]
        return (f"Asset Graph: {len(hosts)} host(s), {len(endpoints)} endpoint(s), "
                f"{len(params)} parameter(s), {len(findings)} finding(s), {len(secrets)} secret(s)")
