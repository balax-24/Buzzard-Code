"""
Knowledge-graph tools bound to the agent loop.

These tools let the model maintain a structured picture of the attack surface
(hosts, services, endpoints, parameters, findings, secrets) and drive the
hypothesis-driven tool-selection layer. They receive the loop's AssetGraph
(`knowledge`) and ToolSelector (`selector`) injected from the tool context.

The graph is the "security knowledge graph" of the architecture: instead of
re-scanning, the agent records what it knows and uses it to pick the next test.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from security_agent.intelligence.asset_graph import AssetGraph
from security_agent.intelligence.selector import ToolSelector


def knowledge_add(knowledge: AssetGraph, kind: str, **kwargs) -> str:
    """Record an asset or finding into the security knowledge graph.

    Args:
        kind: One of 'host', 'service', 'endpoint', 'parameter', 'finding', 'secret'.
        host: Host name/IP (for host/service/finding/secret).
        ip: Optional IP for a host.
        port: Port for a service.
        service_name: Service name for a service.
        banner: Optional service banner.
        url: Endpoint URL (for endpoint/parameter/finding).
        method: HTTP method for an endpoint (default GET).
        auth_required: Whether the endpoint requires auth (bool).
        param_name: Parameter name (for parameter).
        param_type: Parameter type (query/body/header) for parameter.
        vuln_class: Vulnerability class (for finding).
        severity: Severity for a finding (critical/high/medium/low/info).
        evidence: Evidence string for a finding.
        technique: Technique used for a finding.
        secret_type: Type of secret (for secret).
        value_hint: Hint of the secret value (for secret).
    """
    kind = (kind or "").lower()
    host = kwargs.get("host") or ""
    url = kwargs.get("url") or ""
    try:
        if kind == "host":
            n = knowledge.add_host(host, ip=kwargs.get("ip"))
            return f"Recorded host: {n.name}"
        if kind == "service":
            n = knowledge.add_service(host, int(kwargs.get("port", 0)),
                                      kwargs.get("service_name", "unknown"),
                                      banner=kwargs.get("banner", ""))
            return f"Recorded service: {n.name}"
        if kind == "endpoint":
            n = knowledge.add_endpoint(url, method=kwargs.get("method", "GET"),
                                       auth_required=bool(kwargs.get("auth_required", False)))
            return f"Recorded endpoint: {n.name}"
        if kind == "parameter":
            n = knowledge.add_parameter(url, kwargs.get("param_name", ""),
                                         param_type=kwargs.get("param_type", "query"))
            return f"Recorded parameter: {n.name} on {url}"
        if kind == "finding":
            n = knowledge.add_finding(host, url, kwargs.get("vuln_class", "unknown"),
                                      severity=kwargs.get("severity", "medium"),
                                      evidence=kwargs.get("evidence", ""),
                                      technique=kwargs.get("technique", ""))
            return f"Recorded finding: {n.name} (severity={n.metadata.get('severity')})"
        if kind == "secret":
            stype = ((kwargs.get("secret_type") or "").strip().lower() or "unknown")
            shost = (host or "").strip() or "unknown"
            value_hint = (kwargs.get("value_hint") or "")[:120]
            node_id = f"secret:{shost}:{stype}"
            existed = node_id in getattr(knowledge, "nodes", {})
            n = knowledge.add_secret(shost, stype, value_hint=value_hint)
            if existed:
                return (f"Secret already recorded: {n.name} (duplicate skipped; "
                        f"hint='{value_hint[:40]}')")
            return f"Recorded secret: {n.name}"
        return (f"TOOL ERROR: unknown kind '{kind}'. Must be one of "
                "host, service, endpoint, parameter, finding, secret.")
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


def knowledge_dump(knowledge: AssetGraph, format: str = "text") -> str:
    """Dump the current security knowledge graph.

    Args:
        format: 'text' (compact prompt render) or 'json' (full graph).
    """
    if format == "json":
        return json.dumps(knowledge.to_dict(), indent=2, default=str)
    d = knowledge.to_dict()
    lines = [knowledge.summary()]
    for n in d["nodes"]:
        meta = n["metadata"]
        if n["type"] == "host":
            lines.append(f"  HOST {n['name']} ip={meta.get('ip', '')}")
        elif n["type"] == "service":
            lines.append(f"  SERVICE {n['name']} banner={meta.get('banner', '')[:60]}")
        elif n["type"] == "endpoint":
            lines.append(f"  ENDPOINT {n['name']} auth={meta.get('auth_required')}")
        elif n["type"] == "parameter":
            lines.append(f"  PARAM {n['name']} ({meta.get('param_type')}) on {meta.get('url', '')}")
        elif n["type"] == "finding":
            lines.append(f"  FINDING {n['name']} severity={meta.get('severity')} technique={meta.get('technique')}")
        elif n["type"] == "secret":
            lines.append(f"  SECRET {n['name']} hint={meta.get('value_hint', '')[:40]}")
    return "\n".join(lines)


def select_next(selector: ToolSelector, situation: str, top_k: int = 3) -> str:
    """Recommend the next capability to run based on the current situation.

    Args:
        situation: A short description of the current situation / hypothesis
                   (e.g. 'authenticated object endpoint /api/users/1').
        top_k: Number of recommendations to return (default 3).
    """
    recs = selector.recommend(situation, top_k=top_k)
    if not recs:
        return json.dumps({
            "status": "no_match",
            "situation": situation,
            "recommendations": [],
            "message": "No capability recommendation matched. Describe situation with keywords: login, sql, jwt, open port, http."
        })
    
    result = {
        "status": "ready",
        "situation": situation,
        "top_capability": recs[0]["capability"],
        "recommendations": [
            {
                "capability": r["capability"],
                "confidence": r["confidence"],
                "rationale": r["rationale"]
            }
            for r in recs
        ]
    }
    return json.dumps(result, indent=2)


def register_knowledge_tools(registry) -> None:
    """Register the knowledge-graph tools into a ToolRegistry."""
    registry.register(
        name="knowledge_add",
        description=("Record an asset or finding into the security knowledge graph. "
                     "Arguments: kind (host|service|endpoint|parameter|finding|secret), "
                     "host (str), ip (str), port (int), service_name (str), banner (str), "
                     "url (str), method (str), auth_required (bool), param_name (str), "
                     "param_type (str), vuln_class (str), severity (str), evidence (str), "
                     "technique (str), secret_type (str), value_hint (str)."),
        func=lambda knowledge, **kw: knowledge_add(knowledge, kw.pop("kind", ""), **kw),
    )
    registry.register(
        name="knowledge_dump",
        description=("Dump the current security knowledge graph. "
                     "Arguments: format ('text' or 'json')."),
        func=lambda knowledge, **kw: knowledge_dump(knowledge, kw.get("format", "text")),
    )
    registry.register(
        name="select_next",
        description=("Recommend the next capability to run based on the current situation. "
                     "Arguments: situation (str), top_k (int, optional)."),
        func=lambda selector, **kw: select_next(selector, kw.get("situation", ""),
                                                int(kw.get("top_k", 3))),
    )
