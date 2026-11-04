"""
Phase 14 Canonical Golden Trace Generator & Fixture.

Defines the golden deterministic trajectory lifecycle:
DISCOVERY
   ↓
SERVICE
   ↓
ENDPOINT
   ↓
HYPOTHESIS
   ↓
VALIDATION
   ↓
CAPABILITY
   ↓
GRAPH EXPANSION
   ↓
NEW SURFACE
   ↓
HYPOTHESIS
   ↓
VALIDATION
   ↓
VERIFICATION
   ↓
REPORT

Every future backend change must preserve this lifecycle contract.
"""

from __future__ import annotations

import time
from typing import List, Dict, Any

from security_agent.events.types import EventType


def generate_golden_trace_events(session_id: str = "golden-session-001", target: str = "127.0.0.1") -> List[Dict[str, Any]]:
    """
    Generates the complete sequence of canonical telemetry events representing a perfect assessment.
    """
    base_time = 1700000000.0
    events = [
        # 1. Assessment Started
        {
            "event_type": EventType.ASSESSMENT_STARTED.value,
            "session_id": session_id,
            "timestamp": base_time + 1.0,
            "data": {"target": target, "scope": [target, "127.0.0.1/24"]}
        },
        # 2. Phase -> DISCOVERY
        {
            "event_type": EventType.ASSESSMENT_PHASE_CHANGED.value,
            "session_id": session_id,
            "timestamp": base_time + 2.0,
            "data": {"phase": "DISCOVERY"}
        },
        # 3. Discovery Tool Started & Completed
        {
            "event_type": EventType.TOOL_STARTED.value,
            "session_id": session_id,
            "timestamp": base_time + 3.0,
            "data": {"tool": "nmap", "target": target}
        },
        {
            "event_type": EventType.EVIDENCE_CREATED.value,
            "session_id": session_id,
            "timestamp": base_time + 4.0,
            "data": {
                "evidence_id": "evi-nmap-01",
                "source_tool": "nmap",
                "target": target,
                "content": "Port 80/tcp open http (Apache/2.4.41), Port 22/tcp open ssh (OpenSSH 8.2p1)"
            }
        },
        # 4. Graph Expanded (Services)
        {
            "event_type": EventType.GRAPH_EXPANDED.value,
            "session_id": session_id,
            "timestamp": base_time + 5.0,
            "data": {
                "nodes": [
                    {"node_id": "host-1", "kind": "HOST", "label": target, "status": "EXPLORED", "metadata": {"host": target}},
                    {"node_id": "svc-http", "kind": "SERVICE", "label": "HTTP 80", "status": "EXPLORED", "metadata": {"host": target, "port": 80, "service": "http"}},
                    {"node_id": "svc-ssh", "kind": "SERVICE", "label": "SSH 22", "status": "PENDING", "metadata": {"host": target, "port": 22, "service": "ssh"}}
                ],
                "edges": [
                    {"edge_id": "e1", "source_id": "host-1", "target_id": "svc-http", "kind": "DISCOVERED_ON", "evidence_ids": ["evi-nmap-01"]},
                    {"edge_id": "e2", "source_id": "host-1", "target_id": "svc-ssh", "kind": "DISCOVERED_ON", "evidence_ids": ["evi-nmap-01"]}
                ]
            }
        },
        # 5. Phase -> ENUMERATION (HTTP Endpoint Discovery)
        {
            "event_type": EventType.ASSESSMENT_PHASE_CHANGED.value,
            "session_id": session_id,
            "timestamp": base_time + 6.0,
            "data": {"phase": "TARGETED_ENUMERATION"}
        },
        {
            "event_type": EventType.EVIDENCE_CREATED.value,
            "session_id": session_id,
            "timestamp": base_time + 7.0,
            "data": {
                "evidence_id": "evi-web-01",
                "source_tool": "http_request",
                "target": f"http://{target}:80/login",
                "content": "HTTP/1.1 200 OK - LoginForm found with user and password input fields"
            }
        },
        # 6. Graph Expanded (Endpoint)
        {
            "event_type": EventType.GRAPH_EXPANDED.value,
            "session_id": session_id,
            "timestamp": base_time + 8.0,
            "data": {
                "nodes": [
                    {"node_id": "ep-login", "kind": "ENDPOINT", "label": "/login", "status": "EXPLORED", "metadata": {"host": target, "port": 80, "service": "http"}}
                ],
                "edges": [
                    {"edge_id": "e3", "source_id": "svc-http", "target_id": "ep-login", "kind": "ENDPOINT_OF", "evidence_ids": ["evi-web-01"]}
                ]
            }
        },
        # 7. Hypothesis Generation
        {
            "event_type": EventType.HYPOTHESIS_CREATED.value,
            "session_id": session_id,
            "timestamp": base_time + 9.0,
            "data": {
                "hypothesis_id": "hyp-sqli-01",
                "title": "SQL Injection Authentication Bypass on /login",
                "target": f"http://{target}:80/login",
                "category": "AUTH_BYPASS",
                "status": "UNTESTED",
                "supporting_evidence_ids": ["evi-web-01"]
            }
        },
        # 8. Phase -> EXPLOITATION (Validation)
        {
            "event_type": EventType.ASSESSMENT_PHASE_CHANGED.value,
            "session_id": session_id,
            "timestamp": base_time + 10.0,
            "data": {"phase": "EXPLOITATION"}
        },
        {
            "event_type": EventType.EVIDENCE_CREATED.value,
            "session_id": session_id,
            "timestamp": base_time + 11.0,
            "data": {
                "evidence_id": "evi-sqli-proof",
                "source_tool": "sqlmap",
                "target": f"http://{target}:80/login",
                "content": "Payload: admin' OR '1'='1' -- yielded HTTP 302 Redirect to /admin/dashboard with Set-Cookie: session=admintoken123"
            }
        },
        # 9. Capability Acquired (ADMIN_ACCESS)
        {
            "event_type": EventType.CAPABILITY_ACQUIRED.value,
            "session_id": session_id,
            "timestamp": base_time + 12.0,
            "data": {
                "capability_id": "cap-admin-session",
                "capability_type": "ADMIN_ACCESS",
                "source_evidence_ids": ["evi-sqli-proof"],
                "acquisition_action": "sqlmap_auth_bypass",
                "target_scope": target
            }
        },
        # 10. Graph Expansion -> New Authenticated Surface (/admin/upload)
        {
            "event_type": EventType.GRAPH_EXPANDED.value,
            "session_id": session_id,
            "timestamp": base_time + 13.0,
            "data": {
                "nodes": [
                    {"node_id": "ep-admin-upload", "kind": "ENDPOINT", "label": "/admin/upload", "status": "PENDING", "metadata": {"host": target, "port": 80, "service": "http"}}
                ],
                "edges": [
                    {"edge_id": "e4", "source_id": "ep-login", "target_id": "ep-admin-upload", "kind": "ENABLES", "evidence_ids": ["evi-sqli-proof"]}
                ]
            }
        },
        # 11. Verification
        {
            "event_type": EventType.ASSESSMENT_PHASE_CHANGED.value,
            "session_id": session_id,
            "timestamp": base_time + 14.0,
            "data": {"phase": "VERIFICATION"}
        },
        {
            "event_type": EventType.EVIDENCE_CREATED.value,
            "session_id": session_id,
            "timestamp": base_time + 15.0,
            "data": {
                "evidence_id": "evi-verify-01",
                "source_tool": "http_request",
                "target": f"http://{target}:80/admin/dashboard",
                "content": "Independent GET with session=admintoken123 returned 200 OK Dashboard Content"
            }
        },
        {
            "event_type": EventType.FINDING_VERIFIED.value,
            "session_id": session_id,
            "timestamp": base_time + 16.0,
            "data": {
                "finding_id": "find-sqli-01",
                "title": "SQL Injection Authentication Bypass on /login",
                "description": "Unauthenticated attackers can bypass login using classic boolean-based SQL injection.",
                "severity": "CRITICAL",
                "target": f"http://{target}:80/login",
                "evidence_ids": ["evi-sqli-proof", "evi-verify-01"]
            }
        },
        # 12. Reporting
        {
            "event_type": EventType.ASSESSMENT_PHASE_CHANGED.value,
            "session_id": session_id,
            "timestamp": base_time + 17.0,
            "data": {"phase": "REPORTING"}
        },
        {
            "event_type": EventType.ASSESSMENT_COMPLETED.value,
            "session_id": session_id,
            "timestamp": base_time + 18.0,
            "data": {"status": "SUCCESS", "findings_count": 1, "capabilities_count": 1}
        }
    ]
    return events
