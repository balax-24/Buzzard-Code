"""
Evidence Ingestion, Fact-Grounding & Canonical Evidence Pipeline.

Authoritative ingestor that consumes ToolExecutionResult objects, produces
immutable structured EvidenceItem records, deterministically extracts verified facts,
and updates the canonical AssessmentState as the single source of truth.
"""

from __future__ import annotations

import os
import re
import json
import time
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from model.schemas import Evidence, EvidenceType
from storage.db import StorageManager
from storage.assessment_logger import AssessmentLogger
from agent.assessment_state import (
    AssessmentState,
    ServiceRecord,
    HTTPEndpointRecord,
    HTTPState,
    ServiceState,
    VerificationStatus,
    FailureClassification,
    classify_failure
)


class ClaimStatus(str, Enum):
    """Factual claim verification status."""
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"
    REJECTED = "REJECTED"


@dataclass
class FactualClaim:
    """
    Represents an atomic factual statement about a target asset.
    Strictly ties facts to corroborating evidence IDs and source tools.
    """
    claim: str
    status: ClaimStatus = ClaimStatus.UNKNOWN
    evidence_ids: List[str] = field(default_factory=list)
    source_tool: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "status": self.status.value,
            "evidence_ids": self.evidence_ids,
            "source_tool": self.source_tool,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class EvidenceItem:
    """
    Immutable technical evidence unit captured from a verified tool execution.
    """
    evidence_id: str
    tool_name: str
    timestamp: float
    target: str
    arguments: Dict[str, Any]
    raw_output_reference: Optional[str] = None
    raw_output_snippet: str = ""
    structured_data: Dict[str, Any] = field(default_factory=dict)
    status: str = "VERIFIED"
    source_type: str = "tool_output"
    exit_code: int = 0
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "target": self.target,
            "arguments": self.arguments,
            "raw_output_reference": self.raw_output_reference,
            "raw_output_snippet": self.raw_output_snippet[:300],
            "structured_data": self.structured_data,
            "status": self.status,
            "source_type": self.source_type,
            "exit_code": self.exit_code,
            "duration": self.duration,
        }


class EvidenceIngestor:
    """
    Authoritative Evidence Ingestor.
    
    Transforms raw tool outputs into structured EvidenceItem objects,
    extracts deterministic ground truth, enforces version verification rules,
    detects state contradictions, and populates AssessmentState.
    """

    def __init__(
        self,
        storage: Optional[StorageManager] = None,
        assessment_logger: Optional[AssessmentLogger] = None,
        base_dir: Optional[str] = None
    ):
        self.storage = storage
        self.assessment_logger = assessment_logger
        self.base_dir = Path(base_dir) if base_dir else (Path.home() / ".security-agent" / "evidence")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._seq_counter = 0

    def _generate_evidence_id(self, tool_name: str) -> str:
        self._seq_counter += 1
        clean_tool = re.sub(r"[^a-zA-Z0-9]", "_", tool_name).upper()
        return f"EVI-{clean_tool}-{self._seq_counter:03d}-{uuid.uuid4().hex[:4].upper()}"

    def _persist_raw_output(self, session_id: str, evidence_id: str, raw_output: str) -> Optional[str]:
        """Saves large raw output to disk so it can be referenced without polluting LLM context."""
        try:
            session_dir = self.base_dir / (session_id or "default") / "raw"
            session_dir.mkdir(parents=True, exist_ok=True)
            filepath = session_dir / f"{evidence_id}.txt"
            filepath.write_text(raw_output or "", encoding="utf-8")
            return str(filepath)
        except Exception:
            return None

    def ingest(
        self,
        tool_result: Any,
        state: Optional[AssessmentState] = None,
        session_id: str = "",
        target: str = ""
    ) -> EvidenceItem:
        """
        Main entrypoint for evidence ingestion.
        Consumes ToolExecutionResult (or compatible object), parses facts,
        updates state, and stores evidence.
        """
        tool_name = getattr(tool_result, "tool_name", "unknown")
        tool_args = getattr(tool_result, "arguments", {}) or {}
        raw_output = str(getattr(tool_result, "raw_output", ""))
        exit_code = getattr(tool_result, "exit_code", 0)
        duration = getattr(tool_result, "duration", 0.0)
        resolved_target = target or getattr(tool_result, "target", "") or tool_args.get("host") or tool_args.get("target") or "127.0.0.1"

        if "://" in resolved_target:
            resolved_target_clean = resolved_target.split("://")[-1].split("/")[0].split(":")[0]
        else:
            resolved_target_clean = resolved_target.split(":")[0]

        evidence_id = self._generate_evidence_id(tool_name)
        raw_ref = self._persist_raw_output(session_id, evidence_id, raw_output)

        # 1. Deterministic Parsing
        structured_data: Dict[str, Any] = {}
        claims: List[FactualClaim] = []

        # A. Network & Port Scans (nmap, scan_ports, port_scan)
        if "nmap" in tool_name or ("PORT" in raw_output and "STATE" in raw_output) or tool_name in ("scan_ports", "port_scan"):
            structured_data = self._parse_port_scan(
                raw_output=raw_output,
                host=resolved_target_clean,
                exit_code=exit_code,
                evidence_id=evidence_id,
                state=state
            )

        # B. Web Fingerprinting & Headers (whatweb, web_tech_detect)
        elif "whatweb" in tool_name or "HTTPServer" in raw_output or "Title[" in raw_output:
            structured_data = self._parse_whatweb(
                raw_output=raw_output,
                tool_args=tool_args,
                host=resolved_target_clean,
                evidence_id=evidence_id,
                state=state
            )

        # C. Service Banner Grabbing (grab_banner, service_fingerprint)
        elif "grab_banner" in tool_name or "service_fingerprint" in tool_name or "banner" in tool_name:
            structured_data = self._parse_banner_grab(
                raw_output=raw_output,
                tool_args=tool_args,
                host=resolved_target_clean,
                evidence_id=evidence_id,
                state=state
            )

        # D. HTTP Probing (http.request, web_fetch, check_headers, evaluate_security_headers)
        elif any(w in tool_name for w in ("http", "curl", "web_fetch", "headers")):
            structured_data = self._parse_http_probe(
                raw_output=raw_output,
                tool_args=tool_args,
                host=resolved_target_clean,
                exit_code=exit_code,
                evidence_id=evidence_id,
                state=state
            )

        # E. Fuzzing & Directory Discovery (ffuf, gobuster, dirb)
        elif any(w in tool_name for w in ("ffuf", "gobuster", "dirb")):
            structured_data = self._parse_fuzz_endpoints(
                raw_output=raw_output,
                tool_args=tool_args,
                evidence_id=evidence_id,
                state=state
            )

        # F. Browser Observations & DOM Snapshots
        elif "browser" in tool_name or "DOM SNAPSHOT" in raw_output or "PAGE:" in raw_output or "BROWSER\n" in raw_output:
            structured_data = self._parse_browser_observation(
                raw_output=raw_output,
                tool_args=tool_args,
                host=resolved_target_clean,
                exit_code=exit_code,
                evidence_id=evidence_id,
                state=state
            )

        # 2. Construct EvidenceItem
        evidence_item = EvidenceItem(
            evidence_id=evidence_id,
            tool_name=tool_name,
            timestamp=time.time(),
            target=resolved_target_clean,
            arguments=tool_args,
            raw_output_reference=raw_ref,
            raw_output_snippet=raw_output[:300],
            structured_data=structured_data,
            status="VERIFIED" if exit_code == 0 else "FAILED",
            source_type="tool_output",
            exit_code=exit_code,
            duration=duration
        )

        # 3. Persist to Storage if available
        if self.storage and session_id:
            try:
                ev_type = EvidenceType.HTTP if "http" in tool_name else (
                    EvidenceType.TERMINAL if "terminal" in tool_name else EvidenceType.OTHER
                )
                self.storage.add_evidence(
                    session_id=session_id,
                    evidence=Evidence(
                        id=evidence_id,
                        type=ev_type,
                        target=resolved_target_clean,
                        description=f"Output of {tool_name} with {json.dumps(tool_args)} (exit {exit_code})",
                        data=structured_data or {"raw_snippet": raw_output[:300]},
                        timestamp=datetime.now().isoformat()
                    )
                )
            except Exception:
                pass

        # 4. Record action attempt in canonical state
        if state is not None:
            failure_type = classify_failure(raw_output, exit_code=exit_code)
            state.record_action_attempt(
                tool_name=tool_name,
                args=tool_args,
                target=resolved_target_clean,
                success=(exit_code == 0),
                failure_type=failure_type,
                output_snippet=raw_output,
                duration=duration
            )

        return evidence_item

    def _parse_port_scan(
        self,
        raw_output: str,
        host: str,
        exit_code: int,
        evidence_id: str,
        state: Optional[AssessmentState]
    ) -> Dict[str, Any]:
        """
        Deterministically parses port scan output into verified services.
        ENFORCES VERSION RULE: If version is not explicitly returned in the scan,
        it remains UNKNOWN.
        """
        discovered_services: List[Dict[str, Any]] = []
        port_lines = []

        for line in raw_output.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith(("#", "PORT", "Starting", "Nmap", "Service", "Host", "Not shown")):
                continue

            # e.g. "631/tcp open ipp" or "80/tcp open http Apache httpd 2.4.41"
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$", line_str)
            if m:
                port = int(m.group(1))
                proto = m.group(2).lower()
                port_state = m.group(3).lower()
                service_name = m.group(4).strip()
                raw_version = (m.group(5) or "").strip()

                # Determine version and verification status
                if raw_version and raw_version.lower() not in ("unknown", "unrecognized", "?"):
                    version_val = raw_version
                    ver_status = VerificationStatus.VERIFIED
                else:
                    version_val = "UNKNOWN"
                    ver_status = VerificationStatus.UNKNOWN

                srv_dict = {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "service": service_name,
                    "version": version_val,
                    "state": port_state,
                    "version_status": ver_status.value,
                    "evidence_id": evidence_id
                }
                discovered_services.append(srv_dict)

                if state is not None and port_state == "open":
                    # Check if service was previously known
                    existing = state.services.get((host, port, proto))
                    
                    # Do not downgrade verified version to UNKNOWN if already verified by banner/whatweb
                    final_ver = version_val
                    final_ver_status = ver_status
                    if existing and existing.verification_status == VerificationStatus.VERIFIED and version_val == "UNKNOWN":
                        final_ver = existing.version
                        final_ver_status = VerificationStatus.VERIFIED

                    state.record_service(
                        host=host,
                        port=port,
                        protocol=proto,
                        service=service_name,
                        version=final_ver,
                        state=ServiceState.OPEN,
                        evidence_id=evidence_id,
                        verification_status=final_ver_status
                    )
                    # Associate evidence ID
                    if (host, port, proto) in state.services:
                        srv_rec = state.services[(host, port, proto)]
                        if evidence_id not in srv_rec.evidence_ids:
                            srv_rec.evidence_ids.append(evidence_id)

        return {
            "type": "port_scan",
            "host": host,
            "services": discovered_services,
            "open_count": len(discovered_services),
            "evidence_id": evidence_id
        }

    def _parse_whatweb(
        self,
        raw_output: str,
        tool_args: Dict[str, Any],
        host: str,
        evidence_id: str,
        state: Optional[AssessmentState]
    ) -> Dict[str, Any]:
        """
        Deterministically parses WhatWeb output.
        Extracts verified technologies and HTTP server headers.
        """
        extracted_techs: List[str] = []
        http_server: Optional[str] = None
        status_code: Optional[int] = None

        server_m = re.search(r"HTTPServer\[([^\]]+)\]", raw_output)
        if server_m:
            http_server = server_m.group(1).strip()

        status_m = re.search(r"(\d{3})\s+(OK|Found|Moved|Forbidden|Unauthorized)", raw_output)
        if status_m:
            status_code = int(status_m.group(1))

        # Extract technology tags e.g. "Apache[2.4.41]", "PHP[7.4.3]"
        for m in re.finditer(r"([A-Za-z0-9_\-]+)(?:\[([^\]]*)\])?", raw_output):
            name, ver = m.group(1), m.group(2)
            if name not in ("http", "https", "Country", "IP", "Summary", "Unassigned"):
                tag = f"{name} {ver}".strip() if ver else name
                if tag not in extracted_techs:
                    extracted_techs.append(tag)

        # Update state HTTP endpoint and associated service
        url = tool_args.get("url", "") or f"http://{host}/"
        url_port = 80
        try:
            netloc = url.split("://")[-1].split("/")[0]
            if ":" in netloc:
                url_port = int(netloc.split(":")[1])
            elif url.startswith("https://"):
                url_port = 443
        except (ValueError, IndexError):
            url_port = 80

        if state is not None:
            state.record_http_probe(
                url=url,
                state=HTTPState.RESPONDS,
                status_code=status_code or 200,
                server_header=http_server or "",
                evidence_id=evidence_id
            )
            # Mark service investigated and verify version if present
            if state.services:
                for key, srv in state.services.items():
                    if srv.port == url_port or (srv.host == host and srv.port in (80, 443, 8080, 8443)):
                        srv.investigated = True
                        if http_server:
                            srv.version = http_server
                            srv.verification_status = VerificationStatus.VERIFIED
                        if evidence_id not in srv.evidence_ids:
                            srv.evidence_ids.append(evidence_id)

        return {
            "type": "whatweb_scan",
            "host": host,
            "url": url,
            "http_server": http_server,
            "technologies": extracted_techs,
            "evidence_id": evidence_id
        }

    def _parse_banner_grab(
        self,
        raw_output: str,
        tool_args: Dict[str, Any],
        host: str,
        evidence_id: str,
        state: Optional[AssessmentState]
    ) -> Dict[str, Any]:
        """
        Parses banner grabbing results.
        If banner is received, extracts verified version.
        If banner is empty / no banner received, keeps version as UNKNOWN.
        """
        port_raw = tool_args.get("port")
        port = int(port_raw) if port_raw else 0
        banner_text = raw_output.strip()

        is_empty_or_failed = (
            not banner_text
            or "no banner" in banner_text.lower()
            or "timed out" in banner_text.lower()
            or "connection refused" in banner_text.lower()
            or "error" in banner_text.lower()
        )

        version_extracted = "UNKNOWN"
        ver_status = VerificationStatus.UNKNOWN

        if not is_empty_or_failed:
            # Check for SSH banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            ssh_m = re.search(r"SSH-[\d\.]+-([A-Za-z0-9_\-\.]+)", banner_text)
            if ssh_m:
                version_extracted = ssh_m.group(1).replace("_", " ")
                ver_status = VerificationStatus.VERIFIED
            else:
                # First line of banner up to 60 chars
                first_line = banner_text.splitlines()[0][:60].strip()
                if first_line:
                    version_extracted = first_line
                    ver_status = VerificationStatus.VERIFIED

        if state is not None and port > 0:
            for key, srv in state.services.items():
                if srv.host == host and srv.port == port:
                    srv.investigated = True
                    srv.banner = banner_text if not is_empty_or_failed else "none"
                    if ver_status == VerificationStatus.VERIFIED:
                        srv.version = version_extracted
                        srv.verification_status = VerificationStatus.VERIFIED
                    if evidence_id not in srv.evidence_ids:
                        srv.evidence_ids.append(evidence_id)

        return {
            "type": "banner_grab",
            "host": host,
            "port": port,
            "banner": banner_text[:200],
            "version": version_extracted,
            "version_status": ver_status.value,
            "evidence_id": evidence_id
        }

    def _parse_http_probe(
        self,
        raw_output: str,
        tool_args: Dict[str, Any],
        host: str,
        exit_code: int,
        evidence_id: str,
        state: Optional[AssessmentState]
    ) -> Dict[str, Any]:
        """
        Parses HTTP request responses and security headers.
        Detects contradictions (e.g. earlier 200 OK vs now Connection Refused).
        """
        url = tool_args.get("url", "") or f"http://{host}/"
        out_low = raw_output.lower()

        # Check for connection refused / network errors
        if "connection refused" in out_low or "err_connection_refused" in out_low:
            new_state = HTTPState.REFUSED
            status_code = 0
        elif exit_code == 0:
            new_state = HTTPState.RESPONDS
            status_m = re.search(r"HTTP/\S+\s+(\d{3})|Status:\s*(\d{3})", raw_output)
            status_code = int(status_m.group(1) or status_m.group(2)) if status_m else 200
        else:
            new_state = HTTPState.UNREACHABLE
            status_code = 0

        # Contradiction Detection
        is_contradiction = False
        if state is not None:
            target_host = url.split("://")[-1].split("/")[0].split(":")[0]
            port = 443 if "https://" in url else 80
            if ":" in url.split("://")[-1].split("/")[0]:
                try:
                    port = int(url.split("://")[-1].split("/")[0].split(":")[1])
                except Exception:
                    pass
            ep_key = f"{target_host}:{port}"
            existing_rec = state.http_endpoints.get(ep_key) or state.http_endpoints.get(url)

            if existing_rec:
                if existing_rec.state == HTTPState.RESPONDS and new_state == HTTPState.REFUSED:
                    is_contradiction = True
                    state.record_contradiction({
                        "type": "HTTP_REACHABILITY_CONTRADICTION",
                        "url": url,
                        "description": f"URL {url} previously responded ({existing_rec.status_code}) but current probe failed (Connection Refused)",
                        "evidence_ids": [existing_rec.state.value, evidence_id],
                        "timestamp": time.time()
                    })
                elif existing_rec.state == HTTPState.REFUSED and new_state == HTTPState.RESPONDS:
                    is_contradiction = True
                    state.record_contradiction({
                        "type": "HTTP_REACHABILITY_CONTRADICTION",
                        "url": url,
                        "description": f"URL {url} previously refused connection but current probe succeeded (HTTP {status_code})",
                        "evidence_ids": [evidence_id],
                        "timestamp": time.time()
                    })

            state.record_http_probe(url, new_state, status_code=status_code, evidence_id=evidence_id)

            # Parse headers and body for SessionStore continuity
            parsed_headers: Dict[str, str] = {}
            body_str = ""
            if "STATUS:" in raw_output:
                hm = re.search(r"HEADERS:\s*\n(.*?)(?=\n\nBODY:|\n\nDURATION:|\Z)", raw_output, re.DOTALL)
                if hm:
                    for line in hm.group(1).splitlines():
                        if ":" in line:
                            hk, hv = line.split(":", 1)
                            parsed_headers[hk.strip()] = hv.strip()
                bm = re.search(r"BODY:\s*\n(.*?)(?=\n\nDURATION:|\Z)", raw_output, re.DOTALL)
                if bm:
                    body_str = bm.group(1)
            else:
                body_str = raw_output

            state.ingest_session_http_response(
                target_url=url,
                status_code=status_code,
                headers=parsed_headers,
                body=body_str,
                evidence_id=evidence_id
            )

        return {
            "type": "http_probe",
            "url": url,
            "state": new_state.value,
            "status_code": status_code,
            "contradiction": is_contradiction,
            "evidence_id": evidence_id
        }

    def _parse_fuzz_endpoints(
        self,
        raw_output: str,
        tool_args: Dict[str, Any],
        evidence_id: str,
        state: Optional[AssessmentState]
    ) -> Dict[str, Any]:
        """Parses ffuf / directory discovery outputs."""
        base_url = tool_args.get("url", "")
        endpoints: List[Dict[str, Any]] = []

        ffuf_pattern = re.compile(r"^\s*(\S+)\s+\[Status:\s*(\d+)", re.MULTILINE)
        for m in ffuf_pattern.finditer(raw_output):
            path = m.group(1).strip()
            status = int(m.group(2))
            if not path.startswith("::"):
                full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if base_url else path
                endpoints.append({"path": path, "status_code": status, "url": full_url})
                if state is not None:
                    state.record_http_probe(full_url, HTTPState.RESPONDS, status_code=status)

        return {
            "type": "directory_fuzz",
            "base_url": base_url,
            "endpoints": endpoints,
            "count": len(endpoints),
            "evidence_id": evidence_id
        }

    def _parse_browser_observation(
        self,
        raw_output: str,
        tool_args: Dict[str, Any],
        host: str,
        exit_code: int,
        evidence_id: str,
        state: Optional[AssessmentState] = None
    ) -> Dict[str, Any]:
        """
        Parses browser tool outputs, DOM snapshots, forms, links, JS routes, and network events.
        """
        from browser.dom import DOMReducer, DOMSnapshot

        target_url = tool_args.get("url") or host
        if "://" not in target_url and target_url:
            target_url = f"http://{target_url}"
        elif not target_url:
            target_url = "http://localhost/"

        # Reduce raw_output into DOMSnapshot
        snapshot = DOMReducer.reduce(
            html_content=raw_output,
            url=target_url,
            status_code=200 if exit_code == 0 else 500,
            evidence_ids=[evidence_id]
        )

        structured = {
            "type": "browser_observation",
            "snapshot_id": snapshot.snapshot_id,
            "url": snapshot.url,
            "title": snapshot.title,
            "forms": [f.to_dict() for f in snapshot.forms],
            "links": [l.to_dict() for l in snapshot.links],
            "api_candidates": [a.to_dict() for a in snapshot.api_candidates],
            "websockets": [w.to_dict() for w in snapshot.websockets],
            "auth_indicators": snapshot.auth_indicators,
            "reduction_ratio": snapshot.reduction_ratio,
            "evidence_id": evidence_id,
        }

        if state is not None:
            if hasattr(state, "record_dom_snapshot"):
                state.record_dom_snapshot(snapshot)
            else:
                for f in snapshot.forms:
                    if hasattr(state, "record_discovered_form"):
                        state.record_discovered_form(f)
                for w in snapshot.websockets:
                    if hasattr(state, "record_discovered_websocket"):
                        state.record_discovered_websocket(w)

        return structured
