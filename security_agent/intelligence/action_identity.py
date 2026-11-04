"""
Phase 15: Semantic Action Identity & Normalization Engine.

Provides stable, canonical semantic identities for candidate security actions across
different syntax representations (e.g. curl vs http_request vs raw requests).
Filters noise, sorts query parameters, normalizes URLs and network targets, and
computes context signatures for capability and state awareness.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ActionCategory(str, Enum):
    DISCOVERY = "DISCOVERY"
    ENUMERATION = "ENUMERATION"
    PROBING = "PROBING"
    EXPLOITATION = "EXPLOITATION"
    VERIFICATION = "VERIFICATION"
    CAPABILITY = "CAPABILITY"
    REPORTING = "REPORTING"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SemanticActionKey:
    """Immutable representation of a normalized semantic action."""
    tool_name: str
    action_type: str
    target: str
    endpoint: str
    canonical_parameters: str
    context_signature: str
    canonical_key: str

    def __str__(self) -> str:
        return self.canonical_key


class ActionIdentity:
    """
    Normalizes security actions into stable canonical identities.
    """

    @classmethod
    def normalize_url(cls, url: str) -> str:
        """Normalizes URLs by standardizing scheme, netloc, path, and sorted queries."""
        if not url:
            return ""
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("ws://") and not url.startswith("wss://"):
            url = "http://" + url

        try:
            parsed = urllib.parse.urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip("/") if parsed.path != "/" and parsed.path else "/"
            query = ""
            if parsed.query:
                qsl = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                sorted_qsl = sorted(qsl)
                query = "?" + urllib.parse.urlencode(sorted_qsl)
            return f"{scheme}://{netloc}{path}{query}"
        except Exception:
            return url.strip()

    @classmethod
    def normalize_target(cls, target: str) -> str:
        """Normalizes host/IP/port representations."""
        if not target:
            return "127.0.0.1"
        t = target.strip().lower()
        t = re.sub(r"^https?://", "", t)
        t = t.rstrip("/")
        return t

    @classmethod
    def create_context_signature(
        cls,
        capabilities: Optional[List[str]] = None,
        active_sessions: Optional[List[str]] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> str:
        """Computes a hash signature of the current operational/capability context."""
        caps = sorted(list(capabilities or []))
        sessions = sorted(list(active_sessions or []))
        creds = sorted(list((credentials or {}).keys()))
        if not caps and not sessions and not creds:
            return "default"
        payload = json.dumps({"caps": caps, "sessions": sessions, "creds": creds}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    @classmethod
    def generate_canonical_key(
        cls,
        tool_name: str,
        parameters: Dict[str, Any],
        target: Optional[str] = None,
        capability_context: Optional[str] = None,
    ) -> SemanticActionKey:
        """
        Produces a unique canonical key from tool call specifications.
        """
        tool_norm = (tool_name or "").strip().lower()
        params = dict(parameters or {})

        # Extract target
        raw_target = str(target or params.get("target") or params.get("host") or params.get("url") or "127.0.0.1")
        norm_target = cls.normalize_target(raw_target)

        # Categorize and format
        action_type = "GENERIC"
        endpoint = ""
        meaningful_params: Dict[str, Any] = {}

        # 1. HTTP / Web Clients
        if tool_norm in ("http_request", "http_client", "http", "curl", "web_probe", "url_fetch"):
            method = str(params.get("method") or "GET").strip().upper()
            raw_url = str(params.get("url") or params.get("target") or params.get("endpoint") or "")

            # If inside bash/curl command
            cmd = str(params.get("command") or params.get("cmd") or "")
            if cmd and "curl" in cmd:
                m_match = re.search(r"-X\s+([A-Z]+)", cmd)
                if m_match:
                    method = m_match.group(1).upper()
                u_match = re.search(r"https?://[^\s\"']+", cmd)
                if u_match:
                    raw_url = u_match.group(0)

            norm_url = cls.normalize_url(raw_url) if raw_url else f"http://{norm_target}/"
            action_type = f"HTTP:{method}"
            endpoint = norm_url
            # Filter headers that are non-semantic
            body = params.get("body") or params.get("data") or params.get("json")
            if body:
                meaningful_params["body"] = body

        # 2. Port / Network Scanners
        elif tool_norm in ("nmap", "port_scan", "service_scan", "network_recon", "scan"):
            action_type = "SCAN"
            raw_ports = str(params.get("ports") or params.get("port") or "all").strip()
            if raw_ports and raw_ports != "all":
                try:
                    ports_list = sorted([int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()])
                    ports = ",".join(str(p) for p in ports_list) if ports_list else raw_ports
                except Exception:
                    ports = raw_ports
            else:
                ports = raw_ports
            scan_type = str(params.get("scan_type") or "syn").strip().lower()
            endpoint = ports
            meaningful_params["ports"] = ports
            meaningful_params["scan_type"] = scan_type

        # 3. Browser Actions
        elif tool_norm in ("browser_navigate", "browser_click", "browser_fill", "browser_snapshot"):
            action_type = f"BROWSER:{tool_norm.replace('browser_', '').upper()}"
            url = str(params.get("url") or "")
            selector = str(params.get("selector") or params.get("element") or "")
            endpoint = cls.normalize_url(url) if url else selector
            if selector:
                meaningful_params["selector"] = selector
            if "value" in params:
                meaningful_params["value"] = params["value"]

        # 4. SQL Injection / Vulnerability Probing
        elif tool_norm in ("sqlmap", "sqli_probe", "vuln_check", "fuzz"):
            action_type = f"VULN:{tool_norm.upper()}"
            raw_url = str(params.get("url") or params.get("target") or "")
            param_name = str(params.get("param") or params.get("parameter") or "")
            endpoint = cls.normalize_url(raw_url) if raw_url else norm_target
            meaningful_params["param"] = param_name

        # 5. SSH / Remote Access
        elif tool_norm in ("ssh_exec", "ssh_connect", "ssh_login"):
            action_type = "SSH"
            port = str(params.get("port") or "22")
            user = str(params.get("username") or params.get("user") or "")
            endpoint = f"{user}@{norm_target}:{port}" if user else f"{norm_target}:{port}"

        # 6. Verification Tools
        elif tool_norm in ("verify_finding", "verify_objective", "exploit_verify"):
            action_type = "VERIFICATION"
            finding_id = str(params.get("finding_id") or params.get("hypothesis_id") or "")
            endpoint = finding_id
            meaningful_params["finding_id"] = finding_id

        # 7. Generic Fallback
        else:
            action_type = f"TOOL:{tool_norm.upper()}"
            endpoint = norm_target
            for k, v in params.items():
                if k not in ("session_id", "turn_id", "timestamp", "nonce"):
                    meaningful_params[k] = v

        # Build parameter string
        param_repr = json.dumps(meaningful_params, sort_keys=True)
        ctx_sig = capability_context or "default"

        if endpoint:
            canonical_key = f"{action_type}:{endpoint}"
        else:
            canonical_key = f"{action_type}:{norm_target}"

        if meaningful_params and tool_norm not in ("http_request", "http_client", "curl"):
            canonical_key += f":{param_repr}"

        return SemanticActionKey(
            tool_name=tool_norm,
            action_type=action_type,
            target=norm_target,
            endpoint=endpoint,
            canonical_parameters=param_repr,
            context_signature=ctx_sig,
            canonical_key=canonical_key,
        )

    @classmethod
    def is_semantically_equivalent(
        cls,
        action1: Tuple[str, Dict[str, Any]],
        action2: Tuple[str, Dict[str, Any]],
    ) -> bool:
        """Returns True if two action specifications produce identical canonical identities."""
        k1 = cls.generate_canonical_key(action1[0], action1[1])
        k2 = cls.generate_canonical_key(action2[0], action2[1])
        return k1.canonical_key == k2.canonical_key
