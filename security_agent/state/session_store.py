"""
Authoritative Stateful Session & Credential Continuity Engine.

Responsible for:
1. Target-bound, scope-enforced session persistence (Cookies, Bearer tokens, CSRF tokens).
2. Domain, path, and expiry-aware cookie attachment for outgoing HTTP requests.
3. Automated parsing of Set-Cookie, Bearer headers, CSRF tokens, and HTML links from HTTP responses.
4. Multi-session separation (anonymous, user, admin, service_account).
5. Safe request authentication resolution (model explicit headers > session store defaults).
6. Evidence-grounded session verification and lifecycle tracking (UNVERIFIED -> VERIFIED, EXPIRED, INVALID).
"""

from __future__ import annotations

import re
import time
import uuid
import urllib.parse
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set


class AuthenticationState(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATED   = "AUTHENTICATED"
    EXPIRED         = "EXPIRED"
    INVALID         = "INVALID"
    REVOKED         = "REVOKED"


class SessionVerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED   = "VERIFIED"


@dataclass
class Cookie:
    """Represents an HTTP cookie with strict domain, path, and security flags."""
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    expiry: Optional[float] = None
    same_site: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        if self.expiry is not None and time.time() > self.expiry:
            return True
        return False

    def matches_request(self, host: str, path: str, is_https: bool = False) -> bool:
        """Evaluates whether cookie should be attached to a specific HTTP request."""
        if self.is_expired():
            return False
        if self.secure and not is_https:
            return False

        # Domain matching: exact match or suffix match if domain starts with .
        clean_cookie_domain = self.domain.split(":")[0].lstrip(".").lower()
        clean_host = host.split(":")[0].lower()

        if clean_host != clean_cookie_domain and not clean_host.endswith(f".{clean_cookie_domain}"):
            return False

        # Path matching: prefix match
        req_path = path or "/"
        cookie_path = self.path or "/"
        if not req_path.startswith(cookie_path):
            return False

        return True

    def to_header_str(self) -> str:
        return f"{self.name}={self.value}"

    def to_safe_dict(self) -> Dict[str, Any]:
        val_mask = self.value[:4] + "***" + self.value[-4:] if len(self.value) > 8 else "***"
        return {
            "name": self.name,
            "value": val_mask,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "expired": self.is_expired(),
        }


@dataclass
class BearerToken:
    """Represents an Authorization Bearer token tied to target origin and scope."""
    token: str
    origin: str
    scope: List[str] = field(default_factory=list)
    capability_id: Optional[str] = None
    source_evidence_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_expired(self) -> bool:
        if self.expires_at is not None and time.time() > self.expires_at:
            return True
        return False

    def matches_origin(self, origin: str) -> bool:
        if self.is_expired():
            return False
        clean_origin = origin.split("://")[-1].split("/")[0].lower()
        clean_token_origin = self.origin.split("://")[-1].split("/")[0].lower()
        return clean_origin == clean_token_origin

    def to_safe_dict(self) -> Dict[str, Any]:
        tok_mask = self.token[:6] + "***" + self.token[-4:] if len(self.token) > 10 else "***"
        return {
            "token": tok_mask,
            "origin": self.origin,
            "scope": self.scope,
            "expired": self.is_expired(),
            "source_evidence_id": self.source_evidence_id,
        }


@dataclass
class CSRFToken:
    """Represents a discovered CSRF token for state-changing HTTP requests."""
    csrf_token: str
    source_endpoint: str
    source_evidence_id: Optional[str] = None
    target_origin: str = ""
    field_name: str = "csrf_token"
    header_name: str = "X-CSRF-Token"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_expired(self) -> bool:
        if self.expires_at is not None and time.time() > self.expires_at:
            return True
        return False

    def matches_origin(self, origin: str) -> bool:
        if self.is_expired():
            return False
        clean_origin = origin.split("://")[-1].split("/")[0].lower()
        clean_target = self.target_origin.split("://")[-1].split("/")[0].lower()
        return clean_origin == clean_target

    def to_safe_dict(self) -> Dict[str, Any]:
        tok_mask = self.csrf_token[:4] + "***" if len(self.csrf_token) > 6 else "***"
        return {
            "field_name": self.field_name,
            "header_name": self.header_name,
            "token": tok_mask,
            "source_endpoint": self.source_endpoint,
            "expired": self.is_expired(),
        }


@dataclass
class Session:
    """Authoritative, scope-bound security session representation."""
    session_id: str
    target_origin: str
    scope: List[str] = field(default_factory=list)
    role: str = "default"  # "anonymous", "user", "admin", "service_account"
    cookies: Dict[str, Cookie] = field(default_factory=dict)
    bearer_tokens: Dict[str, BearerToken] = field(default_factory=dict)
    csrf_tokens: Dict[str, CSRFToken] = field(default_factory=dict)
    authentication_state: AuthenticationState = AuthenticationState.UNAUTHENTICATED
    source_evidence_ids: List[str] = field(default_factory=list)
    acquisition_action: str = ""
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    verification_status: SessionVerificationStatus = SessionVerificationStatus.UNVERIFIED
    parent_session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return self.authentication_state in (
            AuthenticationState.UNAUTHENTICATED,
            AuthenticationState.AUTHENTICATED,
        )

    def is_authenticated(self) -> bool:
        return (
            self.authentication_state == AuthenticationState.AUTHENTICATED
            and (len(self.cookies) > 0 or len(self.bearer_tokens) > 0)
        )

    def add_cookie(self, cookie: Cookie) -> None:
        self.cookies[cookie.name] = cookie
        if self.authentication_state == AuthenticationState.UNAUTHENTICATED:
            self.authentication_state = AuthenticationState.AUTHENTICATED

    def add_bearer_token(self, token: BearerToken) -> None:
        self.bearer_tokens[token.origin] = token
        if self.authentication_state == AuthenticationState.UNAUTHENTICATED:
            self.authentication_state = AuthenticationState.AUTHENTICATED

    def add_csrf_token(self, token: CSRFToken) -> None:
        self.csrf_tokens[token.field_name] = token

    def get_cookie_header(self, host: str, path: str, is_https: bool = False) -> Optional[str]:
        matching = [
            c.to_header_str()
            for c in self.cookies.values()
            if c.matches_request(host, path, is_https)
        ]
        return "; ".join(matching) if matching else None

    def get_bearer_header(self, origin: str) -> Optional[str]:
        for tok in self.bearer_tokens.values():
            if tok.matches_origin(origin):
                return f"Bearer {tok.token}"
        return None

    def get_csrf_header(self, origin: str) -> Optional[Tuple[str, str]]:
        for tok in self.csrf_tokens.values():
            if tok.matches_origin(origin):
                return (tok.header_name, tok.csrf_token)
        return None

    def to_safe_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_origin": self.target_origin,
            "scope": self.scope,
            "role": self.role,
            "authentication_state": self.authentication_state.value,
            "verification_status": self.verification_status.value,
            "cookies": [c.to_safe_dict() for c in self.cookies.values()],
            "bearer_tokens": [b.to_safe_dict() for b in self.bearer_tokens.values()],
            "csrf_tokens": [cs.to_safe_dict() for cs in self.csrf_tokens.values()],
            "source_evidence_ids": self.source_evidence_ids,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
        }


class SessionStore:
    """
    Authoritative stateful session manager for autonomous web/HTTP operations.
    Maintains domain-bound cookie jars, bearer credentials, and CSRF tokens across tool calls.
    """

    def __init__(self, default_scope: Optional[List[str]] = None):
        self.sessions: Dict[str, Session] = {}
        self.default_scope: List[str] = default_scope or ["localhost", "127.0.0.1"]
        self.active_session_id: Optional[str] = None
        self._discovered_endpoints: List[Dict[str, Any]] = []

    def create_session(
        self,
        target_origin: str,
        scope: Optional[List[str]] = None,
        role: str = "default",
        session_id: Optional[str] = None,
        source_evidence_ids: Optional[List[str]] = None,
        acquisition_action: str = "",
        auth_state: AuthenticationState = AuthenticationState.UNAUTHENTICATED,
        parent_session_id: Optional[str] = None,
    ) -> Session:
        """Creates and registers a new scope-bound session."""
        sid = session_id or f"SESS-{uuid.uuid4().hex[:6].upper()}"
        clean_origin = target_origin.split("://")[-1].split("/")[0]

        session = Session(
            session_id=sid,
            target_origin=clean_origin,
            scope=scope or list(self.default_scope),
            role=role,
            authentication_state=auth_state,
            source_evidence_ids=source_evidence_ids or [],
            acquisition_action=acquisition_action,
            parent_session_id=parent_session_id,
        )
        self.sessions[sid] = session
        if self.active_session_id is None or role == "default":
            self.active_session_id = sid
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)

    def list_sessions(self, target_origin: Optional[str] = None, role: Optional[str] = None) -> List[Session]:
        res = list(self.sessions.values())
        if target_origin:
            clean_o = target_origin.split("://")[-1].split("/")[0].lower()
            res = [s for s in res if s.target_origin.lower() == clean_o]
        if role:
            res = [s for s in res if s.role == role]
        return res

    def get_active_session_for_request(
        self,
        target_url: str,
        role: str = "default"
    ) -> Optional[Session]:
        """Finds the most specific valid session matching target URL and role."""
        clean_origin = target_url.split("://")[-1].split("/")[0].lower()
        clean_host_no_port = clean_origin.split(":")[0]

        # 1. Look for matching role and origin
        candidates = [
            s for s in self.sessions.values()
            if s.is_valid() and (s.role == role or role == "default")
            and (
                s.target_origin.lower() == clean_origin
                or s.target_origin.lower().split(":")[0] == clean_host_no_port
                or clean_host_no_port.endswith(f".{s.target_origin.lower().split(':')[0]}")
            )
        ]

        if candidates:
            # Sort by authenticated first, then verified first, then newest
            candidates.sort(
                key=lambda s: (
                    s.is_authenticated(),
                    s.verification_status == SessionVerificationStatus.VERIFIED,
                    s.last_used_at
                ),
                reverse=True
            )
            return candidates[0]

        return None

    def get_request_auth_context(
        self,
        target_url: str,
        role: str = "default"
    ) -> Dict[str, Any]:
        """
        Resolves active authentication headers, cookies, and CSRF tokens for a candidate request.
        Returns:
            {
                "headers": Dict[str, str],
                "cookies": Dict[str, str],
                "session_id": Optional[str],
                "is_authenticated": bool,
                "verification_status": str
            }
        """
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path or "/"
        is_https = (parsed.scheme == "https")

        session = self.get_active_session_for_request(target_url, role=role)
        if not session:
            return {
                "headers": {},
                "cookies": {},
                "session_id": None,
                "is_authenticated": False,
                "verification_status": SessionVerificationStatus.UNVERIFIED.value
            }

        session.last_used_at = time.time()
        headers: Dict[str, str] = {}
        cookies_dict: Dict[str, str] = {}

        # 1. Attach cookies
        cookie_header = session.get_cookie_header(host, path, is_https)
        if cookie_header:
            headers["Cookie"] = cookie_header
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies_dict[k.strip()] = v.strip()

        # 2. Attach Bearer token
        bearer_header = session.get_bearer_header(host)
        if bearer_header:
            headers["Authorization"] = bearer_header

        # 3. Attach CSRF token
        csrf = session.get_csrf_header(host)
        if csrf:
            headers[csrf[0]] = csrf[1]

        return {
            "headers": headers,
            "cookies": cookies_dict,
            "session_id": session.session_id,
            "is_authenticated": session.is_authenticated(),
            "verification_status": session.verification_status.value
        }

    def update_from_http_response(
        self,
        target_url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        evidence_id: Optional[str] = None,
        session_id: Optional[str] = None,
        role: str = "default",
    ) -> Tuple[Session, List[Dict[str, Any]]]:
        """
        Parses Set-Cookie, Bearer authorization, CSRF tokens, and response links
        from an HTTP response and updates the appropriate Session.
        Returns (updated_session, newly_discovered_endpoints).
        """
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.netloc or parsed.path.split("/")[0]
        clean_host = host.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        req_path = parsed.path or "/"

        session = self.get_session(session_id) if session_id else self.get_active_session_for_request(target_url, role=role)
        if not session:
            session = self.create_session(
                target_origin=host,
                scope=list(self.default_scope),
                role=role,
                source_evidence_ids=[evidence_id] if evidence_id else []
            )

        if evidence_id and evidence_id not in session.source_evidence_ids:
            session.source_evidence_ids.append(evidence_id)

        # Normalize headers to lowercase keys for inspection
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Check for Authentication Failures (401 Unauthorized / 403 Forbidden / Expired)
        if status_code == 401:
            session.authentication_state = AuthenticationState.EXPIRED
        elif status_code == 403 and session.authentication_state == AuthenticationState.AUTHENTICATED:
            # Permission denied on authenticated session
            pass

        # 2. Extract Set-Cookie Headers
        set_cookie_raw = None
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookie_raw = v
                break

        if set_cookie_raw:
            self._parse_and_add_cookies(set_cookie_raw, clean_host, req_path, session)

        # Also inspect raw output body or cookies embedded in text (e.g. "session=...")
        if body and "session=" in body:
            cookie_match = re.search(r"\b(session|token|auth_token|PHPSESSID|JSESSIONID)=([a-zA-Z0-9_\-\.\:]+)", body)
            if cookie_match:
                c_name, c_val = cookie_match.group(1), cookie_match.group(2)
                session.add_cookie(Cookie(
                    name=c_name,
                    value=c_val,
                    domain=clean_host,
                    path="/"
                ))

        # 3. Extract Bearer / API Tokens from JSON responses
        if body and body.strip().startswith("{") and body.strip().endswith("}"):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    tok_val = data.get("token") or data.get("access_token") or data.get("bearer") or data.get("jwt")
                    if tok_val and isinstance(tok_val, str):
                        session.add_bearer_token(BearerToken(
                            token=tok_val,
                            origin=host,
                            scope=session.scope,
                            source_evidence_id=evidence_id
                        ))
            except Exception:
                pass

        # 4. Extract CSRF Tokens from HTML forms or response headers
        if "x-csrf-token" in headers_lower:
            session.add_csrf_token(CSRFToken(
                csrf_token=headers_lower["x-csrf-token"],
                source_endpoint=req_path,
                source_evidence_id=evidence_id,
                target_origin=host,
                header_name="X-CSRF-Token"
            ))
        elif body and "<input" in body and "csrf" in body.lower():
            csrf_m = re.search(r'<input[^>]+name=["\']([^"\']*csrf[^"\']*)["\'][^>]+value=["\']([^"\']+)["\']', body, re.IGNORECASE)
            if not csrf_m:
                csrf_m = re.search(r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']([^"\']*csrf[^"\']*)["\']', body, re.IGNORECASE)
                if csrf_m:
                    f_name, f_val = csrf_m.group(2), csrf_m.group(1)
                else:
                    f_name, f_val = None, None
            else:
                f_name, f_val = csrf_m.group(1), csrf_m.group(2)

            if f_name and f_val:
                session.add_csrf_token(CSRFToken(
                    csrf_token=f_val,
                    source_endpoint=req_path,
                    source_evidence_id=evidence_id,
                    target_origin=host,
                    field_name=f_name
                ))

        # 5. Extract Newly Discovered Endpoints (HTML links, forms, redirects, API routes)
        discovered_eps = self._extract_endpoints_from_response(
            target_url=target_url,
            status_code=status_code,
            headers=headers,
            body=body,
            evidence_id=evidence_id,
            auth_context=session.session_id
        )

        return session, discovered_eps

    def _parse_and_add_cookies(self, set_cookie_header: str, default_domain: str, default_path: str, session: Session) -> None:
        """Parses standard Set-Cookie strings with attributes."""
        # Split on comma only when followed by a cookie name=value pattern
        cookie_chunks = re.split(r",\s*(?=[a-zA-Z0-9_\-]+=)", set_cookie_header)
        for chunk in cookie_chunks:
            parts = [p.strip() for p in chunk.split(";") if p.strip()]
            if not parts:
                continue

            first_part = parts[0]
            if "=" not in first_part:
                continue

            c_name, c_val = first_part.split("=", 1)
            c_name, c_val = c_name.strip(), c_val.strip()

            c_domain = default_domain
            c_path = "/"
            c_secure = False
            c_http_only = False
            c_expiry = None
            c_same_site = None

            for attr in parts[1:]:
                attr_low = attr.lower()
                if attr_low.startswith("domain="):
                    c_domain = attr.split("=", 1)[1].strip().lstrip(".")
                elif attr_low.startswith("path="):
                    c_path = attr.split("=", 1)[1].strip()
                elif attr_low == "secure":
                    c_secure = True
                elif attr_low == "httponly":
                    c_http_only = True
                elif attr_low.startswith("max-age="):
                    try:
                        max_age = float(attr.split("=", 1)[1].strip())
                        c_expiry = time.time() + max_age
                    except ValueError:
                        pass
                elif attr_low.startswith("samesite="):
                    c_same_site = attr.split("=", 1)[1].strip()

            cookie = Cookie(
                name=c_name,
                value=c_val,
                domain=c_domain,
                path=c_path,
                secure=c_secure,
                http_only=c_http_only,
                expiry=c_expiry,
                same_site=c_same_site
            )
            session.add_cookie(cookie)

    def _extract_endpoints_from_response(
        self,
        target_url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        evidence_id: Optional[str],
        auth_context: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Extracts scope-bound links, forms, and redirects from an HTTP response."""
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
        base_origin = f"{parsed.scheme or 'http'}://{parsed.netloc}"
        discovered: List[Dict[str, Any]] = []
        seen_paths: Set[str] = set()

        # 1. Check Location header (Redirect)
        headers_lower = {k.lower(): v for k, v in headers.items()}
        if "location" in headers_lower:
            loc = headers_lower["location"]
            full_loc = urllib.parse.urljoin(target_url, loc)
            loc_parsed = urllib.parse.urlparse(full_loc)
            if loc_parsed.path and loc_parsed.path not in seen_paths:
                seen_paths.add(loc_parsed.path)
                discovered.append({
                    "url": full_loc,
                    "path": loc_parsed.path,
                    "method": "GET",
                    "discovery_reason": f"HTTP {status_code} Redirect Location",
                    "auth_context": auth_context,
                    "evidence_id": evidence_id
                })

        # 2. Extract HTML links <a href="..."> and forms <form action="...">
        if body:
            # Links
            for m in re.finditer(r'<a\s+[^>]*href=["\']([^"\'#]+)["\']', body, re.IGNORECASE):
                href = m.group(1).strip()
                if href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                full_url = urllib.parse.urljoin(target_url, href)
                u_parsed = urllib.parse.urlparse(full_url)
                # Keep within scope / origin
                if u_parsed.netloc == parsed.netloc and u_parsed.path and u_parsed.path not in seen_paths:
                    seen_paths.add(u_parsed.path)
                    discovered.append({
                        "url": full_url,
                        "path": u_parsed.path,
                        "method": "GET",
                        "discovery_reason": "Discovered in HTML anchor tag",
                        "auth_context": auth_context,
                        "evidence_id": evidence_id
                    })

            # Forms
            for m in re.finditer(r'<form\s+[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?([a-zA-Z]+)?["\']?', body, re.IGNORECASE):
                action = m.group(1).strip() or parsed.path
                f_method = (m.group(2) or "GET").upper()
                full_url = urllib.parse.urljoin(target_url, action)
                u_parsed = urllib.parse.urlparse(full_url)
                if u_parsed.netloc == parsed.netloc and u_parsed.path and u_parsed.path not in seen_paths:
                    seen_paths.add(u_parsed.path)
                    discovered.append({
                        "url": full_url,
                        "path": u_parsed.path,
                        "method": f_method,
                        "discovery_reason": f"Discovered in HTML form (method={f_method})",
                        "auth_context": auth_context,
                        "evidence_id": evidence_id
                    })

        return discovered

    def mark_session_verified(self, session_id: str, evidence_id: Optional[str] = None) -> bool:
        """Promotes an unverified session to verified upon independent proof."""
        session = self.get_session(session_id)
        if session:
            session.verification_status = SessionVerificationStatus.VERIFIED
            session.authentication_state = AuthenticationState.AUTHENTICATED
            if evidence_id and evidence_id not in session.source_evidence_ids:
                session.source_evidence_ids.append(evidence_id)
            return True
        return False

    def invalidate_session(self, session_id: str, reason: str = "invalidated") -> bool:
        session = self.get_session(session_id)
        if session:
            session.authentication_state = AuthenticationState.REVOKED
            session.metadata["invalidation_reason"] = reason
            return True
        return False

    def merge_session(self, source_session_id: str, target_session_id: str) -> bool:
        """Merges cookies and tokens from source session into target session."""
        src = self.get_session(source_session_id)
        dst = self.get_session(target_session_id)
        if not src or not dst:
            return False

        for c in src.cookies.values():
            dst.add_cookie(c)
        for b in src.bearer_tokens.values():
            dst.add_bearer_token(b)
        for cs in src.csrf_tokens.values():
            dst.add_csrf_token(cs)
        for eid in src.source_evidence_ids:
            if eid not in dst.source_evidence_ids:
                dst.source_evidence_ids.append(eid)
        return True

    def export_safe_summary(self) -> List[Dict[str, Any]]:
        """Returns non-sensitive summary of all active sessions for planner state & telemetry."""
        return [s.to_safe_dict() for s in self.sessions.values()]
