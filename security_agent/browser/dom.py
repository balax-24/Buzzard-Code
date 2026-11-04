"""
DOM Snapshot & Structural Reduction Engine for Application-Surface Intelligence.

Extracts high-value application structures:
- Forms, inputs, buttons, CSRF fields, enctype
- Hyperlinks, anchors, redirects
- Inline and external script references
- API candidates (fetch, axios, AJAX, REST endpoints)
- WebSocket connections (ws://, wss://)
- Authentication state indicators

Produces compact DOMSnapshot objects and computes context reduction metrics.
"""

from __future__ import annotations

import re
import uuid
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class FormField:
    """Represents an input element, textarea, select, or button."""
    name: str = ""
    type: str = "text"
    id: str = ""
    value: str = ""
    placeholder: str = ""
    required: bool = False
    is_hidden: bool = False
    is_csrf: bool = False
    options: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "id": self.id,
            "value": self.value,
            "placeholder": self.placeholder,
            "required": self.required,
            "is_hidden": self.is_hidden,
            "is_csrf": self.is_csrf,
            "options": self.options,
        }


@dataclass
class FormRecord:
    """Represents an HTML form element with all associated inputs and actions."""
    form_id: str
    method: str = "GET"
    action: str = ""
    enctype: str = "application/x-www-form-urlencoded"
    fields: List[FormField] = field(default_factory=list)
    submit_controls: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    @property
    def has_csrf(self) -> bool:
        return any(f.is_csrf for f in self.fields)

    @property
    def is_login_form(self) -> bool:
        field_names = [f.name.lower() for f in self.fields]
        return any("user" in n or "login" in n or "email" in n for n in field_names) and any(
            "pass" in n or f.type == "password" for f in self.fields for n in [f.name.lower()]
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "form_id": self.form_id,
            "method": self.method.upper(),
            "action": self.action,
            "enctype": self.enctype,
            "fields": [f.to_dict() for f in self.fields],
            "submit_controls": self.submit_controls,
            "has_csrf": self.has_csrf,
            "is_login_form": self.is_login_form,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class LinkRecord:
    """Represents a discovered link or anchor element."""
    text: str
    href: str
    target: str = ""
    rel: str = ""
    is_internal: bool = True
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "href": self.href,
            "target": self.target,
            "rel": self.rel,
            "is_internal": self.is_internal,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class ScriptRecord:
    """Represents an inline or external JavaScript asset."""
    src: Optional[str] = None
    inline_content_snippet: str = ""
    is_external: bool = False
    integrity: Optional[str] = None
    async_attr: bool = False
    defer_attr: bool = False
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "inline_snippet": self.inline_content_snippet[:200] if self.inline_content_snippet else "",
            "is_external": self.is_external,
            "integrity": self.integrity,
        }


@dataclass
class APICandidate:
    """Represents an API endpoint candidate discovered from DOM or JavaScript."""
    url: str
    method: str = "GET"
    source_context: str = "script_static"  # "fetch", "axios", "ajax", "rest_pattern"
    parameters: List[str] = field(default_factory=list)
    status: str = "OBSERVED"  # "OBSERVED", "DISCOVERED", "REACHABLE", "VERIFIED"
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method.upper(),
            "source_context": self.source_context,
            "parameters": self.parameters,
            "status": self.status,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class WebSocketEndpoint:
    """Represents a discovered WebSocket connection or URL."""
    url: str
    origin_page: str = ""
    protocols: List[str] = field(default_factory=list)
    status: str = "OBSERVED"
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "origin_page": self.origin_page,
            "protocols": self.protocols,
            "status": self.status,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class DOMSnapshot:
    """Authoritative, compact structural snapshot of a browser page."""
    snapshot_id: str
    url: str
    title: str = ""
    status_code: int = 200
    forms: List[FormRecord] = field(default_factory=list)
    links: List[LinkRecord] = field(default_factory=list)
    inputs_outside_forms: List[FormField] = field(default_factory=list)
    scripts: List[ScriptRecord] = field(default_factory=list)
    api_candidates: List[APICandidate] = field(default_factory=list)
    websockets: List[WebSocketEndpoint] = field(default_factory=list)
    visible_text_snippet: str = ""
    auth_indicators: List[str] = field(default_factory=list)
    raw_size: int = 0
    reduced_size: int = 0
    reduction_ratio: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)

    def get_discovered_urls(self) -> List[str]:
        """Returns all deduplicated absolute URLs extracted from the snapshot."""
        urls: Set[str] = set()
        if self.url:
            urls.add(self.url)
        for l in self.links:
            if l.href and not l.href.startswith(("#", "javascript:", "mailto:", "tel:")):
                urls.add(l.href)
        for f in self.forms:
            if f.action and not f.action.startswith(("#", "javascript:")):
                urls.add(f.action)
        for a in self.api_candidates:
            if a.url:
                urls.add(a.url)
        for s in self.scripts:
            if s.src:
                urls.add(s.src)
        return sorted(list(urls))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "url": self.url,
            "title": self.title,
            "status_code": self.status_code,
            "forms": [f.to_dict() for f in self.forms],
            "links": [l.to_dict() for l in self.links],
            "inputs_outside_forms": [i.to_dict() for i in self.inputs_outside_forms],
            "scripts": [s.to_dict() for s in self.scripts],
            "api_candidates": [a.to_dict() for a in self.api_candidates],
            "websockets": [w.to_dict() for w in self.websockets],
            "auth_indicators": self.auth_indicators,
            "raw_size": self.raw_size,
            "reduced_size": self.reduced_size,
            "reduction_ratio": round(self.reduction_ratio, 4),
            "evidence_ids": self.evidence_ids,
        }

    def to_planner_context(self) -> str:
        """Produces a compact, high-signal representation for the LLM planner."""
        lines = [
            f"=== DOM SNAPSHOT [{self.snapshot_id}] ===",
            f"URL: {self.url} (HTTP {self.status_code}) | Title: '{self.title}'",
            f"Reduction: {self.raw_size}B -> {self.reduced_size}B ({self.reduction_ratio:.1%} saved)",
        ]

        if self.auth_indicators:
            lines.append(f"AUTH SIGNALS: {', '.join(self.auth_indicators)}")

        if self.forms:
            lines.append("FORMS:")
            for f in self.forms:
                fields_summary = ", ".join(
                    f"{fld.name}:{fld.type}" + ("[CSRF]" if fld.is_csrf else "")
                    for fld in f.fields
                ) or "no fields"
                lines.append(f"  • [{f.method}] {f.action} (id='{f.form_id}') -> {fields_summary}")

        if self.api_candidates:
            lines.append("DISCOVERED APIS / ROUTES:")
            for a in self.api_candidates[:8]:
                lines.append(f"  • [{a.method}] {a.url} (source: {a.source_context})")

        if self.websockets:
            lines.append("WEBSOCKETS:")
            for w in self.websockets:
                lines.append(f"  • {w.url}")

        if self.links:
            lines.append("KEY LINKS:")
            for l in self.links[:10]:
                lines.append(f"  • {l.text or '[Link]'} -> {l.href}")

        if self.visible_text_snippet:
            lines.append(f"CONTENT SNIPPET:\n  {self.visible_text_snippet[:300]}")

        lines.append("=========================================")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Static JavaScript Surface Extractor
# ---------------------------------------------------------------------------

class JavaScriptSurfaceExtractor:
    """Lightweight static pattern matcher for JavaScript route and endpoint discovery."""

    FETCH_PATTERN = re.compile(r"fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.IGNORECASE)
    AXIOS_PATTERN = re.compile(r"axios\s*(?:\.(?:get|post|put|delete|patch))?\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.IGNORECASE)
    AJAX_PATTERN  = re.compile(r"\$\s*\.\s*(?:ajax|get|post)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.IGNORECASE)
    WS_PATTERN    = re.compile(r"new\s+WebSocket\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.IGNORECASE)
    WS_URL_PATTERN = re.compile(r"['\"`](wss?://[^'\"`\s]+)['\"`]", re.IGNORECASE)
    REST_PATTERN  = re.compile(r"['\"`](/(?:api|v[0-9]|graphql|admin|internal|upload|debug|system|auth|users)[^'\"`\s]*)['\"`]", re.IGNORECASE)

    @classmethod
    def extract_from_script(
        cls,
        script_content: str,
        base_url: str,
        evidence_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Extracts candidate APIs, WebSockets, and routes from a script string."""
        apis: List[APICandidate] = []
        websockets: List[WebSocketEndpoint] = []
        seen_urls: Set[str] = set()
        eids = list(evidence_ids or [])

        # 1. fetch() calls
        for m in cls.FETCH_PATTERN.finditer(script_content):
            raw_target = m.group(1).strip()
            full_url = urllib.parse.urljoin(base_url, raw_target)
            if full_url not in seen_urls:
                seen_urls.add(full_url)
                apis.append(APICandidate(
                    url=full_url,
                    method="GET",
                    source_context="fetch()",
                    evidence_ids=eids
                ))

        # 2. axios calls
        for m in cls.AXIOS_PATTERN.finditer(script_content):
            raw_target = m.group(1).strip()
            full_url = urllib.parse.urljoin(base_url, raw_target)
            if full_url not in seen_urls:
                seen_urls.add(full_url)
                apis.append(APICandidate(
                    url=full_url,
                    method="API",
                    source_context="axios()",
                    evidence_ids=eids
                ))

        # 3. $.ajax calls
        for m in cls.AJAX_PATTERN.finditer(script_content):
            raw_target = m.group(1).strip()
            full_url = urllib.parse.urljoin(base_url, raw_target)
            if full_url not in seen_urls:
                seen_urls.add(full_url)
                apis.append(APICandidate(
                    url=full_url,
                    method="AJAX",
                    source_context="jQuery.ajax()",
                    evidence_ids=eids
                ))

        # 4. WebSocket calls
        for m in cls.WS_PATTERN.finditer(script_content):
            raw_ws = m.group(1).strip()
            if raw_ws.startswith("/"):
                # Convert http:// to ws://
                p = urllib.parse.urlparse(base_url)
                scheme = "wss" if p.scheme == "https" else "ws"
                full_ws = f"{scheme}://{p.netloc}{raw_ws}"
            else:
                full_ws = raw_ws
            if full_ws not in seen_urls:
                seen_urls.add(full_ws)
                websockets.append(WebSocketEndpoint(
                    url=full_ws,
                    origin_page=base_url,
                    evidence_ids=eids
                ))

        for m in cls.WS_URL_PATTERN.finditer(script_content):
            ws_url = m.group(1).strip()
            if ws_url not in seen_urls:
                seen_urls.add(ws_url)
                websockets.append(WebSocketEndpoint(
                    url=ws_url,
                    origin_page=base_url,
                    evidence_ids=eids
                ))

        # 5. Static REST-like route literals
        for m in cls.REST_PATTERN.finditer(script_content):
            raw_route = m.group(1).strip()
            full_url = urllib.parse.urljoin(base_url, raw_route)
            if full_url not in seen_urls:
                seen_urls.add(full_url)
                apis.append(APICandidate(
                    url=full_url,
                    method="GET",
                    source_context="static_js_string",
                    evidence_ids=eids
                ))

        return {
            "api_candidates": apis,
            "websockets": websockets,
        }


# ---------------------------------------------------------------------------
# HTML Parser & DOM Reducer
# ---------------------------------------------------------------------------

class _DOMParser(HTMLParser):
    """Custom streaming HTML parser for structured feature extraction."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.in_title = False
        self.in_script = False
        self.current_script_attrs: Dict[str, str] = {}
        self.current_script_text = ""

        self.forms: List[FormRecord] = []
        self.current_form: Optional[FormRecord] = None

        self.links: List[LinkRecord] = []
        self.inputs_outside_forms: List[FormField] = []
        self.scripts: List[ScriptRecord] = []
        self.text_chunks: List[str] = []
        self.in_ignored_tag = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict: Dict[str, str] = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self.in_title = True
        elif tag in ("style", "svg", "noscript"):
            self.in_ignored_tag = True
        elif tag == "script":
            self.in_script = True
            self.current_script_attrs = attr_dict
            self.current_script_text = ""
            src = attr_dict.get("src")
            if src:
                full_src = urllib.parse.urljoin(self.base_url, src)
                self.scripts.append(ScriptRecord(
                    src=full_src,
                    is_external=bool(urllib.parse.urlparse(full_src).netloc != urllib.parse.urlparse(self.base_url).netloc),
                    integrity=attr_dict.get("integrity"),
                    async_attr=("async" in attr_dict),
                    defer_attr=("defer" in attr_dict),
                ))

        elif tag == "form":
            action = attr_dict.get("action") or self.base_url
            full_action = urllib.parse.urljoin(self.base_url, action)
            form_id = attr_dict.get("id") or attr_dict.get("name") or f"form_{len(self.forms) + 1}"
            self.current_form = FormRecord(
                form_id=form_id,
                method=(attr_dict.get("method") or "GET").upper(),
                action=full_action,
                enctype=attr_dict.get("enctype") or "application/x-www-form-urlencoded",
                fields=[],
                submit_controls=[]
            )

        elif tag in ("input", "textarea", "select", "button"):
            name = attr_dict.get("name", "")
            inp_type = (attr_dict.get("type") or ("button" if tag == "button" else "text")).lower()
            inp_id = attr_dict.get("id", "")
            val = attr_dict.get("value", "")
            ph = attr_dict.get("placeholder", "")
            req = "required" in attr_dict
            is_hid = (inp_type == "hidden")
            is_csrf = bool(
                "csrf" in name.lower()
                or "csrf" in inp_id.lower()
                or "xsrf" in name.lower()
                or "token" in name.lower() and is_hid
            )

            field_obj = FormField(
                name=name,
                type=inp_type,
                id=inp_id,
                value=val,
                placeholder=ph,
                required=req,
                is_hidden=is_hid,
                is_csrf=is_csrf
            )

            if self.current_form is not None:
                self.current_form.fields.append(field_obj)
                if inp_type in ("submit", "button") or tag == "button":
                    self.current_form.submit_controls.append(name or inp_id or val or "Submit")
            else:
                self.inputs_outside_forms.append(field_obj)

        elif tag == "a":
            href = attr_dict.get("href")
            if href:
                full_href = urllib.parse.urljoin(self.base_url, href)
                parsed_base = urllib.parse.urlparse(self.base_url)
                parsed_href = urllib.parse.urlparse(full_href)
                is_internal = (parsed_href.netloc == parsed_base.netloc or not parsed_href.netloc)
                self.links.append(LinkRecord(
                    text="",
                    href=full_href,
                    target=attr_dict.get("target", ""),
                    rel=attr_dict.get("rel", ""),
                    is_internal=is_internal
                ))

    def handle_endtag(self, tag: str):
        if tag == "title":
            self.in_title = False
        elif tag in ("style", "svg", "noscript"):
            self.in_ignored_tag = False
        elif tag == "script":
            self.in_script = False
            if self.current_script_text.strip():
                self.scripts.append(ScriptRecord(
                    src=None,
                    inline_content_snippet=self.current_script_text.strip(),
                    is_external=False
                ))
        elif tag == "form":
            if self.current_form is not None:
                self.forms.append(self.current_form)
                self.current_form = None

    def handle_data(self, data: str):
        if self.in_title:
            self.title += data.strip()
        elif self.in_script:
            self.current_script_text += data
        elif not self.in_ignored_tag:
            clean = data.strip()
            if clean:
                self.text_chunks.append(clean)
                if self.links and not self.links[-1].text:
                    self.links[-1].text = clean


class DOMReducer:
    """
    Main reducer that transforms raw HTML/DOM into a compact, secure DOMSnapshot.
    Computes size reduction ratios and extracts full application surface intelligence.
    """

    AUTH_KEYWORDS = [
        "login", "signin", "sign in", "sign-in", "logout", "signout", "sign out",
        "admin", "administrator", "dashboard", "authenticated", "welcome",
        "user profile", "account", "unauthorized", "forbidden"
    ]

    @classmethod
    def reduce(
        cls,
        html_content: str,
        url: str = "http://localhost/",
        title: str = "",
        status_code: int = 200,
        evidence_ids: Optional[List[str]] = None,
        snapshot_id: Optional[str] = None,
    ) -> DOMSnapshot:
        """Parses and reduces raw HTML into a structured DOMSnapshot."""
        raw_size = len(html_content.encode("utf-8")) if html_content else 0
        sid = snapshot_id or f"SNAP-{uuid.uuid4().hex[:6].upper()}"
        eids = list(evidence_ids or [])

        parser = _DOMParser(base_url=url)
        try:
            parser.feed(html_content or "")
        except Exception:
            pass

        final_title = title or parser.title or "Untitled"
        visible_text = " ".join(parser.text_chunks[:50])

        # Extract JS surface candidates
        all_apis: List[APICandidate] = []
        all_ws: List[WebSocketEndpoint] = []

        for s in parser.scripts:
            if s.inline_content_snippet:
                js_res = JavaScriptSurfaceExtractor.extract_from_script(
                    s.inline_content_snippet, base_url=url, evidence_ids=eids
                )
                all_apis.extend(js_res["api_candidates"])
                all_ws.extend(js_res["websockets"])

        # Also parse whole HTML for inline onclick / fetch patterns
        html_js_res = JavaScriptSurfaceExtractor.extract_from_script(
            html_content, base_url=url, evidence_ids=eids
        )
        for a in html_js_res["api_candidates"]:
            if not any(x.url == a.url for x in all_apis):
                all_apis.append(a)
        for w in html_js_res["websockets"]:
            if not any(x.url == w.url for x in all_ws):
                all_ws.append(w)

        # Detect Authentication State Signals in page text
        auth_signals: List[str] = []
        low_text = (final_title + " " + html_content[:2000]).lower()
        for kw in cls.AUTH_KEYWORDS:
            if kw in low_text and kw not in auth_signals:
                auth_signals.append(kw)

        # Build Snapshot
        snapshot = DOMSnapshot(
            snapshot_id=sid,
            url=url,
            title=final_title,
            status_code=status_code,
            forms=parser.forms,
            links=parser.links[:50],
            inputs_outside_forms=parser.inputs_outside_forms,
            scripts=parser.scripts[:20],
            api_candidates=all_apis[:30],
            websockets=all_ws[:10],
            visible_text_snippet=visible_text[:400],
            auth_indicators=auth_signals,
            raw_size=raw_size,
            evidence_ids=eids
        )

        reduced_text = snapshot.to_planner_context()
        reduced_size = len(reduced_text.encode("utf-8"))
        snapshot.reduced_size = reduced_size

        if raw_size > 0:
            snapshot.reduction_ratio = max(0.0, 1.0 - (float(reduced_size) / float(raw_size)))
        else:
            snapshot.reduction_ratio = 0.0

        return snapshot
