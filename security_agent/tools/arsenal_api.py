"""
API security capabilities: OpenAPI/Swagger parsing, GraphQL introspection,
JWT inspection/cracking, rate-limit testing, and the request-diff access
control comparator.

Every capability is a strategy chain (binary-first, Python fallback) so the
agent keeps working even when no external tool is installed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from security_agent.tools.fallback import FallbackRunner, strategy_from_cmd


# ---------------------------------------------------------------------------
# HTTP helper (shared by the Python strategies in this module)
# ---------------------------------------------------------------------------

def _http(method: str, url: str, data: Optional[Dict[str, Any]] = None,
          headers: Optional[Dict[str, str]] = None, timeout: float = 10.0):
    """Minimal HTTP client returning (status, headers, body, elapsed)."""
    import urllib.request
    body = None
    hdrs = {"User-Agent": "buzzard-code/1.0"}
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace"), round(time.time() - started, 3)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace"), round(time.time() - started, 3)
    except Exception as e:
        return -1, {}, str(e), round(time.time() - started, 3)


# ---------------------------------------------------------------------------
# openapi_parse
# ---------------------------------------------------------------------------

def _openapi_fetch_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    base = (kw.get("url") or "").rstrip("/")
    if not base:
        return False, "url required", ""
    paths = [p for p in [
        kw.get("doc_url"),
        "/openapi.json", "/swagger.json", "/api-docs", "/swagger/v1/swagger.json",
        "/openapi.yaml", "/swagger.yaml", "/api/openapi.json",
    ] if p]
    last_err = ""
    for suffix in paths:
        url = base + (suffix if suffix.startswith("/") else "/" + suffix)
        st, hd, body, _ = _http("GET", url, timeout=8)
        if st != 200 or not body.strip():
            last_err = f"{url} -> {st}"
            continue
        spec = None
        for loader in (json.loads, _yaml_load):
            try:
                spec = loader(body)
                break
            except Exception:
                continue
        if not isinstance(spec, dict):
            last_err = f"{url} -> unparseable"
            continue
        endpoints = []
        for path, ops in (spec.get("paths") or {}).items():
            for method in ("get", "post", "put", "delete", "patch"):
                if method in ops:
                    op = ops[method]
                    endpoints.append(f"{method.upper()} {path}  # {op.get('summary', '')}".rstrip())
        info = spec.get("info", {})
        host = spec.get("host") or hd.get("X-Forwarded-Host", "")
        out = [
            f"OpenAPI spec: {info.get('title', '?')} v{info.get('version', '?')}",
            f"Source: {url}",
            f"Servers: {json.dumps(spec.get('servers', []))}",
            f"Host header: {host}",
            "",
            f"Endpoints ({len(endpoints)}):",
        ] + (sorted(endpoints) if endpoints else ["  (no paths found)"])
        return True, f"{len(endpoints)} endpoints parsed from {url}", "\n".join(out)
    return False, "no OpenAPI/Swagger doc found", last_err or "no candidates tried"


def _yaml_load(text: str) -> Any:
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        raise ValueError("yaml unavailable")


def _openapi_chain() -> List[Tuple[str, Any]]:
    return [("python-openapi", _openapi_fetch_py)]


# ---------------------------------------------------------------------------
# graphql_introspect
# ---------------------------------------------------------------------------

GRAPHQL_INTROSPECTION = """query { __schema { queryType { name } mutationType { name }
types { name kind fields { name args { name type { name kind ofType { name kind } } }
type { name kind ofType { name kind } } } } } }"""


def _graphql_introspect_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    base = (kw.get("url") or "").rstrip("/")
    if not base:
        return False, "url required", ""
    candidates = []
    for p in (kw.get("endpoint"), "/graphql", "/graphiql", "/api/graphql", "/gql"):
        if p:
            candidates.append(base + (p if p.startswith("/") else "/" + p))
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        st, hd, body, _ = _http("POST", url, headers={"Content-Type": "application/json"},
                                data={"query": GRAPHQL_INTROSPECTION}, timeout=10)
        # urllib sends form-encoded; retry with raw JSON body
        if st not in (200, 400):
            continue
        try:
            payload = json.loads(body)
        except Exception:
            continue
        schema = (payload.get("data") or {}).get("__schema")
        if not schema:
            continue
        types = [t for t in schema.get("types", []) if not t.get("name", "").startswith("__")]
        lines = [
            f"GraphQL schema found at {url}",
            f"Query root: {schema.get('queryType', {}).get('name')}",
            f"Mutation root: {schema.get('mutationType', {}).get('name')}",
            f"Types ({len(types)}):",
        ]
        for t in sorted(types, key=lambda x: x.get("name", "")):
            fields = t.get("fields") or []
            names = ", ".join(f.get("name", "?") for f in fields[:20]) or "(scalar/enum)"
            lines.append(f"  {t.get('kind', '?')} {t.get('name')}: {names}")
        return True, f"GraphQL introspection succeeded at {url}", "\n".join(lines)
    return False, "no GraphQL endpoint responded to introspection", "tried: " + ", ".join(candidates)


def _graphql_chain() -> List[Tuple[str, Any]]:
    return [("python-graphql", _graphql_introspect_py)]


# ---------------------------------------------------------------------------
# jwt_decode / jwt_crack
# ---------------------------------------------------------------------------

def _b64url_decode(seg: str) -> str:
    pad = "=" * (-len(seg) % 4)
    raw = base64.urlsafe_b64decode(seg + pad)
    return raw.decode("utf-8", "replace")


def _jwt_decode_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    token = (kw.get("jwt") or kw.get("token") or "").strip()
    if not token:
        return False, "jwt required", ""
    parts = token.split(".")
    if len(parts) < 2:
        return False, "not a JWT (needs header.payload)", ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return False, f"JWT parse failed: {e}", ""
    alg = header.get("alg", "?")
    lines = [
        "=== JWT HEADER ===",
        json.dumps(header, indent=2),
        "=== JWT PAYLOAD ===",
        json.dumps(payload, indent=2),
        "",
        f"Algorithm: {alg}",
        f"Segments: {len(parts)} (signed: {len(parts) == 3})",
    ]
    if len(parts) == 3 and parts[2]:
        lines.append(f"Signature (b64url): {parts[2][:60]}...")
    if alg == "none":
        lines.append("[!] alg=none — signature can be trivially bypassed")
    elif alg and alg.lower().startswith("hs"):
        lines.append("[!] HS* — symmetric; crackable offline if the secret is weak (use jwt_crack)")
    return True, f"JWT decoded (alg={alg})", "\n".join(lines)


def _jwt_crack_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    token = (kw.get("jwt") or kw.get("token") or "").strip()
    if not token:
        return False, "jwt required", ""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False, "JWT must have 3 segments (signed)", ""
    header = json.loads(_b64url_decode(parts[0]))
    if (header.get("alg") or "").lower() not in ("hs256", "hs384", "hs512"):
        return False, f"alg {header.get('alg')} is not symmetric-HS (offline crack needs HS*)", ""
    signing_input = (parts[0] + "." + parts[1]).encode()
    sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    wordlist = runner.tool_available("john") or True  # fallback list below
    words: List[str] = []
    candidate_file = kw.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
    try:
        with open(candidate_file, "r", errors="replace") as f:
            words = [ln.strip() for ln in f]
    except Exception:
        pass
    if not words:
        words = ["admin", "password", "secret", "secretkey", "supersecretkey123", "changeme",
                 "123456", "qwerty", "letmein", "token", "jwt", "key", "your-256-bit-secret",
                 "test", "dev", "12345678", "abc123"]
    algo = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}[header["alg"].lower()]
    max_tries = int(kw.get("limit", 100_000))
    checked = 0
    for w in words:
        if checked >= max_tries:
            break
        checked += 1
        if hmac.new(w.encode(), signing_input, algo).digest() == sig:
            return True, f"JWT secret cracked: '{w}'", (
                f"Secret: {w}\nAlgorithm: {header.get('alg')}\n"
                "You can now forge tokens for ANY payload. Consider: role escalation, "
                "exp bypass, or user impersonation. See jwt_decode + request_diff.")
    return False, "secret not found in wordlist", f"{checked} candidates tried (no match)"

def _jwt_crack_chain() -> List[Tuple[str, Any]]:
    return [("python-jwt-crack", _jwt_crack_py)]


def _jwt_decode_chain() -> List[Tuple[str, Any]]:
    return [("python-jwt-decode", _jwt_decode_py)]


# ---------------------------------------------------------------------------
# rate_limit_test
# ---------------------------------------------------------------------------

def _rate_limit_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = kw.get("url", "")
    if not url:
        return False, "url required", ""
    method = (kw.get("method") or "GET").upper()
    data = kw.get("data")
    count = int(kw.get("count", 30))
    gap = float(kw.get("gap_s", 0.05))
    statuses: Dict[int, int] = {}
    samples: List[Tuple[int, int]] = []
    for i in range(count):
        st, hd, body, elapsed = _http(method, url, data=data, timeout=8)
        statuses[st] = statuses.get(st, 0) + 1
        if len(samples) < 10:
            samples.append((st, elapsed))
        time.sleep(gap)
    total_2xx = sum(v for k, v in statuses.items() if 200 <= k < 300)
    total_429 = statuses.get(429, 0)
    total_5xx = sum(v for k, v in statuses.items() if 500 <= k < 600)
    lines = [
        f"{count} requests to {url} (gap={gap}s)",
        f"Status distribution: {json.dumps(statuses)}",
        f"2xx: {total_2xx} | 429: {total_429} | 5xx: {total_5xx}",
        f"Sample latencies (status, s): {samples}",
    ]
    if total_429 == 0 and total_2xx > 0:
        lines.append("[!] No rate limiting observed — brute-force/lockout attacks are feasible.")
        return True, "no rate limiting detected", "\n".join(lines)
    if total_429 > 0:
        lines.append(f"[OK] Rate limiting present ({total_429} requests answered 429).")
    return True, f"{total_429} of {count} requests rate-limited", "\n".join(lines)


def _rate_limit_chain() -> List[Tuple[str, Any]]:
    return [("python-rate-limit", _rate_limit_py)]


# ---------------------------------------------------------------------------
# request_diff — the access-control comparator (IDOR / BOLA / privilege tests)
# ---------------------------------------------------------------------------

def _request_diff_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Send request A and request B, compare status/headers/body/timing/redirects."""
    method_a = (kw.get("method_a") or "GET").upper()
    url_a = kw.get("url_a") or kw.get("url")
    method_b = (kw.get("method_b") or method_a).upper()
    url_b = kw.get("url_b") or url_a
    if not url_a or not url_b:
        return False, "url_a/url_b required (or url for same-URL role comparison)", ""
    data_a = kw.get("data_a")
    data_b = kw.get("data_b")
    headers_a = _parse_headers(kw.get("headers_a"))
    headers_b = _parse_headers(kw.get("headers_b")) if kw.get("headers_b") else headers_a

    st_a, hd_a, body_a, dt_a = _http(method_a, url_a, data=data_a, headers=headers_a, timeout=10)
    st_b, hd_b, body_b, dt_b = _http(method_b, url_b, data=data_b, headers=headers_b, timeout=10)

    def _summarize(body: str) -> str:
        import re
        text = re.sub(r"<[^>]+>", " ", body)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:220]

    status_same = st_a == st_b
    body_same = body_a == body_b
    len_a, len_b = len(body_a), len(body_b)
    loc_a, loc_b = hd_a.get("Location", ""), hd_b.get("Location", "")
    id_a = _extract_ids(body_a, hd_a)
    id_b = _extract_ids(body_b, hd_b)

    lines = [
        f"REQUEST A  {method_a} {url_a}  -> {st_a} ({dt_a}s)  headers={len(hd_a)} body={len_a}B",
        f"REQUEST B  {method_b} {url_b}  -> {st_b} ({dt_b}s)  headers={len(hd_b)} body={len_b}B",
        "",
        "COMPARISON",
        f"  Status codes identical : {status_same}  ({st_a} vs {st_b})",
        f"  Bodies identical       : {body_same}  ({len_a}B vs {len_b}B)",
        f"  Timing delta           : {dt_a - dt_b:+.3f}s",
        f"  Redirects              : A='{loc_a}'  B='{loc_b}'",
        f"  Entity IDs in A        : {json.dumps(id_a)}",
        f"  Entity IDs in B        : {json.dumps(id_b)}",
        "",
        "  Body A: " + _summarize(body_a),
        "  Body B: " + _summarize(body_b),
    ]

    # Heuristic interpretation for access-control testing
    if st_a != st_b:
        if st_b in (401, 403) and st_a in (200, 302):
            lines.append("=> [OK] B was denied while A succeeded — authorization appears enforced.")
        elif st_a in (401, 403) and st_b in (200, 302):
            lines.append("=> [!] B gained access where A was denied — possible privilege/IDOR issue.")
        else:
            lines.append("=> [~] Different status codes — inspect why (authz? not-found? redirect?).")
    else:
        if body_same and len_a == len_b:
            lines.append("=> [~] Identical responses across contexts — check whether data leakage/IDOR applies.")
        elif st_b == 200 and st_a == 200:
            lines.append("=> [!] Both requests succeeded — verify the AUTHORIZATION CONTEXT differs and data matches requester.")
    return True, f"diff: A={st_a} B={st_b} bodies_equal={body_same}", "\n".join(lines)


def _parse_headers(raw: Optional[str]) -> Dict[str, str]:
    out = {}
    if not raw:
        return out
    for line in str(raw).split("\\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _extract_ids(body: str, headers: Dict[str, str]) -> List[str]:
    import re
    ids = []
    for pat in (r'["\']?id["\']?\s*[:=]\s*["\']?(\d+)', r'/(?:users|orders|items|accounts)/(\d+)'):
        ids += re.findall(pat, body or "", re.IGNORECASE)
    loc = headers.get("Location", "")
    m = re.search(r"/(\d+)$", loc)
    if m:
        ids.append(m.group(1))
    return sorted(set(ids))[:10]


def _request_diff_chain() -> List[Tuple[str, Any]]:
    return [("python-request-diff", _request_diff_py)]
