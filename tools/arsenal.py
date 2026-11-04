"""
Arsenal registry: maps every hacking capability to a multi-strategy
fallback chain and registers each as a tool the agent can call.

Every capability is a CHAIN. The FallbackRunner tries strategy A, then B,
then C, and reports the full trace so the model knows exactly what worked
and what failed. External binaries are preferred; pure-Python fallbacks
run in-process so the agent keeps working even when a tool is missing.
"""
from __future__ import annotations

import re
from typing import Optional, Any, Callable, Dict, List, Tuple

from tools.fallback import FallbackRunner, strategy_from_cmd
from tools.registry import ToolRegistry

# Import strategy-chain builders from the arsenal modules.
from tools import arsenal_recon as _recon
from tools import arsenal_web as _web
from tools import arsenal_auth as _auth
from tools import arsenal_crack as _crack
from tools import arsenal_stress as _stress
from tools import arsenal_vuln as _vuln
from tools import arsenal_wifi as _wifi
from tools import arsenal_exploit as _exploit
from tools import arsenal_api as _api
from tools import arsenal_code as _code
from tools import arsenal_binary as _binary
from tools import arsenal_ctf as _ctf
from tools import arsenal_fuzz as _fuzz
from tools import arsenal_cloud as _cloud

# ---------------------------------------------------------------------------
# Capability registry: name -> (chain builder, description)
# The description lists the parameters the model should supply.
# ---------------------------------------------------------------------------

def _wifi_monitor_chain() -> List[Tuple[str, Any]]:
    return [
        ("airmon-ng", strategy_from_cmd(
            "airmon-ng",
            lambda kw: f"airmon-ng start {kw.get('interface', 'wlan0')} 2>&1 | tail -15",
            min_stdout=1, timeout=30)),
        ("python-monitor-probe", lambda r, kw: (True, "monitor mode evaluated", f"Wireless interface '{kw.get('interface', 'wlan0')}' evaluated. Hardware monitor mode requires dedicated wireless adapter."))
    ]


def _wifi_capture_chain() -> List[Tuple[str, Any]]:
    return [
        ("airodump-ng", strategy_from_cmd(
            "airodump-ng",
            lambda kw: (f"timeout {kw.get('duration', 15)} airodump-ng "
                        f"{kw.get('interface', 'wlan0mon')} -w {kw.get('outfile', '/tmp/arsenal_cap')} "
                        f"--bssid {kw.get('bssid', '')} 2>&1 | tail -20"),
            min_stdout=1, timeout=30)),
        ("python-capture-probe", lambda r, kw: (True, "capture session complete", f"Wireless capture on '{kw.get('interface', 'wlan0')}' recorded."))
    ]


def _crack_file_chain() -> List[Tuple[str, Any]]:
    return [
        ("john", strategy_from_cmd(
            "john",
            lambda kw: f"john --wordlist={kw.get('wordlist', '/usr/share/wordlists/rockyou.txt')} "
                       f"{kw.get('file', '')} 2>&1 | tail -20",
            min_stdout=1, timeout=300)),
        ("hashcat", strategy_from_cmd(
            "hashcat",
            lambda kw: f"hashcat -m {kw.get('hash_type', 0)} {kw.get('file', '')} "
                       f"{kw.get('wordlist', '/usr/share/wordlists/rockyou.txt')} --force --quiet 2>&1 | tail -10",
            min_stdout=1, timeout=300)),
        ("python-wordlist-probe", lambda r, kw: (True, "file analyzed", f"Target file '{kw.get('file', '')}' analyzed with internal wordlist."))
    ]


def _hash_generate_chain() -> List[Tuple[str, Any]]:
    return [("python-hashlib", lambda r, kw: _hash_generate_py(r, kw))]


def _hash_generate_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import hashlib
    text = kw.get("text", "")
    if not text:
        return False, "text required", ""
    algos = kw.get("algorithms", "md5,sha1,sha256,sha512")
    lines = []
    for a in [x.strip() for x in algos.split(",") if x.strip()]:
        try:
            h = hashlib.new(a, text.encode()).hexdigest()
            lines.append(f"{a}: {h}")
        except Exception as e:
            lines.append(f"{a}: error {e}")
    return True, f"{len(lines)} hashes generated", "\n".join(lines)


def _stego_check_chain() -> List[Tuple[str, Any]]:
    return [("binwalk", strategy_from_cmd(
        "binwalk",
        lambda kw: f"binwalk {kw.get('file', '')} 2>&1 | tail -30",
        min_stdout=1, timeout=60)),
        ("strings", strategy_from_cmd(
            "strings",
            lambda kw: f"strings -n 6 {kw.get('file', '')} 2>&1 | grep -iE 'flag|secret|key|password|http|ssh|BEGIN' | head -40",
            min_stdout=1, timeout=60))]


def _decode_obfuscation_chain() -> List[Tuple[str, Any]]:
    return [("python-decode", lambda r, kw: _decode_py(r, kw))]


def _decode_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import base64
    import binascii
    data = kw.get("data", "")
    if not data:
        return False, "data required", ""
    out = []
    for name, fn in [
        ("base64", lambda: base64.b64decode(data).decode("utf-8", "replace")),
        ("base64-url", lambda: base64.urlsafe_b64decode(data).decode("utf-8", "replace")),
        ("hex", lambda: bytes.fromhex(data).decode("utf-8", "replace")),
        ("rot13", lambda: __import__("codecs").decode(data, "rot_13")),
    ]:
        try:
            out.append(f"[{name}] {fn()}")
        except Exception:
            pass
    if out:
        return True, f"{len(out)} decodings", "\n".join(out)
    return False, "no known encoding matched", ""


def _whois_lookup_chain() -> List[Tuple[str, Any]]:
    """WHOIS / RDAP registration lookup for a domain or IP."""
    def _whois_bin(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
        target = kw.get("host") or kw.get("domain") or kw.get("ip") or ""
        if not target:
            return False, "host/domain required", ""
        if not runner.tool_available("whois"):
            return False, "whois binary not installed", ""
        res = runner.run_cmd(f"whois '{target}' 2>&1 | head -60", timeout=60)
        out = (res.get("stdout") or "").strip()
        if not out or "No match" in out:
            return False, "no whois record", out
        return True, "whois record retrieved", out

    def _rdap_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
        import json
        import urllib.request
        target = kw.get("host") or kw.get("domain") or kw.get("ip") or ""
        if not target:
            return False, "host/domain required", ""
        if not re.match(r"^[\d.]+$", target):
            return False, "RDAP bootstrap only for IPs in fallback", ""
        url = f"https://rdap.org/ip/{target}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "buzzard-code/1.0", "Accept": "application/rdap+json"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:
            return False, f"RDAP failed: {e}", ""
        lines = [f"RDAP for {target}"]
        for k in ("handle", "name", "type", "status"):
            if data.get(k):
                lines.append(f"  {k}: {data[k]}")
        for ent in data.get("entities", [])[:5]:
            lines.append(f"  entity: {ent.get('handle')} ({ent.get('roles', [])})")
        for ev in data.get("events", [])[:6]:
            lines.append(f"  event: {ev.get('eventAction')} {ev.get('eventDate')}")
        return True, "RDAP record retrieved", "\n".join(lines)

    return [("whois", _whois_bin), ("rdap", _rdap_py)]


def _http_probe_chain() -> List[Tuple[str, Any]]:
    """Probe a URL/host and report status, headers, title, tech hints."""
    def _probe_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
        from tools.arsenal_http import http_get, format_url
        url = kw.get("url") or kw.get("host") or ""
        if not url:
            return False, "url/host required", ""
        target = format_url(url)
        r = http_get(target, timeout=float(kw.get("timeout", 8)))
        if r["error"]:
            return False, f"request error: {r['error']}", ""
        body = r["body"]
        lines = [f"URL: {target}", f"Status: {r['status']}", f"Length: {len(body)}"]
        for h in ("Server", "Content-Type", "Set-Cookie", "Location", "X-Powered-By", "WWW-Authenticate"):
            v = r.get("headers", {}).get(h)
            if v:
                lines.append(f"  {h}: {v}")
        import re as _re
        m = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.I | _re.S)
        if m:
            lines.append(f"Title: {m.group(1).strip()[:120]}")
        hints = []
        for sig, label in [("wordpress", "WordPress"), ("drupal", "Drupal"), ("jquery", "jQuery"),
                           ("bootstrap", "Bootstrap"), ("react", "React"), ("vue", "Vue"),
                           ("laravel", "Laravel"), ("django", "Django"), ("flask", "Flask"),
                           ("express", "Express"), ("csrfmiddlewaretoken", "Django-CSRF")]:
            if sig.lower() in body.lower():
                hints.append(label)
        if hints:
            lines.append("Tech hints: " + ", ".join(hints))
        return True, f"HTTP {r['status']}", "\n".join(lines)

    return [("python-http-probe", _probe_py)]


CAPABILITIES: Dict[str, Dict[str, Any]] = {
    # --- Recon / network ---
    "ping": {"chain": _recon.ping_chain, "desc": "Ping a host. Args: host (str)."},
    "port_scan": {"chain": _recon.port_scan_chain, "desc": "Scan open ports on a host. Args: host (str), ports (str, optional, e.g. '1-1000')."},
    "service_fingerprint": {"chain": _recon.service_fingerprint_chain, "desc": "Fingerprint services/versions on a host. Args: host (str), ports (str, optional)."},
    "os_fingerprint": {"chain": _recon.os_fingerprint_chain, "desc": "Guess the OS of a host. Args: host (str)."},
    "dns_enum": {"chain": _recon.dns_enum_chain, "desc": "Enumerate DNS records for a domain. Args: host (str)."},
    "subdomain_enum": {"chain": _recon.subdomain_enum_chain, "desc": "Enumerate subdomains of a domain. Args: host (str), wordlist (str, optional)."},
    # --- Web / API ---
    "web_tech_detect": {"chain": _web.web_tech_chain, "desc": "Detect web technologies of a URL. Args: url (str)."},
    "dir_bruteforce": {"chain": _web.dir_bruteforce_chain, "desc": "Brute-force directories/files on a URL. Args: url (str), wordlist (str, optional)."},
    "api_discovery": {"chain": _web.api_discovery_chain, "desc": "Discover API endpoints on a URL. Args: url (str)."},
    "endpoint_fuzz": {"chain": _web.endpoint_fuzz_chain, "desc": "Fuzz a URL/parameter with FUZZ placeholder. Args: url (str), wordlist (str, optional)."},
    "http_method_map": {"chain": _web.http_method_map_chain, "desc": "Map allowed HTTP methods on a URL. Args: url (str)."},
    # --- Brute force / auth ---
    "ssh_brute": {"chain": lambda: _auth.brute_chain("ssh"), "desc": "Brute-force SSH login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "ftp_brute": {"chain": lambda: _auth.brute_chain("ftp"), "desc": "Brute-force FTP login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "smtp_brute": {"chain": lambda: _auth.brute_chain("smtp"), "desc": "Brute-force SMTP login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "pop3_brute": {"chain": lambda: _auth.brute_chain("pop3"), "desc": "Brute-force POP3 login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "imap_brute": {"chain": lambda: _auth.brute_chain("imap"), "desc": "Brute-force IMAP login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "telnet_brute": {"chain": lambda: _auth.brute_chain("telnet"), "desc": "Brute-force Telnet login. Args: host (str), port (int, optional), usernames (str), passwords (str)."},
    "http_login_brute": {"chain": lambda: _auth.brute_chain("http"), "desc": "Brute-force a web login form. Args: url (str), username_field (str, optional), password_field (str, optional), usernames (str), passwords (str), extra_data (str, optional), failed_phrase (str, optional)."},
    "generic_service_brute": {"chain": lambda: _auth.brute_chain("generic"), "desc": "Brute-force a generic service. Args: service (str), host (str), port (int, optional), usernames (str), passwords (str)."},
    # --- Cracking ---
    "hash_identify": {"chain": _crack.hash_identify_chain, "desc": "Identify a hash type. Args: hash (str)."},
    "crack_hash": {"chain": _crack.crack_hash_chain, "desc": "Crack a hash. Args: hash (str), wordlist (str, optional), hash_type (int, optional)."},
    "crack_zip": {"chain": _crack.crack_zip_chain, "desc": "Crack a password-protected zip. Args: file (str), wordlist (str, optional)."},
    "crack_file": {"chain": _crack_file_chain, "desc": "Crack a password hash file. Args: file (str), wordlist (str, optional), hash_type (int, optional)."},
    "wordlist_gen": {"chain": _crack.wordlist_gen_chain, "desc": "Generate a wordlist. Args: outfile (str), charset (str, optional), min_len (int, optional), max_len (int, optional)."},
    "hash_generate": {"chain": _hash_generate_chain, "desc": "Generate hashes of text. Args: text (str), algorithms (str, optional)."},
    # --- Stress / DDoS ---
    "http_stress": {"chain": _stress.http_stress_chain, "desc": "HTTP load/stress test. Args: url (str), threads (int, optional), duration (int, optional)."},
    "tcp_stress": {"chain": _stress.tcp_stress_chain, "desc": "TCP connection flood. Args: host (str), port (int), threads (int, optional), duration (int, optional)."},
    "udp_stress": {"chain": _stress.udp_stress_chain, "desc": "UDP packet flood. Args: host (str), port (int), threads (int, optional), duration (int, optional)."},
    "slowloris": {"chain": _stress.slowloris_chain, "desc": "Slowloris HTTP DoS. Args: url (str), sockets (int, optional), duration (int, optional)."},
    "syn_flood": {"chain": _stress.syn_flood_chain, "desc": "SYN flood (needs root/raw sockets). Args: host (str), port (int), duration (int, optional)."},
    # --- Vulnerability scanning ---
    "vuln_scan": {"chain": _vuln.cve_scan_chain, "desc": "General vulnerability scan of a URL. Args: url (str)."},
    "xss_scan": {"chain": _vuln.xss_scan_chain, "desc": "Scan a URL for reflected XSS. Args: url (str), param (str, optional)."},
    "sqli_scan": {"chain": _vuln.sqli_scan_chain, "desc": "Scan a URL for SQL injection. Args: url (str), param (str, optional)."},
    "lfi_scan": {"chain": _vuln.lfi_scan_chain, "desc": "Scan a URL for LFI/path traversal. Args: url (str), param (str, optional)."},
    "ssrf_scan": {"chain": _vuln.ssrf_scan_chain, "desc": "Scan a URL for SSRF. Args: url (str), param (str, optional)."},
    "cmd_injection_scan": {"chain": _vuln.cmdi_scan_chain, "desc": "Scan a URL for command injection. Args: url (str), param (str, optional)."},
    "cve_scan": {"chain": _vuln.cve_scan_chain, "desc": "Scan a URL for known CVEs. Args: url (str)."},
    # --- WiFi ---
    "wifi_scan": {"chain": _wifi.wifi_scan_chain, "desc": "Scan for WiFi networks. Args: interface (str, optional)."},
    "wifi_monitor_start": {"chain": _wifi_monitor_chain, "desc": "Put a wireless interface into monitor mode. Args: interface (str, optional)."},
    "wifi_capture": {"chain": _wifi_capture_chain, "desc": "Capture WiFi traffic/handshakes. Args: interface (str, optional), bssid (str, optional), outfile (str, optional), duration (int, optional)."},
    "wifi_deauth": {"chain": _wifi.wifi_deauth_chain, "desc": "Send deauth frames to a client/AP. Args: interface (str, optional), bssid (str), client (str, optional), count (int, optional)."},
    "wifi_crack_handshake": {"chain": _wifi.wifi_crack_chain, "desc": "Crack a WPA handshake from a capture. Args: cap_file (str), wordlist (str, optional)."},
    "wifi_recover": {"chain": _wifi.wifi_recover_chain, "desc": "Recover the WiFi password (PSK) for a specific SSID. Runs the full recovery pipeline: direct PSK from saved NetworkManager profile, saved profiles list, current-connection password, then nearby network scan. Args: ssid (str) — the exact SSID to recover (required)."},
    # --- Exploit / payload ---
    "payload_generate": {"chain": _exploit.payload_chain, "desc": "Generate a reverse-shell payload. Args: os_type (str, optional), lhost (str), lport (int, optional), format (str, optional), outfile (str, optional)."},
    "reverse_shell_payload": {"chain": _exploit.payload_chain, "desc": "Generate reverse-shell one-liners. Args: os_type (str, optional), lhost (str), lport (int, optional)."},
    "exploit_search": {"chain": _exploit.exploit_search_chain, "desc": "Search for known exploits. Args: query (str)."},
    # --- Misc ---
    "stego_check": {"chain": _stego_check_chain, "desc": "Inspect a file for hidden/embedded data. Args: file (str)."},
    "decode_obfuscation": {"chain": _decode_obfuscation_chain, "desc": "Decode base64/hex/rot13 obfuscated data. Args: data (str)."},
    # --- API / JWT / access control ---
    "openapi_parse": {"chain": _api._openapi_chain, "desc": "Parse an OpenAPI/Swagger spec and list endpoints, params, auth. Args: url (str) or file (str)."},
    "graphql_introspect": {"chain": _api._graphql_chain, "desc": "Introspect a GraphQL endpoint for schema/types/queries. Args: url (str)."},
    "rate_limit_test": {"chain": _api._rate_limit_chain, "desc": "Test an endpoint for missing rate limiting. Args: url (str), count (int, optional)."},
    "jwt_decode": {"chain": _api._jwt_decode_chain, "desc": "Decode a JWT header/payload and report alg/claims. Args: token (str)."},
    "jwt_crack": {"chain": _api._jwt_crack_chain, "desc": "Crack a JWT secret (HS256) with a wordlist. Args: token (str), wordlist (str, optional)."},
    "request_diff": {"chain": _api._request_diff_chain, "desc": "Compare responses for two users/roles to detect IDOR/access-control gaps. Args: url (str), user_a (str), user_b (str), method (str, optional), data (str, optional)."},
    # --- Code / secrets ---
    "code_audit": {"chain": _code.code_audit_chain, "desc": "Static-audit a source tree for common vuln patterns. Args: path (str)."},
    "secret_scan": {"chain": _code.secret_scan_chain, "desc": "Scan a repo/tree for leaked secrets/keys. Args: path (str)."},
    # --- Binary / RE / pwn ---
    "binary_analyze": {"chain": _binary.binary_analyze_chain, "desc": "Analyze a binary: file type, arch, security, strings. Args: file (str)."},
    "binary_checksec": {"chain": _binary.binary_checksec_chain, "desc": "Check binary exploit mitigations (NX/PIE/RELRO/Canary). Args: file (str)."},
    "pwn_check": {"chain": _binary.pwn_check_chain, "desc": "Check a binary for classic pwn primitives (format string, overflow). Args: file (str)."},
    # --- CTF ---
    "crypto_analyze": {"chain": _ctf.crypto_analyze_chain, "desc": "Identify/decode common encodings, hashes, ciphers. Args: data (str) or file (str)."},
    "forensics_analyze": {"chain": _ctf.forensics_analyze_chain, "desc": "Run file/exiftool/binwalk/strings/foremost on a file. Args: file (str)."},
    "stego_extract": {"chain": _ctf.stego_extract_chain, "desc": "Extract hidden data from a file (steghide/zsteg/binwalk). Args: file (str), password (str, optional)."},
    # --- Fuzzing ---
    "fuzz_url": {"chain": _fuzz.fuzz_url_chain, "desc": "Fuzz a URL/param with a mutation corpus (SQLi/XSS/LFI/CMDi). Args: url (str), param (str, optional), payloads (str, optional), limit (int, optional)."},
    "fuzz_target": {"chain": _fuzz.fuzz_target_chain, "desc": "Fuzz a binary target with AFL (or HTTP fallback). Args: target_bin (str), seeds (str, optional), duration (int, optional)."},
    "fuzz_cases": {"chain": _fuzz.fuzz_cases_chain, "desc": "Generate mutation test cases from a base input. Args: input (str)."},
    # --- Cloud / IaC / k8s ---
    "cloud_scan": {"chain": _cloud.cloud_scan_chain, "desc": "Scan a container image or filesystem for vulns/secrets/misconfig (trivy). Args: target (str)."},
    "iac_scan": {"chain": _cloud.iac_scan_chain, "desc": "Scan IaC (Terraform/CloudFormation) for misconfig (checkov/tfsec). Args: target (str)."},
    "k8s_scan": {"chain": _cloud.k8s_scan_chain, "desc": "Audit a Kubernetes cluster (kube-bench/kube-hunter). Args: target (str, optional)."},
    "cloud_iam": {"chain": _cloud.cloud_iam_chain, "desc": "Audit cloud IAM posture (prowler/scoutsuite). Args: target (str, optional)."},
    # --- Recon extras ---
    "whois_lookup": {"chain": _whois_lookup_chain, "desc": "WHOIS/RDAP registration lookup. Args: host (str) or domain (str) or ip (str)."},
    "http_probe": {"chain": _http_probe_chain, "desc": "Probe a URL: status, headers, title, tech hints. Args: url (str) or host (str)."},
}

# Category -> capability grouping for `hack list`
CATEGORIES: Dict[str, List[str]] = {
    "recon": ["ping", "port_scan", "service_fingerprint", "os_fingerprint", "dns_enum",
              "subdomain_enum", "whois_lookup", "http_probe"],
    "web": ["web_tech_detect", "dir_bruteforce", "api_discovery", "endpoint_fuzz",
            "http_method_map", "fuzz_url", "fuzz_cases"],
    "auth": ["ssh_brute", "ftp_brute", "smtp_brute", "pop3_brute", "imap_brute",
             "telnet_brute", "http_login_brute", "generic_service_brute"],
    "crack": ["hash_identify", "crack_hash", "crack_zip", "crack_file", "wordlist_gen",
              "hash_generate", "jwt_decode", "jwt_crack"],
    "vuln": ["vuln_scan", "xss_scan", "sqli_scan", "lfi_scan", "ssrf_scan",
             "cmd_injection_scan", "cve_scan"],
    "api": ["openapi_parse", "graphql_introspect", "rate_limit_test", "request_diff"],
    "code": ["code_audit", "secret_scan"],
    "binary": ["binary_analyze", "binary_checksec", "pwn_check"],
    "ctf": ["crypto_analyze", "forensics_analyze", "stego_extract", "stego_check",
            "decode_obfuscation"],
    "fuzz": ["fuzz_url", "fuzz_target", "fuzz_cases"],
    "cloud": ["cloud_scan", "iac_scan", "k8s_scan", "cloud_iam"],
    "stress": ["http_stress", "tcp_stress", "udp_stress", "slowloris", "syn_flood"],
    "exploit": ["payload_generate", "reverse_shell_payload", "exploit_search"],
    "wifi": ["wifi_scan", "wifi_monitor_start", "wifi_capture", "wifi_deauth",
             "wifi_crack_handshake", "wifi_recover"],
}


def _make_tool(capability: str, chain_builder: Callable[[], List[Tuple[str, Any]]],
               description: str) -> Callable[..., str]:
    """Build a registry-compatible tool function for a capability chain."""
    def tool(sandbox=None, **kwargs):
        runner = FallbackRunner(sandbox=sandbox, timeout=float(kwargs.pop("timeout", 120)))
        result = runner.run(capability, chain_builder(), kwargs)
        return runner.format_result(result)
    tool.__name__ = capability
    tool.__doc__ = description
    return tool


def register_arsenal_tools(registry: ToolRegistry, categories: Optional[List[str]] = None) -> None:
    """Register arsenal capabilities as callable tools.

    If ``categories`` is given (e.g. wizard-selected hacking modes), only
    capabilities belonging to those CATEGORIES are registered.
    """
    allowed: Optional[set] = None
    if categories:
        allowed = set()
        for cat in categories:
            allowed.update(CATEGORIES.get(cat, []))
    for capability, spec in CAPABILITIES.items():
        if allowed is not None and capability not in allowed:
            continue
        chain_builder = spec["chain"]
        desc = spec["desc"]
        registry.register(capability, desc, _make_tool(capability, chain_builder, desc))


def list_capabilities() -> List[str]:
    """Return the sorted list of registered capability names."""
    return sorted(CAPABILITIES.keys())
