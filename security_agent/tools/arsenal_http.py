"""Shared HTTP / network helpers for the arsenal python fallback strategies."""
from __future__ import annotations

import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False

import urllib.request
import urllib.error

DEFAULT_TIMEOUT = 6.0


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------
def port_list(ports: str) -> List[int]:
    """Parse '1-1000' / '22,80,443' / '443' into a list of ints."""
    out: List[int] = []
    for chunk in (ports or "1-1000").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                lo, hi = int(a), int(b)
                out.extend(range(lo, min(hi, 65535) + 1))
            except Exception:
                continue
        else:
            try:
                out.append(int(chunk))
            except Exception:
                continue
    return sorted(set(out))[:2000]


# ---------------------------------------------------------------------------
# HTTP helpers (httpx preferred, urllib fallback — both available in-process)
# ---------------------------------------------------------------------------
def http_request(method: str, url: str, data: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 allow_redirects: bool = True) -> Dict[str, Any]:
    """Returns {status, body, headers, final_url, error}."""
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) UA-arsenal/1.0",
            "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    # httpx sends raw str/bytes bodies without any Content-Type, so Flask-style
    # form parsing silently sees an empty body. Default to form-encoding for
    # payload data unless the caller supplied a Content-Type or a JSON body.
    has_ct = any(k.lower() == "content-type" for k in hdrs)
    if data and not has_ct:
        looks_json = isinstance(data, str) and data.lstrip()[:1] in ("{", "[")
        if not looks_json:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if HAS_HTTPX:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=allow_redirects,
                              verify=False) as client:
                r = client.request(method, url, data=data.encode() if isinstance(data, str) else data,
                                   headers=hdrs)
                return {"status": r.status_code, "body": r.text,
                        "headers": dict(r.headers), "final_url": str(r.url), "error": ""}
        except Exception as e:
            return {"status": 0, "body": "", "headers": {}, "final_url": url,
                    "error": f"{type(e).__name__}: {e}"}
    try:
        req = urllib.request.Request(url, data=data.encode() if data else None,
                                     headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200_000).decode("utf-8", "replace")
            return {"status": resp.status, "body": body,
                    "headers": dict(resp.headers.items()), "final_url": resp.geturl(), "error": ""}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body, "headers": dict(e.headers.items()),
                "final_url": url, "error": ""}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "final_url": url,
                "error": f"{type(e).__name__}: {e}"}


def http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    return http_request("GET", url, timeout=timeout)


def http_post(url: str, data: str, timeout: float = DEFAULT_TIMEOUT,
              headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return http_request("POST", url, data=data, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------
def conn_ok(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 5.0) -> str:
    """Protocol-aware banner grab (HTTP/SMTP/FTP/SSH/TLS generic)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP
            if port in (80, 8000, 8080, 8888, 3000, 5000, 8001):
                s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                return s.recv(2048).decode("utf-8", "replace")
            # TLS services
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=host) as tls:
                    tls.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                    return tls.recv(2048).decode("utf-8", "replace")
            # Generic: send CRLF and read whatever the service sends first
            s.sendall(b"\r\n")
            time.sleep(0.3)
            data = s.recv(2048).decode("utf-8", "replace").strip()
            if data:
                return data
            s.sendall(b"HELP\r\n")
            time.sleep(0.3)
            return s.recv(2048).decode("utf-8", "replace").strip()
    except Exception as e:
        return f"(no banner) {type(e).__name__}"


def scan_ports_py(host: str, ports: str, timeout: float = 1.2,
                  max_workers: int = 60,
                  targets: Optional[List[int]] = None) -> List[int]:
    """Threaded TCP connect scan. Pass an explicit `targets` list to
    bypass the 2000-port parsing cap (used for prioritized scans)."""
    targets = targets if targets is not None else port_list(ports)
    open_ports: List[int] = []
    lock = threading.Lock()

    def probe(p: int) -> Optional[int]:
        return p if conn_ok(host, p, timeout) else None

    with ThreadPoolExecutor(max_workers=min(max_workers, len(targets) or 1)) as ex:
        for fut in as_completed([ex.submit(probe, p) for p in targets]):
            r = fut.result()
            if r:
                with lock:
                    open_ports.append(r)
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# Built-in wordlists (used when no system wordlist exists)
# ---------------------------------------------------------------------------
DIR_WORDS = """admin login logout register users user profile search flag backup config .env
robots.txt index.php index.html api v1 upload download view file files db database phpinfo.php
shell.php admin.php login.php flag.txt secret debug test old tmp logs log settings panel dashboard
home main docs README.md swagger health status version info metrics graphql actuator env config.php
wp-admin wp-login.php wp-content xmlrpc.php server-status server-info phpmyadmin pma sql adminer
console monitor cache data private public assets static js css img images fonts vendor lib src inc
include modules plugins themes uploads media storage backups bak old.bak test.php info.php phpinfo
debug.log error.log access.log auth authorize token tokens session cookies captcha verify confirm
reset forgot signup sign-in sign-up account accounts admin-panel admin_area cgi-bin cgi forms form
webdav server servers admin123 root""".split()

API_PATHS = """api api/v1 api/v2 v1 v2 swagger swagger.json swagger-ui swagger-ui.html api-docs api-docs.json
openapi.json openapi.yaml redoc graphql graphiql playground health healthz live ready ping status
metrics prometheus actuator actuator/health actuator/env actuator/beans actuator/mappings actuator/info
users user users.json accounts account auth login register token tokens session sessions me profile
admin dashboard config settings env .env secret secrets keys key flags flag flag.txt debug debug.log
internal internal/api private private/api webhook webhooks callback hooks events ws websocket socket.io
search query q explore items item products product orders order cart checkout payments payment
upload uploads files file download downloads export import csv json xml zip tar gz reports report
test tests testing docs documentation readme readme.md robots sitemap sitemap.xml favicon.ico
version versions changelog releases news blog articles post posts comments messages inbox mail email
notifications alerts devices device notifications push sms otp verify 2fa mfa totp backup restore
migrate migration schema db database sql query console shell exec run task jobs cron scheduler queue""".split()

PASS_WORDS = """admin admin123 password password123 letmein 123456 12345678 123456789 12345 1234 123
qwerty abc123 football monkey dragon baseball master monkey123 welcome login 000000 111111 11111111
root toor admin@123 Admin@123 P@ssw0rd Passw0rd password1 changeme default test guest user temp
secret secret123 iloveyou sunshine princess shadow superman michael jordan hunter trustno1 ninja
whatever batman zaq12wsx qwer1234 1q2w3e4r 1qaz2wsx pass admin1234 root123""".split()

USER_WORDS = """admin root administrator admin1 user test guest operator support info sys system
superuser webmaster manager staff helpdesk security auditor analyst agent bot service services
api apiuser developer dev engineer jane john mike bob alice mysql postgres backup""".split()

SUB_WORDS = """www mail smtp pop imap ftp ssh vpn api dev staging test demo beta alpha web app apps
portal admin panel console cms blog news shop store cdn static assets images img video media files
download upload ns1 ns2 dns mx gw gateway proxy cache jenkins ci cd git gitlab github bitbucket
jira confluence wiki kb help support status metrics grafana kibana prometheus monitoring logs
login auth sso idp ldap ad dc sql db mysql postgres mongo redis memcached elastic kibana mq amqp
kafka zookeeper hadoop spark hadoop namenode node worker compute cloud s3 bucket storage archive
backup old test1 test2 dev1 dev2 staging2 preprod qa uat""".split()

HTTP_BANNER_LINES = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache",
    "x-varnish", "via", "link", "set-cookie",
]


def ensure_builtin_wordlists() -> Dict[str, str]:
    """Materialize builtin wordlists to /tmp so external tools can use them."""
    import os
    items = {
        "/tmp/arsenal_dirs.txt": DIR_WORDS,
        "/tmp/arsenal_api.txt": API_PATHS,
        "/tmp/arsenal_pass.txt": PASS_WORDS,
        "/tmp/arsenal_user.txt": USER_WORDS,
        "/tmp/arsenal_sub.txt": SUB_WORDS,
    }
    for path, words in items.items():
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("\n".join(dict.fromkeys(w.strip() for w in words if w.strip())) + "\n")
    return {k: v for k, v in items.items()}


def best_wordlist(kind: str = "dir") -> str:
    """Auto-detect the best available system wordlist for a kind (dir/api/pass/user)."""
    import os
    candidates = {
        "dir": [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        ],
        "api": [
            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        ],
        "pass": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
            "/usr/share/seclists/Passwords/rockyou.txt",
        ],
        "user": [
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        ],
        "sub": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/usr/share/seclists/Discovery/DNS/namelist.txt",
        ],
    }
    for c in candidates.get(kind, []):
        if os.path.exists(c):
            return c
    ensure_builtin_wordlists()
    return {  # builtin fallback per kind
        "dir": "/tmp/arsenal_dirs.txt",
        "api": "/tmp/arsenal_api.txt",
        "pass": "/tmp/arsenal_pass.txt",
        "user": "/tmp/arsenal_user.txt",
        "sub": "/tmp/arsenal_sub.txt",
    }[kind]


def threaded_http_probe(urls: List[str], method: str = "GET",
                        data_tpl: Optional[str] = None,
                        timeout: float = 5.0, max_workers: int = 25) -> List[Dict[str, Any]]:
    """Probe many URLs concurrently; returns results sorted by status."""
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def probe(url: str) -> None:
        if method == "POST" and data_tpl:
            r = http_post(url, data_tpl, timeout=timeout)
        else:
            r = http_get(url, timeout=timeout)
        with lock:
            results.append({"url": url, "status": r["status"], "len": len(r["body"]),
                            "error": r["error"]})

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(probe, u) for u in urls]
        for f in futs:
            try:
                f.result()
            except Exception:
                pass
    results.sort(key=lambda x: (x["status"] == 0, x["status"]))
    return results


def format_url(host_or_url: str, default_port: int = 80) -> str:
    """Normalize '127.0.0.1:8080' or 'http://host/' into an absolute URL."""
    u = (host_or_url or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = f"http://{u}"
    return u.rstrip("/")
