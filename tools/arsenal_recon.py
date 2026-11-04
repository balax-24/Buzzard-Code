"""Network recon strategies: ping, port scan, fingerprint, OS detect, DNS, subdomains."""
from __future__ import annotations

import json
import re
import socket
import subprocess
from typing import Any, Dict, List, Tuple

from tools.fallback import FallbackRunner, strategy_from_cmd
from tools.arsenal_http import (
    conn_ok, grab_banner, port_list, scan_ports_py, best_wordlist,
    threaded_http_probe, SUB_WORDS,
)

import shlex


# Common ports get scanned first so large ranges still hit the juicy services
# even when a strategy caps the number of probes.
COMMON_PORTS = [80, 443, 22, 8080, 8443, 8000, 8888, 5000, 3000, 3306, 3389,
                5432, 6379, 27017, 9200, 5601, 21, 25, 110, 143, 587, 993, 995,
                445, 139, 135, 53, 161, 123, 514, 2049, 1080, 1433, 1521, 7001,
                8009, 9000, 10000, 11211, 2375, 2376, 8081, 8082, 9090, 5900,
                2323, 2222, 5984, 8088, 8181, 9999, 9001]


def _in_requested(port: int, ports_spec: str) -> bool:
    """Check membership against the raw spec (no 2000-port cap) so common
    ports above the cap are still scanned first."""
    for chunk in (ports_spec or "1-1000").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                if int(a) <= port <= min(int(b), 65535):
                    return True
            except Exception:
                continue
        else:
            try:
                if int(chunk) == port:
                    return True
            except Exception:
                continue
    return False


def prioritized_ports(ports: str) -> List[int]:
    """Order requested ports with common ports first, then the rest."""
    requested = port_list(ports)
    common = [p for p in COMMON_PORTS if _in_requested(p, ports)]
    rest = [p for p in requested if p not in common]
    return common + rest


# ---------------------------------------------------------------------------
# ping / host discovery
# ---------------------------------------------------------------------------
def _ping_nmap(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmap"):
        return False, "nmap not installed", ""
    host = kw.get("host", "")
    res = runner.run_cmd(f"nmap -sn -T4 {shlex.quote(host)} 2>&1 | tail -20", timeout=90)
    out = res.get("stdout", "")
    if "Host is up" in out or "Nmap scan report" in out:
        return True, "host is up", out
    return False, "host down or nmap empty", out


def _ping_ping(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ping"):
        return False, "ping not installed", ""
    host = kw.get("host", "")
    res = runner.run_cmd(f"ping -c 2 -W 2 {shlex.quote(host)} 2>&1", timeout=30)
    out = res.get("stdout", "")
    if "bytes from" in out or "ttl=" in out:
        ttl = re.search(r"ttl[=\s:](\d+)", out, re.I)
        return True, f"host up (TTL {ttl.group(1) if ttl else '?'})", out
    return False, "no ping reply", out


def _ping_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    if not host:
        return False, "no host", ""
    try:
        ip = socket.gethostbyname(host)
        # TCP connect to a few common ports as an liveness proxy (ICMP needs root)
        alive = [p for p in (80, 443, 22, 8080, 445, 135) if conn_ok(host, p, 1.0)]
        if alive:
            return True, f"host reachable via TCP {alive}", f"{host} -> {ip}; open probe ports: {alive}"
        return False, "no common port reachable", f"{host} -> {ip}; ICMP requires root, TCP probes silent"
    except Exception as e:
        return False, f"DNS failed: {e}", ""


# ---------------------------------------------------------------------------
# port scan
# ---------------------------------------------------------------------------
def _ports_nmap(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmap"):
        return False, "nmap not installed", ""
    host, ports = kw.get("host", ""), kw.get("ports", "1-1000")
    opts = kw.get("options", "-sV -T4")
    if ports and ports != "1-1000":
        cmd = f"nmap {opts} -p {shlex.quote(ports)} --open {shlex.quote(host)} 2>&1"
    else:
        cmd = f"nmap {opts} --open {shlex.quote(host)} 2>&1"
    res = runner.run_cmd(cmd, timeout=240)
    out = res.get("stdout", "")
    if "open" in out or "Nmap scan report" in out:
        return True, "scan complete", out[-6000:]
    return False, "no open ports detected", out[-3000:]


def _ports_nc(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nc"):
        return False, "nc not installed", ""
    host, ports = kw.get("host", ""), kw.get("ports", "1-1000")
    found = []
    for p in prioritized_ports(ports)[:200]:
        res = runner.run_cmd(f"nc -z -w 1 {shlex.quote(host)} {p} 2>&1", timeout=5)
        if res.get("exit_code") == 0:
            found.append(p)
    if found:
        return True, f"{len(found)} open ports", "Open ports: " + ", ".join(map(str, found))
    return False, "no open ports via nc", ""


def _ports_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host, ports = kw.get("host", ""), kw.get("ports", "1-1000")
    if not host:
        return False, "no host", ""
    open_ports = scan_ports_py(host, ports, timeout=1.0, targets=prioritized_ports(ports))
    if open_ports:
        lines = [f"Open ports ({len(open_ports)}):"]
        for p in open_ports[:80]:
            banner = grab_banner(host, p, timeout=3.0)[:160].replace("\n", " | ")
            lines.append(f"  {p}/tcp  {banner}")
        return True, f"{len(open_ports)} open ports", "\n".join(lines)
    return False, "no open ports", f"TCP connect scan of {ports} found nothing"


# ---------------------------------------------------------------------------
# service fingerprint
# ---------------------------------------------------------------------------
def _svc_nmap(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmap"):
        return False, "nmap not installed", ""
    host = kw.get("host", "")
    ports = kw.get("ports", "")
    cmd = f"nmap -sV -sC -Pn -T4 {('-p ' + shlex.quote(ports)) if ports else ''} {shlex.quote(host)} 2>&1"
    res = runner.run_cmd(cmd, timeout=240)
    out = res.get("stdout", "")
    if re.search(r"^\d+/tcp\s+open", out, re.M):
        return True, "services fingerprinted", out[-6000:]
    return False, "no services", out[-3000:]


def _svc_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    ports_s = kw.get("ports", "21,22,23,25,53,80,110,143,443,445,3306,5432,6379,8080,8443")
    if not host:
        return False, "no host", ""
    rows = []
    for p in port_list(ports_s):
        if not conn_ok(host, p, 1.2):
            continue
        banner = grab_banner(host, p, timeout=4.0)[:200].replace("\n", " | ")
        rows.append(f"  {p}/tcp open  {banner}")
    if rows:
        return True, f"{len(rows)} services", "\n".join(rows)
    return False, "no open service ports", ""


# ---------------------------------------------------------------------------
# OS fingerprint
# ---------------------------------------------------------------------------
def _os_nmap(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmap"):
        return False, "nmap not installed", ""
    host = kw.get("host", "")
    res = runner.run_cmd(f"nmap -O -Pn -T4 {shlex.quote(host)} 2>&1 | grep -A 6 'OS details\\|OS CPE'", timeout=240)
    out = res.get("stdout", "")
    if "OS details" in out or "OS CPE" in out:
        return True, "OS fingerprinted", out
    return False, "OS detection inconclusive", out or "nmap -O produced no OS match"


def _os_ttl(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ping"):
        return False, "ping not installed", ""
    host = kw.get("host", "")
    res = runner.run_cmd(f"ping -c 3 -W 2 {shlex.quote(host)} 2>&1", timeout=30)
    out = res.get("stdout", "")
    m = re.search(r"ttl[=\s:](\d+)", out, re.I)
    if not m:
        return False, "no TTL observed", out
    ttl = int(m.group(1))
    guess = "Linux/Unix (TTL 64)" if ttl <= 64 else ("Windows (TTL 128)" if ttl <= 128 else "Network device (TTL 255)")
    return True, guess, f"TTL={ttl} -> {guess}\n{out[:1500]}"


# ---------------------------------------------------------------------------
# DNS enumeration
# ---------------------------------------------------------------------------
def _dns_dig(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("dig"):
        return False, "dig not installed", ""
    host = kw.get("host", "")
    out_parts = []
    for rec in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        res = runner.run_cmd(f"dig +short {rec} {shlex.quote(host)} 2>&1", timeout=20)
        val = res.get("stdout", "").strip()
        if val:
            out_parts.append(f"{rec}: {val}")
    if out_parts:
        return True, "DNS records found", "\n".join(out_parts)
    return False, "no DNS records", ""


def _dns_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    if not host:
        return False, "no host", ""
    try:
        ip = socket.gethostbyname(host)
        try:
            rev = socket.gethostbyaddr(ip)
            rev_name = rev[0]
        except Exception:
            rev_name = "(no PTR)"
        return True, f"A: {ip}", f"{host} -> {ip}\nPTR: {rev_name}"
    except Exception as e:
        return False, f"resolution failed: {e}", ""


# ---------------------------------------------------------------------------
# subdomain enumeration
# ---------------------------------------------------------------------------
def _sub_subfinder(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("subfinder"):
        return False, "subfinder not installed", ""
    dom = kw.get("domain", "")
    res = runner.run_cmd(f"subfinder -d {shlex.quote(dom)} -silent 2>/dev/null | head -200", timeout=180)
    out = res.get("stdout", "").strip()
    if out:
        return True, f"{len(out.splitlines())} subdomains", out
    return False, "subfinder returned nothing", ""


def _sub_amass(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("amass"):
        return False, "amass not installed", ""
    dom = kw.get("domain", "")
    res = runner.run_cmd(f"amass enum -passive -d {shlex.quote(dom)} -timeout 3 2>/dev/null | head -200", timeout=200)
    out = res.get("stdout", "").strip()
    if out:
        return True, f"{len(out.splitlines())} subdomains", out
    return False, "amass returned nothing", ""


def _sub_crtsh(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    from tools.arsenal_http import http_get
    dom = kw.get("domain", "")
    try:
        r = http_get(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=20)
        if r["status"] == 200 and r["body"].strip():
            names = set()
            for row in json.loads(r["body"]):
                for n in str(row.get("name_value", "")).split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n and n.endswith(dom):
                        names.add(n)
            if names:
                return True, f"{len(names)} subdomains from cert transparency", "\n".join(sorted(names)[:150])
        return False, "crt.sh returned nothing", r.get("error") or f"status {r['status']}"
    except Exception as e:
        return False, f"crt.sh failed: {e}", ""


def _sub_pybrute(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    dom = kw.get("domain", "")
    if not dom:
        return False, "no domain", ""
    found = []
    words = [w for w in (kw.get("wordlist") or "").split(",") if w.strip()] or SUB_WORDS
    for w in words[:200]:
        fqdn = f"{w.strip().lower()}.{dom}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append(f"{fqdn} -> {ip}")
        except Exception:
            continue
    if found:
        return True, f"{len(found)} resolving subdomains", "\n".join(found[:100])
    return False, "no subdomains resolved", "DNS brute-force over builtin list found nothing"


# ---------------------------------------------------------------------------
# Capability chains
# ---------------------------------------------------------------------------
def ping_chain() -> List[Tuple[str, Any]]:
    return [("nmap", _ping_nmap), ("ping", _ping_ping), ("python-socket", _ping_py)]


def port_scan_chain() -> List[Tuple[str, Any]]:
    return [("nmap", _ports_nmap), ("netcat", _ports_nc), ("python-connect", _ports_py)]


def service_fingerprint_chain() -> List[Tuple[str, Any]]:
    return [("nmap-sV", _svc_nmap), ("python-banner", _svc_py)]


def os_fingerprint_chain() -> List[Tuple[str, Any]]:
    return [("nmap-O", _os_nmap), ("ttl-heuristic", _os_ttl)]


def dns_enum_chain() -> List[Tuple[str, Any]]:
    return [("dig", _dns_dig), ("python-resolve", _dns_py)]


def subdomain_enum_chain() -> List[Tuple[str, Any]]:
    return [("subfinder", _sub_subfinder), ("amass", _sub_amass),
            ("crt.sh", _sub_crtsh), ("python-dnsbrute", _sub_pybrute)]
