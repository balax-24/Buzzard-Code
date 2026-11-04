import pytest
from security_agent.intelligence.evidence_parser import (
    EvidenceParser,
    DiscoveredService,
    AttackSurfaceSnapshot,
)


def test_parse_nmap_output():
    nmap_raw = """
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-22 11:30 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000084s latency).
Not shown: 984 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
631/tcp   open  ipp     CUPS 2.4
8384/tcp  open  http    Syncthing administrative web GUI
11434/tcp open  http    Ollama LLM API
18789/tcp open  unknown
18791/tcp open  http    Node.js Express framework
33060/tcp open  mysqlx

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
"""
    parser = EvidenceParser()
    snapshot = parser.parse_tool_output("nmap_scan", {"host": "127.0.0.1"}, nmap_raw)
    
    assert len(snapshot.services) == 6
    ports = [s.port for s in snapshot.services]
    assert 631 in ports
    assert 8384 in ports
    assert 11434 in ports
    assert 18789 in ports
    assert 18791 in ports
    assert 33060 in ports
    
    s_8384 = next(s for s in snapshot.services if s.port == 8384)
    assert s_8384.service == "http"
    assert "Syncthing" in s_8384.version
    assert s_8384.is_http() is True

    summary = snapshot.format_evidence_summary()
    assert "Port 8384/tcp" in summary
    assert "Port 11434/tcp" in summary


def test_parse_whatweb_and_curl_output():
    whatweb_raw = "http://127.0.0.1:8384 [200 OK] HTTPServer[Syncthing], Title[Syncthing], HTML5, Script[bundle.js]"
    parser = EvidenceParser()
    snapshot = parser.parse_tool_output("whatweb_scan", {"url": "http://127.0.0.1:8384"}, whatweb_raw)
    
    assert len(snapshot.web_technologies) > 0
    assert any("Syncthing" in t for t in snapshot.web_technologies)


def test_parse_ffuf_dir_output():
    ffuf_raw = """
admin                   [Status: 200, Size: 1243, Words: 212, Lines: 45, Duration: 2ms]
api                     [Status: 301, Size: 180, Words: 12, Lines: 5, Duration: 1ms]
robots.txt              [Status: 200, Size: 54, Words: 4, Lines: 2, Duration: 1ms]
"""
    parser = EvidenceParser()
    snapshot = parser.parse_tool_output("ffuf_fuzz", {"url": "http://127.0.0.1:8080/FUZZ"}, ffuf_raw)
    
    assert len(snapshot.endpoints) == 3
    paths = [ep.path for ep in snapshot.endpoints]
    assert "admin" in paths
    assert "api" in paths
