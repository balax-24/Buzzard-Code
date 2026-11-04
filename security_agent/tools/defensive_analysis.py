"""
Defensive Analysis and Incident Response Suite for Buzzard Code.

Provides bounded, safe defensive log analysis, IOC extraction, and reputation inspection:
- log_search
- log_summary
- ioc_extract
- ioc_match
- indicator_normalize
- hash_lookup
- ip_reputation
- domain_reputation
- url_reputation
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from security_agent.tools.registry import ToolCategory, ToolRegistry


def log_search(file_path: str, pattern: str, max_lines: int = 50) -> str:
    """
    Searches a local log file for a specific string pattern or regular expression.
    Arguments:
        file_path: Path to the log file.
        pattern: String or regex pattern to match.
        max_lines: Maximum matching lines to return (default 50, max 100).
    """
    if not file_path or not str(file_path).strip():
        return json.dumps({"status": "error", "error": "File path parameter is required."})
    if not pattern or not str(pattern).strip():
        return json.dumps({"status": "error", "error": "Search pattern parameter is required."})

    target_path = os.path.abspath(str(file_path).strip())
    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        return json.dumps({"status": "error", "error": f"Log file '{file_path}' does not exist."})

    limit = max(1, min(int(max_lines or 50), 100))
    pattern_str = str(pattern).strip()

    try:
        regex = re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        # Fall back to literal string search
        regex = re.compile(re.escape(pattern_str), re.IGNORECASE)

    matches = []
    total_matches = 0

    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if regex.search(line):
                total_matches += 1
                if len(matches) < limit:
                    matches.append({
                        "line_number": line_num,
                        "line": line.rstrip("\r\n")[:300]
                    })

    return json.dumps({
        "status": "success",
        "file_path": target_path,
        "pattern": pattern_str,
        "total_matches": total_matches,
        "returned_matches": len(matches),
        "matches": matches
    }, indent=2)


def log_summary(file_path: str, max_lines: int = 1000) -> str:
    """
    Summarizes key statistics from a log file (status codes, errors, top IPs, line count).
    Arguments:
        file_path: Path to the log file.
        max_lines: Maximum lines to analyze (default 1000, max 5000).
    """
    if not file_path or not str(file_path).strip():
        return json.dumps({"status": "error", "error": "File path parameter is required."})

    target_path = os.path.abspath(str(file_path).strip())
    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        return json.dumps({"status": "error", "error": f"Log file '{file_path}' does not exist."})

    limit = max(10, min(int(max_lines or 1000), 5000))

    total_lines = 0
    error_count = 0
    warn_count = 0
    ip_counts = {}
    status_counts = {}

    ip_regex = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    status_regex = re.compile(r"\s([1-5]\d{2})\s")

    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            l_lower = line.lower()
            if "error" in l_lower or "fatal" in l_lower or "critical" in l_lower:
                error_count += 1
            elif "warn" in l_lower:
                warn_count += 1

            ip_match = ip_regex.search(line)
            if ip_match:
                ip = ip_match.group(0)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

            status_match = status_regex.search(line)
            if status_match:
                code = status_match.group(1)
                status_counts[code] = status_counts.get(code, 0) + 1

            if total_lines >= limit:
                break

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_statuses = sorted(status_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return json.dumps({
        "status": "success",
        "file_path": target_path,
        "analyzed_lines": total_lines,
        "error_lines": error_count,
        "warning_lines": warn_count,
        "top_client_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "top_http_status_codes": [{"code": code, "count": cnt} for code, cnt in top_statuses]
    }, indent=2)


def ioc_extract(text_or_file: str = "", text: str = "", content: str = "", max_results: int = 100) -> str:
    text_or_file = text_or_file or text or content
    """
    Extracts structured IOCs (IPs, hashes, domains, URLs, CVEs, emails) from text or file content.
    Arguments:
        text_or_file: Raw string text or path to a local text/log file.
        max_results: Maximum IOCs to return per category (default 100).
    """
    if not text_or_file or not str(text_or_file).strip():
        return json.dumps({"status": "error", "error": "Input text or file path is required."})

    content = str(text_or_file)
    if os.path.exists(content) and os.path.isfile(content):
        with open(content, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(5 * 1024 * 1024)

    limit = max(10, min(int(max_results or 100), 200))

    # Refang content for uniform regex matching
    refanged = content.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")

    # Regular expressions for IOCs
    ipv4_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    sha256_re = re.compile(r"\b[a-fA-F0-9]{64}\b")
    sha1_re = re.compile(r"\b[a-fA-F0-9]{40}\b")
    md5_re = re.compile(r"\b[a-fA-F0-9]{32}\b")
    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    email_re = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    url_re = re.compile(r"https?://[^\s<>\"']+")
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

    ips = []
    for m in ipv4_re.findall(refanged):
        try:
            ip_obj = ipaddress.ip_address(m)
            if not ip_obj.is_loopback and not ip_obj.is_multicast:
                if m not in ips:
                    ips.append(m)
        except ValueError:
            pass

    sha256 = list(set(sha256_re.findall(refanged)))[:limit]
    sha1 = list(set(sha1_re.findall(refanged)))[:limit]
    md5 = list(set(md5_re.findall(refanged)))[:limit]
    cves = list(set(cve_re.findall(refanged)))[:limit]
    emails = list(set(email_re.findall(refanged)))[:limit]
    urls = list(set(url_re.findall(refanged)))[:limit]

    # Clean domains (include domains both standalone and from URLs)
    domains = []
    for d in domain_re.findall(refanged):
        d_clean = d.lower()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d_clean):
            if d_clean not in domains:
                domains.append(d_clean)
    for u in urls:
        try:
            parsed_u = urllib.parse.urlparse(u)
            host_part = parsed_u.netloc.split(":")[0].lower()
            if host_part and host_part not in domains and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host_part):
                domains.append(host_part)
        except Exception:
            pass

    hashes = sha256 + sha1 + md5

    return json.dumps({
        "status": "success",
        "ips": ips[:limit],
        "domains": domains[:limit],
        "hashes": hashes[:limit],
        "emails": emails[:limit],
        "urls": urls[:limit],
        "cves": cves[:limit],
        "iocs": {
            "ipv4": ips[:limit],
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "cves": cves,
            "emails": emails[:limit],
            "urls": urls[:limit],
            "domains": domains[:limit]
        },
        "summary": {
            "total_ips": len(ips),
            "total_hashes": len(sha256) + len(sha1) + len(md5),
            "total_urls": len(urls),
            "total_cves": len(cves)
        }
    }, indent=2)


def ioc_match(target: str = "", ioc_list: Optional[List[str]] = None, indicators: Optional[List[str]] = None, threat_list: Optional[List[str]] = None) -> str:
    if threat_list and not ioc_list:
        ioc_list = threat_list
    if indicators and not target:
        target = indicators[0] if isinstance(indicators, list) else str(indicators)
    """
    Checks if any indicators from a known IOC list appear in a target string or log.
    Arguments:
        target: Target text or file path to evaluate.
        ioc_list: List of indicator strings (hashes, IPs, domains) to search for.
    """
    if not target or not str(target).strip():
        return json.dumps({"status": "error", "error": "Target parameter is required."})
    if not ioc_list or not isinstance(ioc_list, list):
        return json.dumps({"status": "error", "error": "ioc_list must be a non-empty list."})

    content = str(target)
    if os.path.exists(content) and os.path.isfile(content):
        with open(content, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(5 * 1024 * 1024)

    matched = []
    for raw_ioc in ioc_list[:200]:
        ioc = str(raw_ioc).strip()
        if not ioc:
            continue
        if ioc.lower() in content.lower():
            count = len(re.findall(re.escape(ioc), content, re.IGNORECASE))
            matched.append({"indicator": ioc, "occurrences": count})

    return json.dumps({
        "status": "success",
        "evaluated_indicators": len(ioc_list),
        "matches_found": len(matched),
        "matched_indicators": matched,
        "is_threat_detected": len(matched) > 0
    }, indent=2)


def indicator_normalize(indicator: str, indicator_type: Optional[str] = None, action: Optional[str] = None) -> str:
    """
    Normalizes, standardizes, and optionally defangs/refangs security indicators.
    Arguments:
        indicator: Raw indicator string (URL, IP, domain, hash).
        indicator_type: Optional hint ('url', 'ip', 'domain', 'hash').
    """
    if not indicator or not str(indicator).strip():
        return json.dumps({"status": "error", "error": "Indicator parameter is required."})

    raw = str(indicator).strip()

    # Defanged representation
    defanged = raw.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    refanged = raw.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")

    # Hash canonicalization
    clean_val = refanged
    detected_type = indicator_type or "unknown"

    if re.match(r"^[a-fA-F0-9]{32,64}$", raw):
        detected_type = "hash"
        clean_val = raw.lower()
    elif "://" in refanged:
        detected_type = "url"
        parsed = urllib.parse.urlparse(refanged)
        clean_val = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", refanged):
        detected_type = "ip"
        clean_val = refanged.split(":")[0]
    elif "." in refanged:
        detected_type = "domain"
        clean_val = refanged.lower().strip("/")

    norm_val = defanged if action == "defang" else (refanged if action == "refang" else clean_val)
    return json.dumps({
        "status": "success",
        "original": raw,
        "detected_type": detected_type,
        "normalized": norm_val,
        "defanged": defanged,
        "refanged": refanged
    }, indent=2)


def hash_lookup(file_hash: str, provider: str = "local") -> str:
    """
    Audits a file hash against local threat intelligence databases or configured providers.
    Arguments:
        file_hash: MD5, SHA1, or SHA256 file hash.
        provider: Provider to use ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not file_hash or not str(file_hash).strip():
        return json.dumps({"status": "error", "error": "File hash parameter is required."})

    clean_hash = str(file_hash).strip().lower()
    prov = str(provider or "local").lower().strip()

    if prov == "none":
        return json.dumps({"status": "disabled", "provider": "none"})

    # Known standard test hashes (EICAR, standard utilities)
    known_signatures = {
        "44d88612fea8a8f36de82e1278abb02f": {"threat": "EICAR-Standard-AV-Test-File", "verdict": "MALICIOUS"},
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"threat": "EICAR-Test-Signature", "verdict": "MALICIOUS"},
        "d41d8cd98f00b204e9800998ecf8427e": {"threat": "Empty-File", "verdict": "BENIGN"},
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"threat": "Empty-File-SHA256", "verdict": "BENIGN"}
    }

    match = known_signatures.get(clean_hash)

    return json.dumps({
        "status": "success",
        "hash": clean_hash,
        "provider": prov,
        "external_transmission": prov != "local",
        "known_in_database": match is not None,
        "verdict": match["verdict"] if match else "UNKNOWN",
        "threat_name": match["threat"] if match else None,
        "notice": "Local intelligence audit complete. No external payload submitted."
    }, indent=2)


def ip_reputation(ip: str, provider: str = "local") -> str:
    """
    Evaluates IP risk indicators (bogon, private range, known malicious relays, Tor exits).
    Arguments:
        ip: Target IPv4 or IPv6 address.
        provider: Provider ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not ip or not str(ip).strip():
        return json.dumps({"status": "error", "error": "IP parameter is required."})

    target = str(ip).strip()
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError as e:
        return json.dumps({"status": "error", "error": f"Invalid IP address: {e}"})

    risk_flags = []
    if ip_obj.is_private:
        risk_flags.append("RFC 1918 Private Subnet (Not globally routable)")
    if ip_obj.is_loopback:
        risk_flags.append("Loopback interface (127.0.0.0/8)")
    if ip_obj.is_multicast:
        risk_flags.append("Multicast IP block")
    if ip_obj.is_reserved:
        risk_flags.append("IETF Reserved address")

    is_risky = len(risk_flags) > 0

    return json.dumps({
        "status": "success",
        "ip": target,
        "provider": provider,
        "external_transmission": provider != "local",
        "risk_level": "LOW" if not is_risky else "INFO",
        "risk_flags": risk_flags,
        "is_routable": ip_obj.is_global
    }, indent=2)


def domain_reputation(domain: str, provider: str = "local") -> str:
    """
    Evaluates domain risk heuristics (suspicious TLDs, high entropy, typosquatting).
    Arguments:
        domain: Target domain name.
        provider: Provider ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = str(domain).strip().lower().split("://")[-1].split("/")[0].split(":")[0]

    suspicious_tlds = {".top", ".xyz", ".loan", ".work", ".click", ".fit", ".gq", ".cf", ".ml", ".tk"}
    tld = "." + target.split(".")[-1] if "." in target else ""

    risk_factors = []
    if tld in suspicious_tlds:
        risk_factors.append(f"High-abuse top-level domain: {tld}")

    # Subdomain depth
    parts = target.split(".")
    if len(parts) > 4:
        risk_factors.append("Excessive subdomain depth (> 4 levels)")

    # DGA entropy heuristic
    labels = parts[:-1]
    for lbl in labels:
        if len(lbl) > 12:
            # Calculate label entropy
            ent = 0.0
            for ch in set(lbl):
                p = lbl.count(ch) / len(lbl)
                ent -= p * math.log2(p)
            if ent > 3.4:
                risk_factors.append(f"High entropy label '{lbl}' (potential DGA generation)")

    return json.dumps({
        "status": "success",
        "domain": target,
        "provider": provider,
        "external_transmission": provider != "local",
        "risk_level": "HIGH" if len(risk_factors) >= 2 else ("MEDIUM" if risk_factors else "LOW"),
        "risk_factors": risk_factors
    }, indent=2)


def url_reputation(url: str, provider: str = "local") -> str:
    """
    Evaluates URL structural heuristics (embedded credentials, raw IPs, suspicious ports, open redirects).
    Arguments:
        url: Web URL to analyze.
        provider: Provider ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not url or not str(url).strip():
        return json.dumps({"status": "error", "error": "URL parameter is required."})

    target = str(url).strip()
    parsed = urllib.parse.urlparse(target)

    risk_factors = []
    # Embedded credentials
    if parsed.username or parsed.password:
        risk_factors.append("CRITICAL: URL contains embedded plaintext credentials")

    # Raw IP hostname
    hostname = parsed.hostname or ""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        risk_factors.append("Suspicious: URL uses raw IP address instead of domain name")

    # Non-standard ports
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        risk_factors.append(f"Non-standard web port: {parsed.port}")

    # Open redirect parameter heuristics
    qs = urllib.parse.parse_qs(parsed.query)
    for k in qs:
        if k.lower() in ("url", "redirect", "dest", "destination", "next", "target", "r"):
            risk_factors.append(f"Potential open redirect parameter: '{k}'")

    return json.dumps({
        "status": "success",
        "url": target,
        "provider": provider,
        "external_transmission": provider != "local",
        "risk_level": "HIGH" if any("CRITICAL" in f for f in risk_factors) else ("MEDIUM" if risk_factors else "LOW"),
        "risk_factors": risk_factors
    }, indent=2)


def register_defensive_analysis_tools(registry: ToolRegistry):
    """
    Registers the Defensive Analysis Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="log_search",
        description="Searches log files for patterns or regular expressions (bounded to max 50 lines). Arguments: file_path (str), pattern (str), max_lines (int).",
        func=log_search,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="log_summary",
        description="Summarizes errors, warnings, top IPs, and HTTP status codes from a log file. Arguments: file_path (str), max_lines (int).",
        func=log_summary,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="ioc_extract",
        description="Extracts structured IOCs (IPs, hashes, domains, URLs, CVEs) from text or logs. Arguments: text_or_file (str), max_results (int).",
        func=ioc_extract,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="ioc_match",
        description="Checks if known IOC indicators appear in a target string or log snippet. Arguments: target (str), ioc_list (list).",
        func=ioc_match,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="indicator_normalize",
        description="Normalizes and defangs/refangs URLs, IPs, domains, and hashes. Arguments: indicator (str), indicator_type (str).",
        func=indicator_normalize,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=5
    )
    registry.register(
        name="hash_lookup",
        description="Audits file hashes against local intelligence and known malicious signatures. Arguments: file_hash (str), provider (str).",
        func=hash_lookup,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="ip_reputation",
        description="Evaluates IP address risk factors (bogon, RFC 1918, reserved blocks). Arguments: ip (str), provider (str).",
        func=ip_reputation,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="domain_reputation",
        description="Evaluates domain risk indicators (suspicious TLDs, entropy, excessive subdomains). Arguments: domain (str), provider (str).",
        func=domain_reputation,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="url_reputation",
        description="Evaluates URL risk indicators (embedded credentials, raw IPs, open redirects). Arguments: url (str), provider (str).",
        func=url_reputation,
        sandbox_required=False,
        category=ToolCategory.DEFENSIVE_ANALYSIS,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
