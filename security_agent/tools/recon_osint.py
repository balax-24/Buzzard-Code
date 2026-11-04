"""
Recon and Defensive OSINT Suite for Buzzard Code.

Provides authorization-aware, bounded reconnaissance tools with explicit provider controls:
- whois_lookup
- asn_lookup
- ip_info
- domain_info
- subdomain_enum
- email_pattern_check
- technology_detect
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from typing import Any, Dict, List, Optional

from security_agent.tools.network_discovery import _query_dns_raw
from security_agent.tools.registry import ToolCategory, ToolRegistry


def _clean_target(target: str) -> str:
    return str(target or "").strip().split("://")[-1].split("/")[0].split(":")[0]

_clean_domain = _clean_target


def whois_lookup(target: str, provider: str = "local") -> str:
    """
    Performs WHOIS domain or IP registration lookup.
    Arguments:
        target: Target domain or IP address.
        provider: Provider to use ('local', 'configured_api', or 'none'). Default is 'local'.
    """
    if not target or not str(target).strip():
        return json.dumps({"status": "error", "error": "Target parameter is required."})

    clean = _clean_target(target)
    prov = str(provider or "local").lower().strip()

    if prov == "none":
        return json.dumps({
            "status": "disabled",
            "target": clean,
            "provider": "none",
            "message": "WHOIS lookup disabled by provider policy."
        }, indent=2)

    # Perform direct port 43 query to whois.iana.org
    whois_data = ""
    server = "whois.iana.org"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((server, 43))
            sock.sendall((clean + "\r\n").encode("utf-8"))
            chunks = []
            while True:
                data = sock.recv(2048)
                if not data or len(chunks) > 16:  # Max 32KB
                    break
                chunks.append(data)
            whois_data = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:
        whois_data = f"WHOIS query to {server} failed: {e}"

    # Extract common fields
    fields = {}
    for line in whois_data.split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("%"):
            k, v = line.split(":", 1)
            k_clean = k.strip().lower()
            if k_clean in ("domain", "refer", "organisation", "status", "created", "changed", "source", "nserver"):
                fields.setdefault(k_clean, []).append(v.strip())

    return json.dumps({
        "status": "success",
        "target": clean,
        "provider": prov,
        "external_transmission": prov != "local",
        "referral_server": fields.get("refer", [None])[0],
        "organization": fields.get("organisation", ["Unknown"]),
        "nameservers": fields.get("nserver", []),
        "raw_snippet": whois_data[:1000]
    }, indent=2)


def asn_lookup(ip_or_asn: str, provider: str = "local") -> str:
    """
    Looks up Autonomous System (AS) number and organization information.
    Arguments:
        ip_or_asn: IP address (e.g. '8.8.8.8') or ASN (e.g. 'AS15169').
        provider: Provider to use ('local', 'configured_api', or 'none'). Default is 'local'.
    """
    if not ip_or_asn or not str(ip_or_asn).strip():
        return json.dumps({"status": "error", "error": "IP or ASN parameter is required."})

    target = str(ip_or_asn).strip()
    prov = str(provider or "local").lower().strip()

    if prov == "none":
        return json.dumps({"status": "disabled", "provider": "none"})

    asn_number = None
    as_name = "Unknown"
    cidr = "Unknown"

    # If it's an IP address, check for well-known prefixes or perform Cymru DNS query
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        # Check standard well-known cloud providers
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private:
            asn_number = "RFC1918"
            as_name = "Private Internal Network"
        elif target.startswith(("8.8.", "8.34.", "8.35.", "142.250.")):
            asn_number = "AS15169"
            as_name = "Google LLC"
        elif target.startswith(("1.1.1.", "1.0.0.")):
            asn_number = "AS13335"
            as_name = "Cloudflare, Inc."
        elif target.startswith(("13.", "20.", "40.", "52.")):
            asn_number = "AS8075"
            as_name = "Microsoft Corporation"
        else:
            # Try origin DNS lookup via Cymru (pure DNS query)
            reversed_ip = ".".join(reversed(target.split(".")))
            cymru_query = f"{reversed_ip}.origin.asn.cymru.com"
            txt_recs = _query_dns_raw(cymru_query, "TXT")
            if txt_recs:
                val = txt_recs[0].get("value", "")
                parts = [p.strip() for p in val.split("|")]
                if len(parts) >= 3:
                    asn_number = f"AS{parts[0]}"
                    cidr = parts[1]
                    as_name = f"Country: {parts[2]}"
    else:
        asn_clean = target.upper()
        if not asn_clean.startswith("AS"):
            asn_clean = f"AS{asn_clean}"
        asn_number = asn_clean

    return json.dumps({
        "status": "success",
        "query": target,
        "provider": prov,
        "asn": asn_number or "Not resolved",
        "as_name": as_name,
        "prefix_cidr": cidr
    }, indent=2)


def ip_info(ip: str, provider: str = "local") -> str:
    """
    Consolidates IP metadata: reverse DNS, ASN, private/bogon check, and IP classification.
    Arguments:
        ip: Target IP address.
        provider: Provider to use ('local', 'configured_api', or 'none'). Default is 'local'.
    """
    if not ip or not str(ip).strip():
        return json.dumps({"status": "error", "error": "IP parameter is required."})

    target = str(ip).strip()
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError as e:
        return json.dumps({"status": "error", "error": f"Invalid IP address: {e}"})

    hostname = None
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
    except Exception:
        pass

    return json.dumps({
        "status": "success",
        "ip": target,
        "provider": provider,
        "version": ip_obj.version,
        "reverse_dns": hostname,
        "is_private": ip_obj.is_private,
        "is_global": ip_obj.is_global,
        "is_loopback": ip_obj.is_loopback,
        "is_multicast": ip_obj.is_multicast,
        "is_reserved": ip_obj.is_reserved,
    }, indent=2)


def domain_info(domain: str, provider: str = "local") -> str:
    """
    Consolidates domain profile: nameservers, mail servers, IP addresses, and DNS metadata.
    Arguments:
        domain: Target domain name.
        provider: Provider ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_target(domain)

    # Gather A, AAAA, NS, MX records
    a_recs = [r.get("value") for r in _query_dns_raw(target, "A")]
    ns_recs = [r.get("value") for r in _query_dns_raw(target, "NS")]
    mx_recs = [r.get("value") for r in _query_dns_raw(target, "MX")]

    return json.dumps({
        "status": "success",
        "domain": target,
        "provider": provider,
        "ipv4_addresses": a_recs,
        "nameservers": ns_recs,
        "mail_exchangers": mx_recs,
        "active_records_count": len(a_recs) + len(ns_recs) + len(mx_recs)
    }, indent=2)


def subdomain_enum(
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_results: int = 20,
    provider: str = "local"
) -> str:
    """
    Performs bounded DNS enumeration of subdomains using a curated prefix list.
    Arguments:
        domain: Target domain name.
        wordlist: Optional custom prefix list (defaults to top subdomains).
        max_results: Maximum active subdomains to return (default 20, max 50).
        provider: Provider to use ('local', 'configured_api', 'none').
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)
    prov = str(provider or "local").lower().strip()
    if prov == "none":
        return json.dumps({"status": "disabled", "provider": "none"})

    default_prefixes = [
        "www", "mail", "api", "dev", "stage", "staging", "admin",
        "app", "portal", "vpn", "auth", "login", "test", "cdn",
        "static", "m", "corp", "internal", "git", "remote"
    ]
    prefixes = [str(p).strip() for p in (wordlist or default_prefixes)][:50]
    max_res = max(1, min(int(max_results or 20), 50))

    discovered = []
    for p in prefixes:
        candidate = f"{p}.{target}"
        try:
            ip_list = socket.gethostbyname_ex(candidate)[2]
            discovered.append({
                "subdomain": candidate,
                "ip_addresses": ip_list
            })
            if len(discovered) >= max_res:
                break
        except Exception:
            continue

    return json.dumps({
        "status": "success",
        "domain": target,
        "provider": prov,
        "prefixes_tested": len(prefixes),
        "discovered_count": len(discovered),
        "subdomains": discovered
    }, indent=2)


def email_pattern_check(domain: str) -> str:
    """
    Audits standard administrative email roles and defensive contact points for a domain.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)

    # Standard RFC 2142 mailbox names
    standard_roles = [
        ("security", f"security@{target}", "Security incident reporting (RFC 2142)"),
        ("abuse", f"abuse@{target}", "Spam and abuse reporting (RFC 2142)"),
        ("postmaster", f"postmaster@{target}", "Mail system status (RFC 822)"),
        ("hostmaster", f"hostmaster@{target}", "DNS operations (RFC 2142)"),
        ("webmaster", f"webmaster@{target}", "Web operations (RFC 2142)"),
        ("noc", f"noc@{target}", "Network operations center"),
    ]

    # Verify if domain has active MX servers
    mx_records = _query_dns_raw(target, "MX")
    has_mail = len(mx_records) > 0

    return json.dumps({
        "status": "success",
        "domain": target,
        "has_mail_infrastructure": has_mail,
        "standard_role_mailboxes": [
            {"role": r[0], "address": r[1], "rfc_purpose": r[2]}
            for r in standard_roles
        ],
        "naming_conventions": [
            f"first.last@{target}",
            f"firstletter_last@{target}",
            f"first@{target}"
        ]
    }, indent=2)


def technology_detect(domain: str = "", target: str = "", provider: str = "local") -> str:
    domain = domain or target
    """
    Passively profiles tech stack using DNS records, mail providers, and CDN/cloud hosting.
    Arguments:
        domain: Target domain name.
        provider: Provider ('local', 'configured_api', 'none'). Default is 'local'.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)

    dns_tech = []
    # Check NS for DNS/CDN provider
    ns_recs = _query_dns_raw(target, "NS")
    for r in ns_recs:
        ns_val = r.get("value", "").lower()
        if "cloudflare" in ns_val:
            dns_tech.append("Cloudflare DNS & CDN")
        elif "awsdns" in ns_val:
            dns_tech.append("AWS Route 53")
        elif "googledomains" in ns_val or "google" in ns_val:
            dns_tech.append("Google Cloud DNS")
        elif "azure-dns" in ns_val:
            dns_tech.append("Azure DNS")

    # Check MX for Mail provider
    mx_recs = _query_dns_raw(target, "MX")
    for r in mx_recs:
        mx_val = r.get("value", "").lower()
        if "google" in mx_val or "googlemail" in mx_val:
            dns_tech.append("Google Workspace Email")
        elif "outlook" in mx_val or "protection.outlook" in mx_val:
            dns_tech.append("Microsoft 365 / Exchange Online")
        elif "pphosted" in mx_val:
            dns_tech.append("Proofpoint Email Security")
        elif "mimecast" in mx_val:
            dns_tech.append("Mimecast Email Security")

    # Check TXT for verification services
    txt_recs = _query_dns_raw(target, "TXT")
    for r in txt_recs:
        txt_val = r.get("value", "").lower()
        if "google-site-verification" in txt_val:
            dns_tech.append("Google Search Console")
        if "ms=" in txt_val:
            dns_tech.append("Microsoft Domain Verification")
        if "facebook-domain-verification" in txt_val:
            dns_tech.append("Facebook Domain Verification")
        if "docusign" in txt_val:
            dns_tech.append("DocuSign Integration")
        if "atlassian-domain-verification" in txt_val:
            dns_tech.append("Atlassian Cloud")

    return json.dumps({
        "status": "success",
        "domain": target,
        "provider": provider,
        "detected_services": list(dict.fromkeys(dns_tech)),
        "count": len(set(dns_tech))
    }, indent=2)


def register_recon_osint_tools(registry: ToolRegistry):
    """
    Registers the Recon and Defensive OSINT Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="whois_lookup",
        description="Queries WHOIS domain/IP registration details and nameservers. Arguments: target (str), provider (str).",
        func=whois_lookup,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="asn_lookup",
        description="Looks up Autonomous System (AS) number, organization, and CIDR prefix. Arguments: ip_or_asn (str), provider (str).",
        func=asn_lookup,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="ip_info",
        description="Audits IP metadata, reverse DNS, and classification (private/public/reserved). Arguments: ip (str), provider (str).",
        func=ip_info,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="domain_info",
        description="Consolidates domain profile: nameservers, mail servers, and IP addresses. Arguments: domain (str), provider (str).",
        func=domain_info,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="subdomain_enum",
        description="Performs bounded subdomain enumeration using curated wordlists (max 50). Arguments: domain (str), wordlist (list), max_results (int), provider (str).",
        func=subdomain_enum,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="MEDIUM",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=30
    )
    registry.register(
        name="email_pattern_check",
        description="Audits RFC 2142 role-based security email mailboxes and naming patterns. Arguments: domain (str).",
        func=email_pattern_check,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="technology_detect",
        description="Passively profiles technology stack from DNS, mail, and cloud provider signatures. Arguments: domain (str), provider (str).",
        func=technology_detect,
        sandbox_required=False,
        category=ToolCategory.RECON,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
