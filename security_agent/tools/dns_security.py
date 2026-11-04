"""
DNS Security Suite for Buzzard Code.

Provides bounded, safe DNS security audit and defensive mail authentication tools:
- dns_mx_check
- dns_txt_check
- dns_spf_check
- dns_dkim_check
- dns_dmarc_check
- dnssec_check
- zone_transfer_check
"""

from __future__ import annotations

import json
import re
import socket
import struct
from typing import Any, Dict, List, Optional

from security_agent.tools.network_discovery import _query_dns_raw
from security_agent.tools.registry import ToolCategory, ToolRegistry


def _clean_domain(domain: str) -> str:
    return str(domain or "").strip().split("://")[-1].split("/")[0].split(":")[0]


def dns_mx_check(domain: str) -> str:
    """
    Audits Mail Exchanger (MX) records and associated mail server IPs for a domain.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)
    records = _query_dns_raw(target, "MX")

    mx_servers = []
    for rec in records:
        exchange = rec.get("exchange", rec.get("value"))
        priority = rec.get("priority", 10)
        # Resolve MX server IP
        ips = []
        try:
            ips = socket.gethostbyname_ex(exchange)[2]
        except Exception:
            pass

        mx_servers.append({
            "exchange": exchange,
            "priority": priority,
            "ip_addresses": ips
        })

    mx_servers.sort(key=lambda x: x["priority"])

    return json.dumps({
        "status": "success",
        "domain": target,
        "mx_record_count": len(mx_servers),
        "mail_servers": mx_servers,
        "has_mx": len(mx_servers) > 0
    }, indent=2)


def dns_txt_check(domain: str) -> str:
    """
    Retrieves and catalogs all TXT records for a domain.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)
    records = _query_dns_raw(target, "TXT")

    txt_values = [r.get("value", "") for r in records if r.get("value")]

    return json.dumps({
        "status": "success",
        "domain": target,
        "count": len(txt_values),
        "txt_records": txt_values
    }, indent=2)


def dns_spf_check(domain: str) -> str:
    """
    Evaluates SPF (Sender Policy Framework) email authentication record and policies.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target = _clean_domain(domain)
    records = _query_dns_raw(target, "TXT")

    spf_record = None
    for r in records:
        val = r.get("value", "")
        if val.startswith("v=spf1") or "v=spf1 " in val:
            spf_record = val
            break

    if not spf_record:
        return json.dumps({
            "status": "success",
            "domain": target,
            "has_spf": False,
            "security_assessment": "CRITICAL: No SPF record configured (allows unauthorized email spoofing)",
        }, indent=2)

    # Parse SPF mechanisms
    terms = spf_record.split()
    all_qualifier = "neutral"
    all_term = [t for t in terms if t.endswith("all")]

    qualifier_map = {
        "-all": ("HardFail", "SECURE: Strict rejection of unauthorized senders"),
        "~all": ("SoftFail", "ACCEPTABLE: Soft fail for unauthorized senders"),
        "?all": ("Neutral", "WARNING: Neutral policy provides no enforcement"),
        "+all": ("Pass", "CRITICAL: +all explicitly authorizes anyone to spoof this domain"),
    }

    status_eval = ("Unknown", "Custom policy")
    if all_term:
        term = all_term[0]
        status_eval = qualifier_map.get(term, ("Custom", "Custom qualifier"))

    includes = [t for t in terms if t.startswith("include:")]
    ip_blocks = [t for t in terms if t.startswith(("ip4:", "ip6:"))]

    return json.dumps({
        "status": "success",
        "domain": target,
        "has_spf": True,
        "spf_record": spf_record,
        "all_policy": status_eval[0],
        "assessment": status_eval[1],
        "include_count": len(includes),
        "includes": includes,
        "ip_authorizations": ip_blocks,
        "exceeds_dns_lookup_limit": len(includes) > 10
    }, indent=2)


def dns_dkim_check(domain: str, selector: str = "default") -> str:
    """
    Verifies DKIM (DomainKeys Identified Mail) public key record for an explicit selector.
    Arguments:
        domain: Target domain name.
        selector: DKIM selector name (e.g., 'default', 'google', 'k1', 'mail').
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target_domain = _clean_domain(domain)
    sel = str(selector or "default").strip()

    # Query selector._domainkey.domain
    dkim_domain = f"{sel}._domainkey.{target_domain}"
    records = _query_dns_raw(dkim_domain, "TXT")

    dkim_val = None
    for r in records:
        val = r.get("value", "")
        if "v=DKIM1" in val or "p=" in val:
            dkim_val = val
            break

    if not dkim_val:
        return json.dumps({
            "status": "success",
            "domain": target_domain,
            "selector": sel,
            "query_record": dkim_domain,
            "has_dkim": False,
            "notice": f"No DKIM record found for selector '{sel}' at {dkim_domain}."
        }, indent=2)

    key_type = "rsa"
    if "k=ed25519" in dkim_val.lower():
        key_type = "ed25519"
    elif "k=" in dkim_val.lower():
        match = re.search(r"k=([a-zA-Z0-9]+)", dkim_val)
        if match:
            key_type = match.group(1)

    has_pubkey = "p=" in dkim_val and not dkim_val.strip().endswith("p=")

    return json.dumps({
        "status": "success",
        "domain": target_domain,
        "selector": sel,
        "query_record": dkim_domain,
        "has_dkim": True,
        "key_type": key_type,
        "has_public_key": has_pubkey,
        "dkim_record": dkim_val
    }, indent=2)


def dns_dmarc_check(domain: str) -> str:
    """
    Evaluates DMARC (Domain-based Message Authentication, Reporting, and Conformance) policy.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target_domain = _clean_domain(domain)
    dmarc_query = f"_dmarc.{target_domain}"
    records = _query_dns_raw(dmarc_query, "TXT")

    dmarc_record = None
    for r in records:
        val = r.get("value", "")
        if val.startswith("v=DMARC1") or "v=DMARC1" in val:
            dmarc_record = val
            break

    if not dmarc_record:
        return json.dumps({
            "status": "success",
            "domain": target_domain,
            "has_dmarc": False,
            "security_assessment": "CRITICAL: No DMARC record found (domain vulnerable to direct email impersonation)",
        }, indent=2)

    # Parse tags
    tags = {}
    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    subdomain_policy = tags.get("sp", policy).lower()
    pct = tags.get("pct", "100")
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")

    policy_assessments = {
        "reject": ("STRONG", "Full protection: unauthorized emails rejected"),
        "quarantine": ("MODERATE", "Moderate protection: unauthorized emails quarantined/marked spam"),
        "none": ("WEAK", "Monitoring only: unauthorized emails still delivered to inboxes"),
    }

    assessment = policy_assessments.get(policy, ("UNKNOWN", "Custom policy"))

    return json.dumps({
        "status": "success",
        "domain": target_domain,
        "has_dmarc": True,
        "dmarc_record": dmarc_record,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "percentage": pct,
        "reporting_uri": rua,
        "forensic_uri": ruf,
        "enforcement_rating": assessment[0],
        "security_assessment": assessment[1]
    }, indent=2)


def dnssec_check(domain: str) -> str:
    """
    Checks for DNSSEC (Domain Name System Security Extensions) deployment records.
    Arguments:
        domain: Target domain name.
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target_domain = _clean_domain(domain)

    # Query DNSKEY (type 48), DS (type 43), RRSIG (type 46)
    dnskey_recs = _query_dns_raw(target_domain, "DNSKEY")
    ds_recs = _query_dns_raw(target_domain, "DS")

    has_dnssec = len(dnskey_recs) > 0 or len(ds_recs) > 0

    return json.dumps({
        "status": "success",
        "domain": target_domain,
        "dnssec_enabled": has_dnssec,
        "dnskey_count": len(dnskey_recs),
        "ds_count": len(ds_recs),
        "assessment": "DNSSEC is ACTIVE (protects against DNS spoofing/cache poisoning)" if has_dnssec else "DNSSEC is NOT enabled"
    }, indent=2)


def zone_transfer_check(domain: str, nameservers: Optional[List[str]] = None, nameserver: Optional[str] = None) -> str:
    if nameserver and not nameservers:
        nameservers = [nameserver]
    """
    Safely tests authoritative nameservers for DNS AXFR zone transfer vulnerability.
    Arguments:
        domain: Target domain name.
        nameservers: Optional list of specific authoritative nameservers to test (max 3).
    """
    if not domain or not str(domain).strip():
        return json.dumps({"status": "error", "error": "Domain parameter is required."})

    target_domain = _clean_domain(domain)

    # Resolve authoritative NS if not provided
    ns_candidates = []
    if nameservers and isinstance(nameservers, list):
        ns_candidates = [str(ns).strip() for ns in nameservers][:3]
    else:
        ns_recs = _query_dns_raw(target_domain, "NS")
        for rec in ns_recs:
            ns_val = rec.get("value")
            if ns_val and ns_val not in ns_candidates:
                ns_candidates.append(ns_val)
        if not ns_candidates:
            # Fallback to standard NS
            ns_candidates = [f"ns1.{target_domain}", f"ns2.{target_domain}"]

    ns_to_test = ns_candidates[:3]
    test_results = []
    vulnerable_found = False

    for ns in ns_to_test:
        ns_ip = ns
        try:
            ns_ip = socket.gethostbyname(ns)
        except Exception:
            pass

        # Perform AXFR TCP query with 3s timeout
        # Type AXFR = 252 (0x00FC), Class IN = 1
        tx_id = 0x55AA
        qname = b""
        for part in target_domain.split("."):
            if part:
                qname += bytes([len(part)]) + part.encode("ascii", errors="replace")
        qname += b"\x00"

        packet = struct.pack(">HHHHHH", tx_id, 0x0000, 1, 0, 0, 0) + qname + struct.pack(">HH", 252, 1)
        tcp_msg = struct.pack(">H", len(packet)) + packet

        ns_vulnerable = False
        status_msg = "Refused / Not allowed"

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect((ns_ip, 53))
                sock.sendall(tcp_msg)
                resp_len_bytes = sock.recv(2)
                if len(resp_len_bytes) == 2:
                    resp_len = struct.unpack(">H", resp_len_bytes)[0]
                    resp = sock.recv(min(resp_len, 4096))
                    if len(resp) >= 6:
                        flags = struct.unpack(">H", resp[2:4])[0]
                        rcode = flags & 0x000F
                        if rcode == 0:  # NOERROR
                            ns_vulnerable = True
                            status_msg = "CRITICAL: Zone transfer ACCEPTED (AXFR open)"
                        elif rcode == 5:
                            status_msg = "REFUSED (Zone transfer properly secured)"
                        elif rcode == 9:
                            status_msg = "NOTAUTH (Server not authoritative for zone)"
        except Exception as e:
            status_msg = f"Connection failed/timed out: {e}"

        if ns_vulnerable:
            vulnerable_found = True

        test_results.append({
            "nameserver": ns,
            "ip": ns_ip,
            "vulnerable": ns_vulnerable,
            "result": status_msg
        })

    return json.dumps({
        "status": "success",
        "domain": target_domain,
        "nameservers_tested": len(test_results),
        "zone_transfer_vulnerable": vulnerable_found,
        "details": test_results
    }, indent=2)


def register_dns_security_tools(registry: ToolRegistry):
    """
    Registers the DNS Security Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="dns_mx_check",
        description="Audits Mail Exchanger (MX) records and associated mail server IPs. Arguments: domain (str).",
        func=dns_mx_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="dns_txt_check",
        description="Catalogues all TXT verification and service records for a domain. Arguments: domain (str).",
        func=dns_txt_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="dns_spf_check",
        description="Evaluates Sender Policy Framework email authentication and all-qualifier enforcement. Arguments: domain (str).",
        func=dns_spf_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="dns_dkim_check",
        description="Audits DKIM public key record for an explicit selector (default 'default'). Arguments: domain (str), selector (str).",
        func=dns_dkim_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="dns_dmarc_check",
        description="Evaluates DMARC anti-spoofing policy, enforcement mode (p=reject/quarantine/none), and reporting URIs. Arguments: domain (str).",
        func=dns_dmarc_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="dnssec_check",
        description="Verifies DNSSEC status, DNSKEY records, and DS trust delegation for a domain. Arguments: domain (str).",
        func=dnssec_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="zone_transfer_check",
        description="Safely audits authoritative nameservers for DNS AXFR zone transfer disclosure. Arguments: domain (str), nameservers (list).",
        func=zone_transfer_check,
        sandbox_required=False,
        category=ToolCategory.DNS,
        risk_level="MEDIUM",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=20
    )
