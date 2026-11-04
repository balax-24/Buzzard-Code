"""
TLS and Certificate Security Suite for Buzzard Code.

Provides bounded, safe, non-destructive TLS and certificate evaluation tools:
- tls_version_check
- tls_cipher_check
- certificate_inspect
- certificate_expiry
- certificate_chain
- certificate_hostname
"""

from __future__ import annotations

import datetime
import fnmatch
import json
import socket
import ssl
from typing import Any, Dict, List, Optional

from tools.registry import ToolCategory, ToolRegistry


def _clean_host_and_port(host: str, port: int = 443) -> tuple[str, int]:
    clean_host = str(host or "").strip().split("://")[-1].split("/")[0].split(":")[0]
    port_num = int(port or 443)
    return clean_host, port_num


def tls_version_check(host: str, port: int = 443) -> str:
    """
    Checks the negotiated and supported TLS versions on a target host.
    Arguments:
        host: Target hostname or IP address.
        port: TLS port number (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    results = {}
    deprecated_found = []

    # Test modern default
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                negotiated = ssock.version()
                results["negotiated_version"] = negotiated
    except Exception as e:
        return json.dumps({"status": "error", "host": target_host, "error": f"TLS handshake failed: {e}"}, indent=2)

    # Test specific versions if supported by Python SSL
    version_probes = []
    if hasattr(ssl, "TLSVersion"):
        version_probes = [
            ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None), True),
            ("TLSv1_1", getattr(ssl.TLSVersion, "TLSv1_1", None), True),
            ("TLSv1_2", getattr(ssl.TLSVersion, "TLSv1_2", None), False),
            ("TLSv1_3", getattr(ssl.TLSVersion, "TLSv1_3", None), False),
        ]

    supported = []
    for ver_name, ver_enum, is_deprecated in version_probes:
        if ver_enum is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_enum
            ctx.maximum_version = ver_enum
            with socket.create_connection((target_host, port_num), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                    supported.append(ver_name)
                    if is_deprecated:
                        deprecated_found.append(ver_name)
        except Exception:
            pass

    return json.dumps({
        "status": "success",
        "host": target_host,
        "port": port_num,
        "negotiated_version": results.get("negotiated_version"),
        "supported_versions": supported if supported else [results.get("negotiated_version", "Unknown")],
        "deprecated_versions_detected": deprecated_found,
        "secure": len(deprecated_found) == 0
    }, indent=2)


def tls_cipher_check(host: str, port: int = 443) -> str:
    """
    Audits the active cipher suite, encryption strength, and checks for weak/deprecated ciphers.
    Arguments:
        host: Target hostname or IP address.
        port: TLS port number (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cipher = ssock.cipher()
                # cipher is (name, protocol, bits)
                cipher_name = cipher[0]
                proto = cipher[1]
                bits = cipher[2]

                # Check for weak patterns
                weak_patterns = ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon"]
                is_weak = any(w.lower() in cipher_name.lower() for w in weak_patterns) or bits < 128
                is_cbc = "CBC" in cipher_name

                findings = []
                if is_weak:
                    findings.append("Weak cipher algorithm or key length < 128 bits")
                if is_cbc:
                    findings.append("CBC mode cipher in use (potential Lucky13/Padding Oracle exposure if TLS < 1.3)")

                return json.dumps({
                    "status": "success",
                    "host": target_host,
                    "port": port_num,
                    "cipher": {
                        "name": cipher_name,
                        "protocol": proto,
                        "bits": bits
                    },
                    "is_weak": is_weak,
                    "findings": findings if findings else ["Strong cipher suite configured"]
                }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "host": target_host, "error": f"Cipher check failed: {e}"}, indent=2)


def certificate_inspect(host: str, port: int = 443) -> str:
    """
    Inspects SSL/TLS certificate details: subject, issuer, validity period, serial, and SANs.
    Arguments:
        host: Target hostname or IP address.
        port: TLS port number (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return json.dumps({"status": "error", "error": "No certificate presented by server."})

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                sans = [v for k, v in cert.get("subjectAltName", ())]

                return json.dumps({
                    "status": "success",
                    "host": target_host,
                    "port": port_num,
                    "subject": {
                        "common_name": subject.get("commonName"),
                        "organization": subject.get("organizationName"),
                        "country": subject.get("countryName"),
                    },
                    "issuer": {
                        "common_name": issuer.get("commonName"),
                        "organization": issuer.get("organizationName"),
                        "country": issuer.get("countryName"),
                    },
                    "serial_number": cert.get("serialNumber"),
                    "version": cert.get("version"),
                    "valid_from": cert.get("notBefore"),
                    "valid_until": cert.get("notAfter"),
                    "subject_alt_names": sans,
                }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "host": target_host, "error": f"Certificate inspection failed: {e}"}, indent=2)


def certificate_expiry(host: str, port: int = 443) -> str:
    """
    Calculates days until certificate expiration and checks validity window.
    Arguments:
        host: Target hostname.
        port: Port number (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get("notAfter", "")
                not_before_str = cert.get("notBefore", "")

                # Parse OpenSSL date format e.g. 'May 15 12:00:00 2025 GMT'
                expiry_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                days_left = (expiry_dt - now_dt).days

                is_expired = days_left < 0
                is_expiring_soon = 0 <= days_left <= 30

                return json.dumps({
                    "status": "success",
                    "host": target_host,
                    "valid_until": not_after_str,
                    "days_until_expiry": days_left,
                    "is_expired": is_expired,
                    "is_expiring_soon": is_expiring_soon,
                    "status_label": "EXPIRED" if is_expired else ("EXPIRING_SOON" if is_expiring_soon else "VALID")
                }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "host": target_host, "error": f"Expiry check failed: {e}"}, indent=2)


def certificate_chain(host: str, port: int = 443) -> str:
    """
    Verifies certificate trust chain and checks for self-signed certificates or CA issues.
    Arguments:
        host: Target hostname.
        port: TLS port (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    trusted = False
    error_detail = None
    is_self_signed = False

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                trusted = True
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                if subject.get("commonName") == issuer.get("commonName"):
                    is_self_signed = True
    except ssl.SSLCertVerificationError as e:
        error_detail = str(e)
        if "self signed" in str(e).lower():
            is_self_signed = True
    except Exception as e:
        error_detail = str(e)

    return json.dumps({
        "status": "success" if trusted or error_detail else "error",
        "host": target_host,
        "trusted_by_system_ca": trusted,
        "is_self_signed": is_self_signed,
        "verification_error": error_detail,
    }, indent=2)


def certificate_hostname(host: str, port: int = 443) -> str:
    """
    Verifies that the server certificate matches the target hostname, including wildcard matching.
    Arguments:
        host: Target hostname.
        port: Port number (default 443).
    """
    if not host or not str(host).strip():
        return json.dumps({"status": "error", "error": "Host parameter is required."})

    target_host, port_num = _clean_host_and_port(host, port)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

                all_names = ([cn] if cn else []) + sans
                matches = False
                matched_pattern = None

                for name in all_names:
                    if fnmatch.fnmatch(target_host.lower(), name.lower()):
                        matches = True
                        matched_pattern = name
                        break

                return json.dumps({
                    "status": "success",
                    "host": target_host,
                    "hostname_matches": matches,
                    "matched_pattern": matched_pattern,
                    "certificate_cn": cn,
                    "subject_alt_names": sans
                }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "host": target_host, "error": f"Hostname check failed: {e}"}, indent=2)


def register_tls_security_tools(registry: ToolRegistry):
    """
    Registers the TLS / Certificate Security Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="tls_version_check",
        description="Audits supported and negotiated TLS protocol versions (detects deprecated TLS 1.0/1.1). Arguments: host (str), port (int).",
        func=tls_version_check,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="tls_cipher_check",
        description="Audits negotiated cipher suite, encryption bits, and flags weak/CBC algorithms. Arguments: host (str), port (int).",
        func=tls_cipher_check,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="certificate_inspect",
        description="Inspects detailed certificate fields: Subject, Issuer, Serial, Dates, SANs. Arguments: host (str), port (int).",
        func=certificate_inspect,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="certificate_expiry",
        description="Calculates days until certificate expiration and flags expiring/expired certificates. Arguments: host (str), port (int).",
        func=certificate_expiry,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="certificate_chain",
        description="Validates certificate trust chain against system CAs and detects self-signed certificates. Arguments: host (str), port (int).",
        func=certificate_chain,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="certificate_hostname",
        description="Verifies that certificate Subject and SANs match the target hostname including wildcards. Arguments: host (str), port (int).",
        func=certificate_hostname,
        sandbox_required=False,
        category=ToolCategory.TLS,
        risk_level="LOW",
        read_only=True,
        network_required=True,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
