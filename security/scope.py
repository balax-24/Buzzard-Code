import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Optional, Tuple


def extract_host_and_port(target: str) -> Tuple[str, Optional[int]]:
    """
    Extracts the hostname/IP and port (if any) from a target string or URL.
    """
    if not target:
        return "", None

    if "://" not in target:
        target_url = f"http://{target}"
    else:
        target_url = target

    try:
        parsed = urlparse(target_url)
        netloc = parsed.netloc
        if not netloc:
            netloc = parsed.path.split("/")[0]

        if ":" in netloc:
            host, port_str = netloc.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
        else:
            host = netloc
            port = parsed.port

        return host, port
    except Exception:
        if ":" in target:
            parts = target.split(":")
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], None
        return target, None


def resolve_host(host: str) -> List[str]:
    """
    Resolves a hostname to a list of IP addresses.
    """
    if not host:
        return []
    try:
        info = socket.getaddrinfo(host, None)
        ips = list(set(item[4][0] for item in info))
        return ips
    except Exception:
        return []


def is_in_scope(target: str, scope: List[str]) -> bool:
    """
    Checks if a target host, CIDR, domain, or URL is authorized within the assessment scope.
    Supports exact matching, subdomains, CIDR subnet matching, and IP resolution.
    """
    if not target or not scope:
        return False

    clean_target = str(target).strip()

    # 1. CIDR subnet target check (e.g., target '192.168.1.0/28')
    if "/" in clean_target and not clean_target.startswith(("http://", "https://")):
        try:
            target_net = ipaddress.ip_network(clean_target, strict=False)
            for allowed in scope:
                try:
                    allowed_net = ipaddress.ip_network(str(allowed).strip(), strict=False)
                    if target_net.subnet_of(allowed_net) or target_net == allowed_net:
                        return True
                except ValueError:
                    pass
        except ValueError:
            pass

    target_host, _ = extract_host_and_port(clean_target)
    if not target_host:
        target_host = clean_target.split("://")[-1].split("/")[0].split(":")[0]
    if not target_host:
        return False

    target_host_lower = target_host.lower()

    # Target IP check
    target_ip = None
    try:
        target_ip = ipaddress.ip_address(target_host_lower)
    except ValueError:
        pass

    target_ips = resolve_host(target_host_lower) if not target_ip else [str(target_ip)]

    for allowed in scope:
        clean_allowed = str(allowed).strip()

        # CIDR scope match (e.g. allowed is '192.168.1.0/24' and target is '192.168.1.15')
        if "/" in clean_allowed and not clean_allowed.startswith(("http://", "https://")):
            try:
                allowed_net = ipaddress.ip_network(clean_allowed, strict=False)
                if target_ip and target_ip in allowed_net:
                    return True
                for ip_str in target_ips:
                    try:
                        if ipaddress.ip_address(ip_str) in allowed_net:
                            return True
                    except ValueError:
                        pass
            except ValueError:
                pass

        allowed_host, _ = extract_host_and_port(clean_allowed)
        if not allowed_host:
            allowed_host = clean_allowed.split("://")[-1].split("/")[0].split(":")[0]
        if not allowed_host:
            continue

        allowed_host_lower = allowed_host.lower()

        # Exact match
        if target_host_lower == allowed_host_lower:
            return True

        # Wildcard or subdomain match (*.example.com or sub.example.com under example.com)
        if allowed_host_lower.startswith("*."):
            suffix = allowed_host_lower[2:]
            if target_host_lower == suffix or target_host_lower.endswith(f".{suffix}"):
                return True
        elif target_host_lower.endswith(f".{allowed_host_lower}"):
            return True

        # Resolved IP match
        allowed_ips = resolve_host(allowed_host_lower)
        if any(ip in allowed_ips for ip in target_ips if ip):
            return True

    return False


class ScopeEngine:
    """
    Enforces authorization scope boundaries across hostnames, domains, subnets, and IPs.
    """
    def __init__(self, scope: Optional[List[str]] = None):
        self.scope = scope or []

    def is_in_scope(self, target: str) -> bool:
        return is_in_scope(target, self.scope)

    def validate(self, target: str) -> Tuple[bool, str]:
        if not self.scope:
            return True, "Scope is unconstrained."
        if is_in_scope(target, self.scope):
            return True, f"Target '{target}' is within authorized scope."
        return False, f"Target '{target}' is outside authorized assessment scope ({self.scope})."
