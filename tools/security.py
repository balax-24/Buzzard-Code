import shlex
from sandbox.container import get_sandbox, ToolResult
from tools.registry import ToolRegistry

def terminal_execute(command: str, sandbox=None) -> str:
    """
    Executes a shell command inside the secure sandbox environment.
    Arguments:
        command: The shell command to run.
    """
    if not command:
        return "Error: Empty command."
    if sandbox is None:
        sandbox = get_sandbox()
        
    res = sandbox.execute(command, tool_name="terminal.execute")
    tool_res = ToolResult.from_sandbox_response(res, command=command, tool_name="terminal.execute")
    return tool_res.to_output_string()

def ping_host(host: str, sandbox) -> str:
    """
    Pings a host to check network reachability inside the sandbox.
    Arguments:
        host: Target IP address or hostname.
    """
    if not host:
        return "Error: Host parameter is required."
        
    # Ping 1 packet, wait 2 seconds
    cmd = f"ping -c 1 -W 2 {host}"
    res = sandbox.execute(cmd)
    
    if res["exit_code"] == 0:
        return f"Host {host} is REACHABLE.\nOutput:\n{res['stdout'].strip()}"
    else:
        err_msg = res['stderr'].strip() or res['stdout'].strip()
        return f"Host {host} is UNREACHABLE or ping failed.\nError: {err_msg}"

def scan_ports(host: str, ports: str, sandbox) -> str:
    """
    Scans a set of TCP ports on a target host.
    Arguments:
        host: Target hostname or IP address.
        ports: Comma-separated list or range of ports (e.g., '22,80,443' or '80-85').
    """
    if not host:
        return "Error: Host parameter is required."
    if not ports:
        return "Error: Ports parameter is required."
        
    # Parse ports
    port_list = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            except ValueError:
                return f"Error: Invalid port range format: {part}"
        else:
            try:
                port_list.append(int(part))
            except ValueError:
                return f"Error: Invalid port format: {part}"
                
    if not port_list:
        return "Error: No valid ports specified."
        
    if len(port_list) > 50:
        return "Error: Maximum of 50 ports can be scanned in a single call."
        
    # Build shell command using netcat
    port_args = " ".join(str(p) for p in port_list)
    cmd = f'for p in {port_args}; do nc -z -w 1 {host} $p && echo "$p: OPEN" || echo "$p: CLOSED"; done'
    
    res = sandbox.execute(cmd)
    if res["exit_code"] != 0 and not res["stdout"]:
        err_msg = res['stderr'].strip() or "Connection error"
        return f"Port scan failed.\nError: {err_msg}"
        
    output_lines = res["stdout"].strip().split("\n")
    open_ports = []
    closed_ports = []
    
    for line in output_lines:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            port_str, status = line.split(":", 1)
            port_str = port_str.strip()
            status = status.strip()
            if status == "OPEN":
                open_ports.append(port_str)
            else:
                closed_ports.append(port_str)
                
    # Format a structured summary response
    summary = [f"Port scan results for {host}:"]
    if open_ports:
        summary.append(f"  OPEN ports: {', '.join(open_ports)}")
    if closed_ports:
        if len(closed_ports) > 10:
            summary.append(f"  CLOSED ports: {len(closed_ports)} ports closed/filtered")
        else:
            summary.append(f"  CLOSED ports: {', '.join(closed_ports)}")
            
    return "\n".join(summary)

def grab_banner(host: str, port: int, sandbox) -> str:
    """
    Attempts to retrieve a service banner from a specific port.
    Arguments:
        host: Target IP or hostname.
        port: Target TCP port number.
    """
    if not host:
        return "Error: Host parameter is required."
    try:
        port_num = int(port)
    except ValueError:
        return f"Error: Invalid port number: {port}"
        
    cmd = f"echo '' | nc -w 2 {host} {port_num}"
    res = sandbox.execute(cmd)
    stdout = res["stdout"].strip()
    stderr = res["stderr"].strip()
    
    if res["exit_code"] == 0 or stdout:
        if stdout:
            # Keep only printable characters
            clean_banner = "".join(ch for ch in stdout if ch.isprintable() or ch in "\r\n\t")
            return f"Successfully retrieved banner from {host}:{port_num}:\n{clean_banner}"
        else:
            return f"Connected to {host}:{port_num} but no banner was returned."
    else:
        err_msg = stderr or "Connection timed out."
        return f"Failed to connect to {host}:{port_num}.\nError: {err_msg}"

import ssl
import socket
import urllib.request
import datetime

def ssl_check(host: str, port: int = 443, sandbox=None) -> str:
    """
    Checks SSL/TLS certificate details, validity, issuer, and cipher suite for a host.
    Arguments:
        host: Target domain or hostname.
        port: SSL port (default: 443).
    """
    if not host:
        return "Error: Host parameter is required."
    
    # Strip scheme and paths if user passes full URL
    clean_host = host.split("://")[-1].split("/")[0].split(":")[0]
    try:
        port_num = int(port) if port else 443
    except Exception:
        port_num = 443
        
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port_num), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                sans = [v for k, v in cert.get("subjectAltName", ())]
                
                lines = [
                    f"SSL/TLS Audit for {clean_host}:{port_num}",
                    f"  TLS Version: {version}",
                    f"  Cipher Suite: {cipher[0]} ({cipher[1]} bits)",
                    f"  Subject: CN={subject.get('commonName', 'Unknown')}, O={subject.get('organizationName', 'Unknown')}",
                    f"  Issuer: CN={issuer.get('commonName', 'Unknown')}, O={issuer.get('organizationName', 'Unknown')}",
                    f"  Valid From: {not_before}",
                    f"  Valid Until: {not_after}",
                    f"  SANs: {', '.join(sans[:10]) if sans else 'None'}"
                ]
                return "\n".join(lines)
    except Exception as e:
        return f"SSL check error on {clean_host}:{port_num}: {e}"

def dns_lookup(host: str, sandbox=None) -> str:
    """
    Performs DNS resolution on target host.
    Arguments:
        host: Target domain name or IP.
    """
    if not host:
        return "Error: Host parameter is required."
    clean_host = host.split("://")[-1].split("/")[0].split(":")[0]
    try:
        ip_list = socket.gethostbyname_ex(clean_host)
        return f"DNS Lookup for {clean_host}:\n  Canonical Name: {ip_list[0]}\n  Aliases: {', '.join(ip_list[1]) if ip_list[1] else 'None'}\n  IP Addresses: {', '.join(ip_list[2])}"
    except Exception as e:
        return f"DNS lookup failed for {clean_host}: {e}"

def check_headers(url: str, sandbox=None) -> str:
    """
    Analyzes HTTP response headers of a target URL for critical security headers.
    Arguments:
        url: Target web URL.
    """
    if not url:
        return "Error: URL parameter is required."
    clean_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
    try:
        req = urllib.request.Request(clean_url, headers={"User-Agent": "BuzzardCode/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
            
        security_headers = {
            "strict-transport-security": "HSTS (Protects against SSL stripping)",
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME-sniffing protection",
            "content-security-policy": "CSP (XSS & injection mitigation)",
            "referrer-policy": "Referrer policy control",
            "permissions-policy": "Permissions / feature policy"
        }
        
        present = []
        missing = []
        for h, desc in security_headers.items():
            if h in headers:
                present.append(f"  ✓ {h}: {headers[h]}")
            else:
                missing.append(f"  ✗ {h} ({desc})")
                
        output = [
            f"Security Header Analysis for {clean_url} (HTTP {status}):",
            f"Present Security Headers ({len(present)}):",
            *(present if present else ["  (None found)"]),
            f"\nMissing / Recommended Security Headers ({len(missing)}):",
            *(missing if missing else ["  (All standard security headers present!)"]),
            f"\nServer Info: {headers.get('server', 'Not disclosed')}",
            f"Powered By: {headers.get('x-powered-by', 'Not disclosed')}"
        ]
        return "\n".join(output)
    except Exception as e:
        return f"Header check failed for {clean_url}: {e}"

def python_executor(code: str, sandbox=None) -> str:
    """
    Executes Python source code safely inside the sandbox.
    Arguments:
        code: Python code string to execute.
    """
    if not code or not code.strip():
        return "Error: Code parameter is required."
    if sandbox is None:
        sandbox = get_sandbox()
        
    cmd = f"python3 -c {shlex.quote(code)}"
    res = sandbox.execute(cmd, tool_name="python_executor")
    stdout = res.get("stdout", "").strip()
    stderr = res.get("stderr", "").strip()
    exit_code = res.get("exit_code", 0)
    
    output = []
    if stdout:
        output.append(stdout)
    if stderr:
        output.append(f"Stderr:\n{stderr}")
    output.append(f"Exit code: {exit_code}")
    return "\n\n".join(output)

def register_security_tools(registry: ToolRegistry):
    """
    Registers the sandbox scanning and execution tools with the registry.
    """
    registry.register(
        name="terminal.execute",
        description="Executes a shell command in the active sandbox after operator approval. Arguments: command (str).",
        func=terminal_execute
    )
    registry.register(
        name="python_executor",
        description="Executes Python source code safely inside the isolated sandbox. Arguments: code (str).",
        func=python_executor
    )
    registry.register(
        name="ping_host",
        description="Sends ICMP packets to verify if a host is reachable. Arguments: host (str).",
        func=ping_host
    )
    registry.register(
        name="scan_ports",
        description="Audits open ports on a target host. Arguments: host (str), ports (str - e.g. '80,443' or '22-80').",
        func=scan_ports
    )
    registry.register(
        name="grab_banner",
        description="Attempts connection to a TCP port to retrieve service banner. Arguments: host (str), port (int).",
        func=grab_banner
    )
    registry.register(
        name="ssl_check",
        description="Audits SSL/TLS certificate, ciphers, issuer, and validity dates. Arguments: host (str), port (int, default 443).",
        func=ssl_check
    )
    registry.register(
        name="dns_lookup",
        description="Resolves DNS records and IPs for a target hostname. Arguments: host (str).",
        func=dns_lookup
    )
    registry.register(
        name="check_headers",
        description="Audits HTTP response headers for missing security protections (HSTS, CSP, X-Frame-Options). Arguments: url (str).",
        func=check_headers
    )
