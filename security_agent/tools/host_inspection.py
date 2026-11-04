"""
Host Inspection and Local Security Suite for Buzzard Code.

Provides bounded, safe host auditing with mandatory secret redaction and resource controls:
- process_list
- listening_ports
- network_interfaces
- routing_table
- system_info
- environment_info
- file_metadata
- file_hash
- directory_inventory
- permissions_check
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional
import psutil

from security_agent.tools.registry import ToolCategory, ToolRegistry


def process_list(max_results: int = 50) -> str:
    """
    Inspects active running processes on the system (bounded to max 50 entries).
    Arguments:
        max_results: Maximum number of processes to return (default 50, max 100).
    """
    limit = max(1, min(int(max_results or 50), 100))
    procs = []

    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
        try:
            info = p.info
            mem_rss = info['memory_info'].rss if info.get('memory_info') else 0
            procs.append({
                "pid": info['pid'],
                "name": info['name'],
                "user": info.get('username') or "N/A",
                "cpu_percent": info.get('cpu_percent', 0.0),
                "memory_mb": round(mem_rss / (1024 * 1024), 2)
            })
            if len(procs) >= limit:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return json.dumps({
        "status": "success",
        "total_returned": len(procs),
        "processes": procs
    }, indent=2)


def listening_ports(proto: str = "all") -> str:
    """
    Audits active listening TCP and UDP sockets and their associated process IDs.
    Arguments:
        proto: Protocol filter ('all', 'tcp', 'udp').
    """
    clean_proto = str(proto or "all").lower().strip()
    kind = "inet"
    if clean_proto == "tcp":
        kind = "tcp"
    elif clean_proto == "udp":
        kind = "udp"

    listeners = []
    try:
        conns = psutil.net_connections(kind=kind)
        for c in conns:
            if c.status == psutil.CONN_LISTEN or c.type == socket.SOCK_DGRAM:
                proc_name = None
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                listeners.append({
                    "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "local_address": c.laddr.ip if c.laddr else "",
                    "local_port": c.laddr.port if c.laddr else 0,
                    "status": c.status,
                    "pid": c.pid,
                    "process_name": proc_name
                })
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Failed to retrieve socket connections: {e}"}, indent=2)

    return json.dumps({
        "status": "success",
        "count": len(listeners),
        "listeners": listeners[:100]
    }, indent=2)


def network_interfaces() -> str:
    """
    Enumerates host network interfaces, IP addresses, netmasks, and MAC addresses.
    """
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        result = {}

        for iface_name, iface_addrs in addrs.items():
            stat = stats.get(iface_name)
            entries = []
            mac = None
            for addr in iface_addrs:
                if addr.family == psutil.AF_LINK or (hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET):
                    mac = addr.address
                elif addr.family == socket.AF_INET:
                    entries.append({"family": "IPv4", "address": addr.address, "netmask": addr.netmask})
                elif addr.family == socket.AF_INET6:
                    entries.append({"family": "IPv6", "address": addr.address, "netmask": addr.netmask})

            result[iface_name] = {
                "is_up": stat.isup if stat else True,
                "speed_mbps": stat.speed if stat else 0,
                "mac_address": mac,
                "addresses": entries
            }

        return json.dumps({
            "status": "success",
            "interface_count": len(result),
            "interfaces": result
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Network interface discovery failed: {e}"}, indent=2)


def routing_table() -> str:
    """
    Retrieves the system IP routing table entries.
    """
    import subprocess
    routes = []
    try:
        if platform.system().lower() == "windows":
            proc = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=5)
            for line in proc.stdout.split("\n"):
                line = line.strip()
                # Windows route print line
                parts = line.split()
                if len(parts) >= 5 and re.match(r"^\d{1,3}\.", parts[0]):
                    routes.append({
                        "destination": parts[0],
                        "netmask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                        "metric": parts[4]
                    })
        else:
            proc = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
            for line in proc.stdout.split("\n"):
                line = line.strip()
                if line:
                    routes.append({"route": line})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Routing table lookup failed: {e}"}, indent=2)

    return json.dumps({
        "status": "success",
        "route_count": len(routes),
        "routes": routes[:50]
    }, indent=2)


def system_info() -> str:
    """
    Collects operating system, hardware architecture, kernel, and resource information.
    """
    try:
        mem = psutil.virtual_memory()
        uptime_sec = int(time.time() - psutil.boot_time())

        return json.dumps({
            "status": "success",
            "os": platform.system(),
        "system": platform.system(),
        "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "cpu_cores": psutil.cpu_count(logical=True),
            "total_ram_gb": round(mem.total / (1024**3), 2),
            "available_ram_gb": round(mem.available / (1024**3), 2),
            "uptime_seconds": uptime_sec,
            "uptime_hours": round(uptime_sec / 3600, 1)
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Failed to retrieve system info: {e}"}, indent=2)


def environment_info(filter_prefix: Optional[str] = None) -> str:
    """
    Retrieves environment variables with MANDATORY REDACTION of credentials, tokens, and secrets.
    Arguments:
        filter_prefix: Optional variable name prefix to filter by.
    """
    # Strict secret redaction patterns
    secret_patterns = re.compile(
        r"(TOKEN|KEY|SECRET|PASS|PASSWORD|AUTH|CREDENTIAL|PRIVATE|API_KEY|DATABASE_URL|ACCESS_KEY|BEARER)",
        re.IGNORECASE
    )

    clean_env = {}
    prefix = str(filter_prefix or "").upper().strip()

    for k, v in os.environ.items():
        if prefix and not k.upper().startswith(prefix):
            continue

        # Redact any key matching sensitive security patterns
        if secret_patterns.search(k):
            clean_env[k] = "[REDACTED_SECRET]"
        elif any(secret_patterns.search(part) for part in re.split(r"[._-]", k)):
            clean_env[k] = "[REDACTED_SECRET]"
        else:
            clean_env[k] = v[:200]  # Bound string length

    return json.dumps({
        "status": "success",
        "filter_prefix": filter_prefix or "all",
        "variable_count": len(clean_env),
        "variables": clean_env,
        "environment": clean_env
    }, indent=2)


def file_metadata(file_path: str) -> str:
    """
    Inspects file size, timestamps, permissions, and file system metadata.
    Arguments:
        file_path: Absolute or workspace-relative path to the file.
    """
    if not file_path or not str(file_path).strip():
        return json.dumps({"status": "error", "error": "File path parameter is required."})

    target_path = os.path.abspath(str(file_path).strip())
    if not os.path.exists(target_path):
        return json.dumps({"status": "error", "error": f"File '{file_path}' does not exist."})

    try:
        stat = os.stat(target_path)
        is_dir = os.path.isdir(target_path)
        is_file = os.path.isfile(target_path)
        is_symlink = os.path.islink(target_path)

        return json.dumps({
            "status": "success",
            "file_path": target_path,
            "size_bytes": stat.st_size,
            "size_kb": round(stat.st_size / 1024, 2),
            "is_file": is_file,
            "is_directory": is_dir,
            "is_symlink": is_symlink,
            "permissions_octal": oct(stat.st_mode)[-3:],
            "created_time": time.ctime(stat.st_ctime),
            "modified_time": time.ctime(stat.st_mtime),
            "accessed_time": time.ctime(stat.st_atime),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "file_path": file_path, "error": str(e)}, indent=2)


def file_hash(file_path: str = "", path: str = "", algorithms: Optional[List[str]] = None, algorithm: Optional[str] = None) -> str:
    file_path = file_path or path
    if algorithm and not algorithms:
        algorithms = [algorithm]
    """
    Computes cryptographic hashes (MD5, SHA1, SHA256, SHA512) for a local file using safe chunking.
    Arguments:
        file_path: Path to the file.
        algorithms: Optional list of hash algorithms (default: ['sha256', 'md5']).
    """
    if not file_path or not str(file_path).strip():
        return json.dumps({"status": "error", "error": "File path parameter is required."})

    target_path = os.path.abspath(str(file_path).strip())
    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        return json.dumps({"status": "error", "error": f"File '{file_path}' does not exist or is not a file."})

    algos = [str(a).lower() for a in (algorithms or ["sha256", "md5"])]
    hashers = {}
    for a in algos:
        if hasattr(hashlib, a):
            hashers[a] = getattr(hashlib, a)()

    if not hashers:
        hashers["sha256"] = hashlib.sha256()

    try:
        # Read file in 64KB safe chunks to avoid OOM on large files
        with open(target_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)

        results = {k: h.hexdigest() for k, h in hashers.items()}
        return json.dumps({
            "status": "success",
            "file_path": target_path,
            "size_bytes": os.path.getsize(target_path),
            "hashes": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "file_path": file_path, "error": str(e)}, indent=2)


def directory_inventory(path: str = ".", max_depth: int = 2, max_entries: int = 100) -> str:
    """
    Generates a bounded inventory of files and subdirectories with extension statistics.
    Arguments:
        path: Base directory to scan (default '.').
        max_depth: Maximum directory recursion depth (default 2, max 4).
        max_entries: Maximum files/folders to audit (default 100, max 200).
    """
    target = os.path.abspath(str(path or ".").strip())
    if not os.path.exists(target):
        return json.dumps({"status": "error", "error": f"Directory '{path}' does not exist."})

    max_depth = max(1, min(int(max_depth or 2), 4))
    limit = max(1, min(int(max_entries or 100), 200))

    entries = []
    extensions = {}
    total_bytes = 0

    base_depth = target.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(target):
        current_depth = root.count(os.sep) - base_depth
        if current_depth >= max_depth:
            dirs.clear()
            continue

        for f in files:
            fpath = os.path.join(root, f)
            try:
                sz = os.path.getsize(fpath)
                total_bytes += sz
                ext = os.path.splitext(f)[1].lower() or "no_ext"
                extensions[ext] = extensions.get(ext, 0) + 1
                entries.append({
                    "name": f,
                    "rel_path": os.path.relpath(fpath, target),
                    "size_bytes": sz,
                    "type": "file"
                })
                if len(entries) >= limit:
                    break
            except Exception:
                continue
        if len(entries) >= limit:
            break

    return json.dumps({
        "status": "success",
        "base_path": target,
        "entry_count": len(entries),
        "total_bytes": total_bytes,
        "total_kb": round(total_bytes / 1024, 2),
        "extension_distribution": extensions,
        "sample_entries": entries[:25]
    }, indent=2)


def permissions_check(file_path: str) -> str:
    """
    Audits file access rights and checks for unsafe permissions (e.g. world-writable, SUID).
    Arguments:
        file_path: Target path to evaluate.
    """
    if not file_path or not str(file_path).strip():
        return json.dumps({"status": "error", "error": "File path parameter is required."})

    target = os.path.abspath(str(file_path).strip())
    if not os.path.exists(target):
        return json.dumps({"status": "error", "error": f"Path '{file_path}' does not exist."})

    stat = os.stat(target)
    mode = stat.st_mode
    octal = oct(mode)[-3:]

    r_ok = os.access(target, os.R_OK)
    w_ok = os.access(target, os.W_OK)
    x_ok = os.access(target, os.X_OK)

    warnings = []
    # Check world-writable
    if mode & 0o002:
        warnings.append("CRITICAL: File is world-writable (allows any local user to modify)")
    # Check SUID/SGID if on POSIX
    if hasattr(os, "stat"):
        if mode & 0o4000:
            warnings.append("HIGH: SUID bit is set")
        if mode & 0o2000:
            warnings.append("MEDIUM: SGID bit is set")

    return json.dumps({
        "status": "success",
        "path": target,
        "permissions_octal": octal,
        "readable_by_agent": r_ok,
        "writable_by_agent": w_ok,
        "executable_by_agent": x_ok,
        "is_safe": len(warnings) == 0,
        "security_warnings": warnings
    }, indent=2)


def register_host_inspection_tools(registry: ToolRegistry):
    """
    Registers the Host Inspection and Local Security Suite in the authoritative ToolRegistry.
    """
    registry.register(
        name="process_list",
        description="Inspects active processes on the host (PID, name, user, CPU/RAM). Arguments: max_results (int).",
        func=process_list,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="listening_ports",
        description="Audits open listening TCP/UDP sockets and associated process names. Arguments: proto (str).",
        func=listening_ports,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="network_interfaces",
        description="Enumerates host network interfaces, MAC addresses, IPv4/IPv6 addresses, and netmasks.",
        func=network_interfaces,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="routing_table",
        description="Retrieves active host IP routing table (destination, gateway, interface).",
        func=routing_table,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="system_info",
        description="Collects host platform, OS release, architecture, hostname, uptime, CPU count, and RAM.",
        func=system_info,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="environment_info",
        description="Retrieves environment variables with MANDATORY REDACTION of credentials and secrets. Arguments: filter_prefix (str).",
        func=environment_info,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="file_metadata",
        description="Inspects file size, timestamps, permissions octal, and symlink properties. Arguments: file_path (str).",
        func=file_metadata,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="file_hash",
        description="Calculates SHA256 and MD5 cryptographic hashes for a file using safe streaming. Arguments: file_path (str), algorithms (list).",
        func=file_hash,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="directory_inventory",
        description="Generates a bounded inventory of files and extension statistics. Arguments: path (str), max_depth (int), max_entries (int).",
        func=directory_inventory,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="permissions_check",
        description="Audits file/directory access rights and checks for world-writable or SUID vulnerabilities. Arguments: file_path (str).",
        func=permissions_check,
        sandbox_required=False,
        category=ToolCategory.HOST,
        risk_level="LOW",
        read_only=True,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10
    )
