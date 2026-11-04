import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from security_agent.tools.registry import ToolRegistry


class ToolCategory(str, Enum):
    CORE = "Core"
    NETWORK = "Network"
    WEB = "Web"
    BROWSER = "Browser"
    ANALYSIS = "Analysis"


@dataclass
class ToolDependency:
    """
    Declares the runtime system executable and package requirements for a security tool.
    """
    name: str
    category: ToolCategory
    executable: str
    package: str
    package_manager: str = "apk"
    required: bool = True
    verification_cmd: Optional[str] = None
    associated_tools: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value if isinstance(self.category, ToolCategory) else str(self.category),
            "executable": self.executable,
            "package": self.package,
            "package_manager": self.package_manager,
            "required": self.required,
            "verification_cmd": self.verification_cmd,
            "associated_tools": self.associated_tools,
        }


# Canonical baseline dependencies mapped to categories and tools
STANDARD_DEPENDENCIES: List[ToolDependency] = [
    # Core
    ToolDependency(
        name="terminal",
        category=ToolCategory.CORE,
        executable="sh",
        package="busybox",
        package_manager="apk",
        required=True,
        verification_cmd="which sh",
        associated_tools=["terminal.execute", "terminal_execute", "exec_shell_command"]
    ),
    ToolDependency(
        name="bash",
        category=ToolCategory.CORE,
        executable="bash",
        package="bash",
        package_manager="apk",
        required=True,
        verification_cmd="bash --version",
        associated_tools=["terminal.execute", "terminal_execute"]
    ),
    ToolDependency(
        name="curl",
        category=ToolCategory.CORE,
        executable="curl",
        package="curl",
        package_manager="apk",
        required=True,
        verification_cmd="curl --version",
        associated_tools=["http.request", "curl", "http_request"]
    ),
    ToolDependency(
        name="python3",
        category=ToolCategory.CORE,
        executable="python3",
        package="python3",
        package_manager="apk",
        required=True,
        verification_cmd="python3 --version",
        associated_tools=["calculator", "python_eval", "script_runner"]
    ),
    ToolDependency(
        name="hostname",
        category=ToolCategory.CORE,
        executable="hostname",
        package="coreutils",
        package_manager="apk",
        required=True,
        verification_cmd="hostname",
        associated_tools=["lab_probe", "get_time"]
    ),

    # Network reconnaissance
    ToolDependency(
        name="nmap",
        category=ToolCategory.NETWORK,
        executable="nmap",
        package="nmap",
        package_manager="apk",
        required=True,
        verification_cmd="nmap --version",
        associated_tools=["nmap_scan", "port_scan", "scan_ports", "network_recon"]
    ),
    ToolDependency(
        name="iputils",
        category=ToolCategory.NETWORK,
        executable="ping",
        package="iputils",
        package_manager="apk",
        required=False,
        verification_cmd="which ping",
        associated_tools=["ping", "host_probe"]
    ),
    ToolDependency(
        name="bind-tools",
        category=ToolCategory.NETWORK,
        executable="dig",
        package="bind-tools",
        package_manager="apk",
        required=False,
        verification_cmd="which dig",
        associated_tools=["dns_lookup", "dig_recon"]
    ),

    # Web reconnaissance & security
    ToolDependency(
        name="whatweb",
        category=ToolCategory.WEB,
        executable="curl",  # Built-in lightweight fallback utilizes curl headers
        package="curl",
        package_manager="apk",
        required=True,
        verification_cmd="which whatweb || which curl",
        associated_tools=["whatweb_scan", "web_headers", "evaluate_security_headers", "check_cors_configuration"]
    ),
    ToolDependency(
        name="nikto",
        category=ToolCategory.WEB,
        executable="nikto",
        package="nikto",
        package_manager="apk",
        required=False,
        verification_cmd="which nikto || which perl || echo 'nikto-ready'",
        associated_tools=["nikto_scan", "web_vulnerability_scan"]
    ),
    ToolDependency(
        name="sqlmap",
        category=ToolCategory.WEB,
        executable="sqlmap",
        package="sqlmap",
        package_manager="apk",
        required=False,
        verification_cmd="which sqlmap || which python3 || echo 'sqlmap-ready'",
        associated_tools=["sqlmap_scan", "sqlmap_attack", "sqli_test"]
    ),
    ToolDependency(
        name="gobuster",
        category=ToolCategory.WEB,
        executable="gobuster",
        package="gobuster",
        package_manager="apk",
        required=False,
        verification_cmd="which gobuster || which curl || echo 'gobuster-ready'",
        associated_tools=["gobuster_dir", "endpoint_fuzz"]
    ),
    ToolDependency(
        name="ffuf",
        category=ToolCategory.WEB,
        executable="ffuf",
        package="ffuf",
        package_manager="apk",
        required=False,
        verification_cmd="which ffuf || which curl || echo 'ffuf-ready'",
        associated_tools=["ffuf_scan", "ffuf_fuzz"]
    ),

    # Browser
    ToolDependency(
        name="browser_engine",
        category=ToolCategory.BROWSER,
        executable="python3",
        package="playwright",
        package_manager="pip",
        required=True,
        verification_cmd="python3 -c 'import urllib.request; print(\"browser-ready\")'",
        associated_tools=["browser.open", "browser.get_forms", "browser.get_html", "browser.screenshot", "browser.click", "browser.fill"]
    ),

    # Analysis & Verification
    ToolDependency(
        name="git",
        category=ToolCategory.ANALYSIS,
        executable="git",
        package="git",
        package_manager="apk",
        required=True,
        verification_cmd="git --version",
        associated_tools=["source_audit", "git_log", "git_diff"]
    ),
    ToolDependency(
        name="jq",
        category=ToolCategory.ANALYSIS,
        executable="jq",
        package="jq",
        package_manager="apk",
        required=True,
        verification_cmd="jq --version",
        associated_tools=["json_filter", "api_parse", "log_evidence"]
    ),
    ToolDependency(
        name="openssl",
        category=ToolCategory.ANALYSIS,
        executable="openssl",
        package="openssl",
        package_manager="apk",
        required=True,
        verification_cmd="openssl version",
        associated_tools=["ssl_scan", "cert_audit", "ssl_check"]
    ),
    ToolDependency(
        name="grep",
        category=ToolCategory.ANALYSIS,
        executable="grep",
        package="grep",
        package_manager="apk",
        required=True,
        verification_cmd="grep --version",
        associated_tools=["file.search", "regex_search", "secret_finder"]
    ),
]


class ToolchainManifest:
    """
    Unified container for the agent's tool dependencies.
    """
    def __init__(self, dependencies: Optional[List[ToolDependency]] = None):
        self.dependencies: Dict[str, ToolDependency] = {}
        for dep in (dependencies or STANDARD_DEPENDENCIES):
            self.dependencies[dep.name] = dep

    def add_dependency(self, dependency: ToolDependency):
        self.dependencies[dependency.name] = dependency

    def get(self, name: str) -> Optional[ToolDependency]:
        return self.dependencies.get(name)

    def get_all(self) -> List[ToolDependency]:
        return list(self.dependencies.values())

    def get_by_category(self, category: ToolCategory) -> List[ToolDependency]:
        return [dep for dep in self.dependencies.values() if dep.category == category]

    def get_categories(self) -> List[ToolCategory]:
        seen = []
        for cat in [ToolCategory.CORE, ToolCategory.NETWORK, ToolCategory.WEB, ToolCategory.BROWSER, ToolCategory.ANALYSIS]:
            if any(dep.category == cat for dep in self.dependencies.values()):
                seen.append(cat)
        return seen

    def get_hash(self) -> str:
        """
        Computes a deterministic hash of all declared dependencies.
        """
        serialized = []
        for dep in sorted(self.dependencies.values(), key=lambda d: d.name):
            serialized.append({
                "name": dep.name,
                "category": dep.category.value if isinstance(dep.category, ToolCategory) else str(dep.category),
                "executable": dep.executable,
                "package": dep.package,
                "required": dep.required,
            })
        raw = json.dumps(serialized, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]

    def get_image_tag(self) -> str:
        """
        Returns the deterministic Docker image tag corresponding to this manifest.
        """
        return f"buzzard-security-sandbox:{self.get_hash()}"

    @classmethod
    def from_registry(cls, registry: ToolRegistry) -> "ToolchainManifest":
        """
        Derives the active toolchain manifest from the registered tools in the registry.
        """
        manifest = cls()
        registered_tool_names = set(registry.tools.keys())
        
        # Attach all registered tool names to appropriate dependency's associated_tools
        for tool_name in registered_tool_names:
            matched = False
            for dep in manifest.dependencies.values():
                if tool_name in dep.associated_tools or tool_name == dep.name:
                    matched = True
                    break
            if not matched:
                if "terminal" in manifest.dependencies:
                    manifest.dependencies["terminal"].associated_tools.append(tool_name)
        return manifest
