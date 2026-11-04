from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Any, List, Optional, Tuple, Union


class ToolCategory(str, Enum):
    CORE = "Core"
    NETWORK = "network"
    WEB = "web"
    TLS = "tls"
    DNS = "dns"
    RECON = "recon"
    HOST = "host"
    FILE_ANALYSIS = "file_analysis"
    DEFENSIVE_ANALYSIS = "defensive_analysis"
    AUTOMATION = "automation"
    BROWSER = "Browser"
    ANALYSIS = "Analysis"
    EVIDENCE = "Evidence"
    UTILITY = "Utility"
    EXPLOIT = "Exploit"
    WIRELESS = "Wireless"
    CRYPTO = "Crypto"
    FUZZ = "Fuzz"
    CLOUD = "Cloud"
    FORENSICS = "Forensics"

class ToolHealthState(str, Enum):
    HEALTHY = "healthy"
    QUARANTINED = "quarantined"
    UNAVAILABLE = "unavailable"


@dataclass
class ToolDefinition:
    """
    Authoritative metadata and execution contract for a security tool.
    """
    name: str
    description: str
    handler: Callable
    schema: Optional[Dict[str, Any]] = None
    dependencies: List[str] = field(default_factory=list)
    python_dependencies: List[str] = field(default_factory=list)
    sandbox_required: bool = True
    smoke_test: Optional[Callable] = None
    category: ToolCategory = ToolCategory.UTILITY
    required: bool = False
    health_state: ToolHealthState = ToolHealthState.HEALTHY
    quarantine_reason: Optional[str] = None
    quarantine_details: Optional[Dict[str, Any]] = None
    risk_level: str = "LOW"
    read_only: bool = True
    destructive: bool = False
    network_required: bool = False
    scope_required: bool = True
    approval_required: bool = False
    timeout: int = 30
    provider: str = "local"
    resource_limits: Optional[Dict[str, Any]] = None
    return_schema: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value if isinstance(self.category, ToolCategory) else str(self.category),
            "dependencies": self.dependencies,
            "python_dependencies": self.python_dependencies,
            "sandbox_required": self.sandbox_required,
            "required": self.required,
            "health_state": self.health_state.value if isinstance(self.health_state, ToolHealthState) else str(self.health_state),
            "quarantine_reason": self.quarantine_reason,
            "quarantine_details": self.quarantine_details,
            "risk_level": self.risk_level,
            "read_only": self.read_only,
            "destructive": self.destructive,
            "network_required": self.network_required,
            "scope_required": self.scope_required,
            "approval_required": self.approval_required,
            "timeout": self.timeout,
            "provider": self.provider,
            "resource_limits": self.resource_limits or {},
            "return_schema": self.return_schema or {},
        }

class Tool:
    """
    Represents an executable registered tool.
    """
    def __init__(
        self,
        name: str,
        description: str,
        func: Callable,
        definition: Optional[ToolDefinition] = None
    ):
        self.name = name
        self.description = description
        self.func = func
        self.signature = inspect.signature(func)
        self.definition = definition or ToolDefinition(
            name=name,
            description=description,
            handler=func
        )

    def execute(self, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
        """
        Executes the tool function with the provided arguments,
        handling signature matching, type coercion, alias mapping, and returning string output.
        """
        try:
            full_args = arguments.copy() if isinstance(arguments, dict) else {}
            if context:
                for k, v in context.items():
                    if k in self.signature.parameters:
                        full_args[k] = v

            sig_params = self.signature.parameters
            has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig_params.values())
            
            prepared_args = {}
            alias_map = {
                "url": ["target", "uri", "address", "endpoint"],
                "host": ["target", "ip", "hostname", "address"],
                "command": ["cmd", "exec", "script"],
                "ports": ["port", "port_range"],
                "selector": ["query", "css", "target"],
                "file_path": ["path", "filepath", "filename"],
                "content": ["data", "text", "body"],
                "summary": ["description", "reason", "notes", "report"]
            }

            for name, param in sig_params.items():
                if name in full_args:
                    val = full_args[name]
                    # Sanitize None / "None" / "null"
                    if val in ("None", "null", "undefined"):
                        val = None if param.default != inspect.Parameter.empty else ""
                    
                    # Safe type conversions
                    if param.annotation is int and isinstance(val, str):
                        try:
                            val = int(val.strip())
                        except Exception:
                            pass
                    elif param.annotation is float and isinstance(val, str):
                        try:
                            val = float(val.strip())
                        except Exception:
                            pass
                    elif param.annotation is bool and isinstance(val, str):
                        val = val.strip().lower() in ("true", "1", "yes")

                    prepared_args[name] = val
                elif param.default != inspect.Parameter.empty:
                    prepared_args[name] = param.default
                else:
                    # Check aliases for missing required argument
                    found_alias = False
                    for alias in alias_map.get(name, []):
                        if alias in full_args:
                            prepared_args[name] = full_args[alias]
                            found_alias = True
                            break
                    if not found_alias:
                        # Provide default empty string/dict for required parameter
                        if param.annotation is dict or param.annotation is Dict:
                            prepared_args[name] = {}
                        elif param.annotation is list or param.annotation is List:
                            prepared_args[name] = []
                        else:
                            prepared_args[name] = ""

            if has_var_kw:
                for k, v in full_args.items():
                    if k not in prepared_args:
                        prepared_args[k] = v

            # Execute function
            result = self.func(**prepared_args)
            return str(result)
        except Exception as e:
            return f"TOOL ERROR: Failed to execute {self.name}: {e}"

    def get_description(self) -> str:
        """
        Formats a user-friendly description of the tool name, signature, and purpose.
        """
        params = []
        for name, param in self.signature.parameters.items():
            # Skip parameters that are part of context to keep description clean for LLM
            if name in ["session_id", "storage_manager", "sandbox", "context", "knowledge", "selector"]:
                continue
            param_str = name
            if param.default != inspect.Parameter.empty:
                param_str += f"={param.default}"
            params.append(param_str)
            
        args_str = ", ".join(params)
        return f"- {self.name}({args_str}): {self.description}"

    def get_schema(self) -> Dict[str, Any]:
        """
        Generates Ollama/OpenAI-compatible tool schema for function calling.
        """
        if self.definition and self.definition.schema:
            return self.definition.schema

        properties = {}
        required = []
        docstring = self.func.__doc__ or ""
        
        for name, param in self.signature.parameters.items():
            # Skip context parameters
            if name in ["session_id", "storage_manager", "sandbox", "context", "knowledge", "selector"]:
                continue
                
            # Determine type
            param_type = "string"
            if param.annotation != inspect.Parameter.empty:
                ann = param.annotation
                # Handle typing.Optional / typing.Union
                if hasattr(ann, "__origin__") and ann.__origin__ is Union:
                    args = ann.__args__
                    non_none_args = [a for a in args if a is not type(None)]
                    if non_none_args:
                        ann = non_none_args[0]
                
                if ann is int:
                    param_type = "integer"
                elif ann is float:
                    param_type = "number"
                elif ann is bool:
                    param_type = "boolean"
                elif ann is dict or ann is Dict:
                    param_type = "object"
                elif ann is list or ann is List:
                    param_type = "array"
            else:
                if param.default != inspect.Parameter.empty and param.default is not None:
                    def_val = param.default
                    if isinstance(def_val, bool):
                        param_type = "boolean"
                    elif isinstance(def_val, int):
                        param_type = "integer"
                    elif isinstance(def_val, float):
                        param_type = "number"
                    elif isinstance(def_val, dict):
                        param_type = "object"
                    elif isinstance(def_val, list):
                        param_type = "array"

            # Parse parameter description from docstring
            description = f"The {name} parameter."
            lines = docstring.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith(f"{name}:") or line.startswith(f"{name} "):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        description = parts[1].strip()
                        break

            properties[name] = {
                "type": param_type,
                "description": description
            }
            
            # If parameter has no default value, it is required
            if param.default == inspect.Parameter.empty:
                required.append(name)
                
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        }

    def export_schema(self) -> Dict[str, Any]:
        return self.get_schema()


class ToolRegistry:
    """
    Authoritative single registry container for all Buzzard Code capabilities.
    """
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self.definitions: Dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        func: Callable,
        category: ToolCategory = ToolCategory.UTILITY,
        dependencies: Optional[List[str]] = None,
        python_dependencies: Optional[List[str]] = None,
        sandbox_required: bool = False,
        required: bool = False,
        smoke_test: Optional[Callable] = None,
        risk_level: str = "LOW",
        read_only: bool = True,
        destructive: bool = False,
        network_required: bool = False,
        scope_required: bool = True,
        approval_required: bool = False,
        timeout: int = 30,
        provider: str = "local",
        resource_limits: Optional[Dict[str, Any]] = None,
        schema: Optional[Dict[str, Any]] = None,
        return_schema: Optional[Dict[str, Any]] = None
    ):
        """
        Registers a function as a tool and creates its ToolDefinition contract.
        """
        defn = ToolDefinition(
            name=name,
            description=description,
            handler=func,
            category=category,
            dependencies=dependencies or [],
            python_dependencies=python_dependencies or [],
            sandbox_required=sandbox_required,
            required=required,
            smoke_test=smoke_test,
            health_state=ToolHealthState.HEALTHY,
            risk_level=risk_level,
            read_only=read_only,
            destructive=destructive,
            network_required=network_required,
            scope_required=scope_required,
            approval_required=approval_required,
            timeout=timeout,
            provider=provider,
            resource_limits=resource_limits or {},
            schema=schema,
            return_schema=return_schema or {}
        )
        self.register_definition(defn)
    def register_definition(self, definition: ToolDefinition):
        """
        Registers a complete ToolDefinition.
        """
        self.definitions[definition.name] = definition
        self.tools[definition.name] = Tool(
            name=definition.name,
            description=definition.description,
            func=definition.handler,
            definition=definition
        )

    TOOL_ALIASES = {
        # Execution & terminal
        "exec_shell_command": "terminal_execute",
        "execute_shell_command": "terminal_execute",
        "exec_command": "terminal_execute",
        "execute_command": "terminal_execute",
        "bash": "terminal_execute",
        "exec_bash": "terminal_execute",
        "terminal.execute": "terminal_execute",
        "terminal": "terminal_execute",
        "run_command": "terminal_execute",

        # Automation & Filesystem
        "file.read": "file_read",
        "read_file": "file_read",
        "file.write": "file_write",
        "write_file": "file_write",
        "file.search": "file_search",
        "search_file": "file_search",
        "file.list": "directory_list",
        "file_list": "directory_list",
        "list_files": "directory_list",

        # Web & HTTP
        "http.request": "http_request",
        "request": "http_request",
        "curl": "http_request",
        "curl_request": "http.request",
        "http_get": "http_request",
        "headers": "check_headers",
        "evaluate_security_headers": "check_headers",
        "cors": "cors_check",
        "check_cors_configuration": "cors_check",
        "web_probe": "http_probe",
        "web_tech_detect": "tech_fingerprint",

        # Network & DNS
        "ping": "ping_host",
        "dns_query": "dns_records",
        "dns_reverse_lookup": "reverse_dns",
        "dns_enum": "subdomain_enum",
        "port_scan": "scan_ports",
        "service_fingerprint": "service_detect",
        "service_inventory": "service_detect",

        # File & Static analysis

        # Browser
        "get_forms": "browser.get_forms",
        "get_html": "browser.get_html",
        "open_browser": "browser.open",
        "open_url": "browser.open",
        "browser_open": "browser.open",
        "browser_get_forms": "browser.get_forms",
        "browser_get_html": "browser.get_html",

        # Evidence & Assessment
        "sqlmap_scan": "sqli_scan",
        "record_finding": "log_finding",
        "capture_evidence": "log_evidence",
        "complete_assessment": "complete",
    }

    def execute(self, name: str, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
        """
        Finds and executes a tool by name, checking health and aliases.
        """
        if name in self.tools:
            canonical_name = name
        elif name in self.TOOL_ALIASES and self.TOOL_ALIASES[name] in self.tools:
            canonical_name = self.TOOL_ALIASES[name]
        else:
            canonical_name = name
            # Match stripped dots / underscores
            for reg_name in self.tools:
                if reg_name.replace(".", "_") == name.replace(".", "_"):
                    canonical_name = reg_name
                    break
            if canonical_name not in self.tools:
                return f"TOOL ERROR: Unknown tool: {name}"

        # Check health
        defn = self.definitions.get(canonical_name)
        if defn and defn.health_state == ToolHealthState.QUARANTINED:
            return (
                f"ACTION REJECTED: Tool '{canonical_name}' is QUARANTINED.\n"
                f"Reason: {defn.quarantine_reason or 'Missing runtime dependency'}\n"
                f"Guidance: Select an alternative healthy tool."
            )

        # Enforce sandbox invariant: sandbox-required tools MUST NOT execute natively when sandbox is unavailable
        if defn and defn.sandbox_required:
            from security_agent.sandbox.container import is_docker_active
            sb = context.get("sandbox") if context else None
            is_blocked = False
            if sb is not None:
                if getattr(sb, "blocked", False) or type(sb).__name__ == "BlockedSandbox" or not getattr(sb, "sandboxed", True):
                    is_blocked = True
            elif not is_docker_active():
                is_blocked = True

            if is_blocked:
                return (
                    f"Stderr: SECURITY STOP: Sandbox unavailable — execution disabled. (Docker daemon is unreachable or sandbox image is missing)\n\n"
                    f"Exit code: 126\n\n"
                    f"Status: FAILED (execution_blocked)"
                )

        return self.tools[canonical_name].execute(arguments, context)

    def quarantine_tool(self, name: str, reason: str, details: Optional[Dict[str, Any]] = None) -> Optional[ToolDefinition]:
        """
        Quarantines a broken tool due to missing runtime dependency or severe failure.
        Immediately excludes it from active and model-visible tool sets.
        """
        canonical_name = self.TOOL_ALIASES.get(name, name)
        defn = None
        if canonical_name in self.definitions:
            defn = self.definitions[canonical_name]
            defn.health_state = ToolHealthState.QUARANTINED
            defn.quarantine_reason = reason
            defn.quarantine_details = details or {}
        if canonical_name in self.tools and self.tools[canonical_name].definition:
            self.tools[canonical_name].definition.health_state = ToolHealthState.QUARANTINED
            self.tools[canonical_name].definition.quarantine_reason = reason
            self.tools[canonical_name].definition.quarantine_details = details or {}
        return defn

    def unquarantine_tool(self, name: str) -> Optional[ToolDefinition]:
        """
        Restores a tool to healthy state.
        """
        canonical_name = self.TOOL_ALIASES.get(name, name)
        defn = None
        if canonical_name in self.definitions:
            defn = self.definitions[canonical_name]
            defn.health_state = ToolHealthState.HEALTHY
            defn.quarantine_reason = None
            defn.quarantine_details = None
        if canonical_name in self.tools and self.tools[canonical_name].definition:
            self.tools[canonical_name].definition.health_state = ToolHealthState.HEALTHY
            self.tools[canonical_name].definition.quarantine_reason = None
            self.tools[canonical_name].definition.quarantine_details = None
        return defn

    def get_active_tools(self) -> Dict[str, Tool]:
        """
        Returns all healthy (non-quarantined) tools.
        """
        return {
            name: tool for name, tool in self.tools.items()
            if self.definitions.get(name, tool.definition).health_state == ToolHealthState.HEALTHY
        }

    def get_model_visible_tools(self) -> List[str]:
        """
        Returns list of healthy tool names that should be exposed to LLM.
        """
        return list(self.get_active_tools().keys())

    def get_quarantined_tools(self) -> Dict[str, ToolDefinition]:
        """
        Returns dict of quarantined tool definitions.
        """
        return {
            name: defn for name, defn in self.definitions.items()
            if defn.health_state == ToolHealthState.QUARANTINED
        }

    def export_schemas(self, model_visible_only: bool = True, only: Optional[frozenset] = None) -> List[Dict[str, Any]]:
        """
        Exports tool schemas for model calling. Only exposes healthy tools by default,
        optionally limited to the names in `only`.
        """
        target_tools = self.get_active_tools() if model_visible_only else self.tools
        if only is not None:
            target_tools = {name: tool for name, tool in target_tools.items() if name in only}
        return [tool.get_schema() for tool in target_tools.values()]

    def get_tools_description(self, model_visible_only: bool = True, only: Optional[frozenset] = None) -> str:
        """
        Returns formatted descriptions of available tools, optionally limited to the names in `only`.
        """
        target_tools = self.get_active_tools() if model_visible_only else self.tools
        if only is not None:
            target_tools = {name: tool for name, tool in target_tools.items() if name in only}
        if not target_tools:
            return "No tools available."
        return "\n".join(tool.get_description() for tool in target_tools.values())

    def get_inventory(self) -> Dict[str, List[ToolDefinition]]:
        """
        Groups all registered tool definitions by category.
        """
        grouped: Dict[str, List[ToolDefinition]] = {}
        for defn in self.definitions.values():
            cat = defn.category.value if isinstance(defn.category, ToolCategory) else str(defn.category)
            grouped.setdefault(cat.upper(), []).append(defn)
        return grouped

    def get_inventory_text(self) -> str:
        """
        Formats dynamic inventory output conforming to Requirement 1.
        """
        inventory = self.get_inventory()
        total = len(self.definitions)
        healthy = len(self.get_active_tools())
        quarantined = len(self.get_quarantined_tools())

        lines = [
            "BUZZARD TOOL INVENTORY",
            f"Registered tools: {total} (Healthy: {healthy}, Quarantined: {quarantined})",
            ""
        ]

        for cat, tools in sorted(inventory.items()):
            lines.append(cat)
            for t in sorted(tools, key=lambda x: x.name):
                status_suffix = " [QUARANTINED]" if t.health_state == ToolHealthState.QUARANTINED else ""
                lines.append(f"  {t.name}{status_suffix} - {t.description[:60]}...")
            lines.append("")

        return "\n".join(lines).strip()

    def validate_counts(self) -> Tuple[bool, Dict[str, int]]:
        """
        Enforces count integrity (Requirement 4):
        REGISTERED_TOOLS == TOOLCHECK_TOOLS == ACTIVE_TOOLS == MODEL_VISIBLE_TOOLS == DISPATCHABLE_TOOLS
        """
        registered = len(self.definitions)
        active = len(self.get_active_tools())
        model_visible = len(self.get_model_visible_tools())
        dispatchable = len(self.tools)
        quarantined = len(self.get_quarantined_tools())

        # If there are no quarantined tools, registered == active == model_visible == dispatchable
        is_consistent = (active == model_visible) and (registered == active + quarantined)
        counts = {
            "registered": registered,
            "active": active,
            "model_visible": model_visible,
            "dispatchable": dispatchable,
            "quarantined": quarantined
        }
        return is_consistent, counts


def create_authoritative_registry(categories: Optional[List[str]] = None) -> ToolRegistry:
    """
    Builds the single authoritative ToolRegistry populated with every capability.
    Discovers all 140 tools with category annotations, dependency tags, and health status.
    """
    registry = ToolRegistry()

    # 1. Basic & Utility tools
    from security_agent.tools.basic import register_basic_tools
    register_basic_tools(registry)

    # 2. Security & Attack execution tools
    from security_agent.tools.security import register_security_tools
    register_security_tools(registry)

    # 2b. Canonical Production Tool Suites
    from security_agent.tools.network_discovery import register_network_discovery_tools
    from security_agent.tools.web_security import register_web_security_tools
    from security_agent.tools.tls_security import register_tls_security_tools
    from security_agent.tools.dns_security import register_dns_security_tools
    from security_agent.tools.recon_osint import register_recon_osint_tools
    from security_agent.tools.host_inspection import register_host_inspection_tools
    from security_agent.tools.file_malware import register_file_malware_tools
    from security_agent.tools.defensive_analysis import register_defensive_analysis_tools

    register_network_discovery_tools(registry)
    register_web_security_tools(registry)
    register_tls_security_tools(registry)
    register_dns_security_tools(registry)
    register_recon_osint_tools(registry)
    register_host_inspection_tools(registry)
    register_file_malware_tools(registry)
    register_defensive_analysis_tools(registry)

    # 3. Dedicated attack tools
    from security_agent.tools.attack import register_attack_tools
    register_attack_tools(registry)

    # 4. HTTP & Web Suite
    from security_agent.tools.http import register_http_tools
    from security_agent.tools.http_suite import register_http_suite_tools
    register_http_tools(registry)
    register_http_suite_tools(registry)

    # 5. Filesystem tools
    from security_agent.tools.filesystem import register_filesystem_tools
    from security_agent.tools.git_tools import register_git_tools
    register_filesystem_tools(registry)
    register_git_tools(registry)

    # 6. Source Audit & SAST tools
    from security_agent.tools.source_audit import register_source_audit_tools
    register_source_audit_tools(registry)

    # 7. Manifest suite
    from security_agent.tools.manifest_suite import register_manifest_tools
    register_manifest_tools(registry)

    # Re-register file_malware to ensure native pure-Python tools override binary wrappers
    from security_agent.tools.file_malware import register_file_malware_tools
    register_file_malware_tools(registry)

    # 8. Browser tools
    from security_agent.tools.browser import register_browser_tools
    register_browser_tools(registry)

    # 9. Evidence & Knowledge tools
    from security_agent.tools.evidence import register_evidence_tools
    from security_agent.tools.knowledge import register_knowledge_tools
    register_evidence_tools(registry)
    register_knowledge_tools(registry)

    # 10. Arsenal offensive capabilities
    from security_agent.tools.arsenal import register_arsenal_tools
    register_arsenal_tools(registry, categories=categories)

    # Enrich metadata, categories, and dependencies on registered definitions
    cat_map = {
        # Core
        "terminal.execute": (ToolCategory.CORE, ["bash", "sh"], True),
        "terminal_execute": (ToolCategory.CORE, ["bash", "sh"], True),
        "python_executor": (ToolCategory.CORE, ["python3"], True),
        "lab_echo": (ToolCategory.CORE, [], False),
        "lab_probe": (ToolCategory.CORE, ["hostname"], True),
        
        # Network
        "nmap_scan": (ToolCategory.NETWORK, ["nmap"], True),
        "scan_ports": (ToolCategory.NETWORK, [], False),
        "port_scan": (ToolCategory.NETWORK, [], False),
        "ping_host": (ToolCategory.NETWORK, [], False),
        "ping": (ToolCategory.NETWORK, [], False),
        "grab_banner": (ToolCategory.NETWORK, [], False),
        "service_fingerprint": (ToolCategory.NETWORK, ["nc"], True),
        "os_fingerprint": (ToolCategory.NETWORK, ["ping"], True),
        "dns_lookup": (ToolCategory.NETWORK, [], False),
        "dns_query": (ToolCategory.NETWORK, [], False),
        "dns_reverse_lookup": (ToolCategory.NETWORK, [], False),
        "dns_enum": (ToolCategory.NETWORK, ["nslookup", "dig"], True),
        "subdomain_enum": (ToolCategory.RECON, [], False),
        "whois_lookup": (ToolCategory.RECON, [], False),
        "service_inventory": (ToolCategory.NETWORK, ["nc"], True),
        "tcp_connectivity_check": (ToolCategory.NETWORK, ["nc"], True),

        # Web
        "http.request": (ToolCategory.WEB, ["curl"], False),
        "web_fetch": (ToolCategory.WEB, ["curl"], False),
        "web_tech_detect": (ToolCategory.WEB, ["curl"], False),
        "whatweb_scan": (ToolCategory.WEB, ["whatweb", "curl"], True),
        "nikto_scan": (ToolCategory.WEB, ["nikto", "curl"], True),
        "gobuster_dir": (ToolCategory.WEB, ["gobuster"], True),
        "nuclei_scan": (ToolCategory.WEB, ["nuclei", "curl"], True),
        "brute_force_http": (ToolCategory.WEB, ["ffuf"], True),
        "http_login_brute": (ToolCategory.WEB, ["ffuf"], True),
        "check_headers": (ToolCategory.WEB, ["curl"], False),
        "ssl_check": (ToolCategory.WEB, ["openssl"], False),
        "check_cors_configuration": (ToolCategory.WEB, ["curl"], False),
        "evaluate_security_headers": (ToolCategory.WEB, ["curl"], False),
        "probe_parameter_injection": (ToolCategory.WEB, ["curl"], False),
        "dir_bruteforce": (ToolCategory.WEB, ["gobuster", "ffuf"], True),
        "api_discovery": (ToolCategory.WEB, ["curl"], True),
        "ssrf_scan": (ToolCategory.WEB, ["curl"], True),
        "lfi_scan": (ToolCategory.WEB, ["curl"], True),
        "sqli_scan": (ToolCategory.WEB, ["sqlmap", "curl"], True),
        "xss_scan": (ToolCategory.WEB, ["curl"], True),
        "cmd_injection_scan": (ToolCategory.WEB, ["curl"], True),
        "vuln_scan": (ToolCategory.WEB, ["nikto", "nuclei"], True),
        "http_method_map": (ToolCategory.WEB, ["curl"], True),

        # Fuzz
        "ffuf_fuzz": (ToolCategory.FUZZ, ["ffuf"], True),
        "endpoint_fuzz": (ToolCategory.FUZZ, ["curl", "ffuf"], True),
        "fuzz_target": (ToolCategory.FUZZ, ["curl", "ffuf"], True),
        "fuzz_url": (ToolCategory.FUZZ, ["curl", "ffuf"], True),
        "fuzz_cases": (ToolCategory.FUZZ, ["ffuf"], True),

        # Exploit & Attacks
        "sqlmap_attack": (ToolCategory.EXPLOIT, ["sqlmap"], True),
        "exploit_search": (ToolCategory.EXPLOIT, ["searchsploit"], True),
        "payload_generate": (ToolCategory.EXPLOIT, ["msfvenom"], True),
        "reverse_shell_payload": (ToolCategory.EXPLOIT, [], False),
        "ssh_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "ftp_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "smtp_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "pop3_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "imap_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "telnet_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "generic_service_brute": (ToolCategory.EXPLOIT, ["hydra", "medusa"], True),
        "syn_flood": (ToolCategory.EXPLOIT, ["hping3"], True),
        "tcp_stress": (ToolCategory.EXPLOIT, ["hping3"], True),
        "udp_stress": (ToolCategory.EXPLOIT, ["hping3"], True),
        "http_stress": (ToolCategory.EXPLOIT, ["ab", "curl"], True),
        "slowloris": (ToolCategory.EXPLOIT, ["slowloris", "python3"], True),

        # Wireless
        "wifi_scan": (ToolCategory.WIRELESS, ["iwlist", "airodump-ng"], True),
        "wifi_monitor_start": (ToolCategory.WIRELESS, ["airmon-ng"], True),
        "wifi_capture": (ToolCategory.WIRELESS, ["airodump-ng"], True),
        "wifi_deauth": (ToolCategory.WIRELESS, ["aireplay-ng"], True),
        "wifi_crack_handshake": (ToolCategory.WIRELESS, ["aircrack-ng"], True),
        "wifi_recover": (ToolCategory.WIRELESS, ["aircrack-ng"], True),

        # Crypto & Crack
        "crack_hash": (ToolCategory.CRYPTO, ["hashcat", "john"], True),
        "crack_zip": (ToolCategory.CRYPTO, ["fcrackzip", "john"], True),
        "crack_file": (ToolCategory.CRYPTO, ["john", "hashcat"], True),
        "wordlist_gen": (ToolCategory.CRYPTO, ["crunch"], True),
        "hash_identify": (ToolCategory.CRYPTO, ["hashid"], True),
        "hash_generate": (ToolCategory.CRYPTO, [], False),
        "jwt_decode": (ToolCategory.CRYPTO, [], False),
        "jwt_crack": (ToolCategory.CRYPTO, ["jwt-tool", "hashcat"], True),
        "crypto_analyze": (ToolCategory.CRYPTO, [], True),
        "decode_obfuscation": (ToolCategory.CRYPTO, [], False),

        # Analysis & Forensics
        "web_search": (ToolCategory.ANALYSIS, [], False),
        "file_identify": (ToolCategory.ANALYSIS, ["file"], True),
        "file_metadata": (ToolCategory.ANALYSIS, [], False),
        "strings_extract": (ToolCategory.FILE_ANALYSIS, [], False),
        "static_analysis": (ToolCategory.ANALYSIS, [], False),
        "binary_analyze": (ToolCategory.ANALYSIS, ["objdump", "readelf"], True),
        "binary_checksec": (ToolCategory.ANALYSIS, ["checksec"], True),
        "pwn_check": (ToolCategory.ANALYSIS, ["gdb", "objdump"], True),
        "stego_check": (ToolCategory.FORENSICS, ["steghide", "binwalk"], True),
        "stego_extract": (ToolCategory.FORENSICS, ["steghide", "binwalk"], True),
        "forensics_analyze": (ToolCategory.FORENSICS, ["foremost", "binwalk"], True),
        "scan_source_secrets": (ToolCategory.ANALYSIS, [], False),
        "secret_scan": (ToolCategory.ANALYSIS, [], False),
        "audit_configurations": (ToolCategory.ANALYSIS, [], False),
        "audit_mobile_storage": (ToolCategory.ANALYSIS, [], False),
        "audit_android_manifest": (ToolCategory.ANALYSIS, [], False),
        "audit_api_spec": (ToolCategory.ANALYSIS, [], False),
        "openapi_parse": (ToolCategory.ANALYSIS, [], False),
        "graphql_introspect": (ToolCategory.WEB, ["curl"], False),
        "cloud_scan": (ToolCategory.CLOUD, [], False),
        "cloud_iam": (ToolCategory.CLOUD, [], False),
        "iac_scan": (ToolCategory.CLOUD, [], False),
        "k8s_scan": (ToolCategory.CLOUD, [], False),
        "cve_scan": (ToolCategory.ANALYSIS, [], False),
        "code_audit": (ToolCategory.ANALYSIS, [], False),
        "edit_file": (ToolCategory.ANALYSIS, [], False),
        "glob": (ToolCategory.ANALYSIS, [], False),
        "grep": (ToolCategory.ANALYSIS, ["grep"], False),
        "file.read": (ToolCategory.ANALYSIS, [], False),
        "file.write": (ToolCategory.ANALYSIS, [], False),
        "file.list": (ToolCategory.ANALYSIS, [], False),
        "file.search": (ToolCategory.ANALYSIS, [], False),

        # Evidence & Utility
        "log_finding": (ToolCategory.EVIDENCE, [], False),
        "log_evidence": (ToolCategory.EVIDENCE, [], False),
        "record_command": (ToolCategory.EVIDENCE, [], False),
        "save_artifact": (ToolCategory.EVIDENCE, [], False),
        "create_report": (ToolCategory.EVIDENCE, [], False),
        "knowledge_add": (ToolCategory.EVIDENCE, [], False),
        "knowledge_dump": (ToolCategory.EVIDENCE, [], False),
        "select_next": (ToolCategory.EVIDENCE, [], False),
        "get_time": (ToolCategory.UTILITY, [], False),
        "calculator": (ToolCategory.UTILITY, [], False),
        "finish_task": (ToolCategory.UTILITY, [], False),
        "complete": (ToolCategory.UTILITY, [], False),
    }

    # Browser tools
    for b_tool in [
        "browser.open", "browser.goto", "browser.click", "browser.fill",
        "browser.press", "browser.screenshot", "browser.get_html",
        "browser.get_text", "browser.get_forms", "browser.get_links",
        "browser.get_url", "browser.back", "browser.close"
    ]:
        cat_map[b_tool] = (ToolCategory.BROWSER, ["chromium", "playwright"], False)

    for name, defn in registry.definitions.items():
        if name in cat_map:
            cat, deps, sb_req = cat_map[name]
            defn.category = cat
            defn.dependencies = deps
            defn.sandbox_required = sb_req

    # Security classification and approval requirements
    high_critical_tools = {
        "terminal.execute": ("HIGH", True),
        "terminal_execute": ("HIGH", True),
        "python_executor": ("HIGH", True),
        "nmap_scan": ("HIGH", True),
        "sqlmap_attack": ("CRITICAL", True),
        "syn_flood": ("CRITICAL", True),
        "tcp_stress": ("CRITICAL", True),
        "udp_stress": ("CRITICAL", True),
        "http_stress": ("CRITICAL", True),
        "slowloris": ("CRITICAL", True),
        "wifi_deauth": ("HIGH", True),
        "wifi_crack_handshake": ("HIGH", True),
        "ssh_brute": ("HIGH", True),
        "ftp_brute": ("HIGH", True),
        "smtp_brute": ("HIGH", True),
        "payload_generate": ("HIGH", True),
        "reverse_shell_payload": ("HIGH", True),
        "scan_ports": ("MEDIUM", False),
        "scan_common_ports": ("MEDIUM", False),
        "subnet_discovery": ("MEDIUM", False),
        "directory_probe": ("MEDIUM", False),
        "web_endpoint_probe": ("MEDIUM", False),
        "zone_transfer_check": ("MEDIUM", False),
        "file_write": ("MEDIUM", False),
    }

    for t_name, (r_level, app_req) in high_critical_tools.items():
        if t_name in registry.definitions:
            registry.definitions[t_name].risk_level = r_level
            registry.definitions[t_name].approval_required = app_req

    return registry
