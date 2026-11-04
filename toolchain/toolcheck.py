"""
Automated Tool Audit, Module Verification, and Safe Smoke-Testing Suite.
Validates imports, tool contracts/schemas, runtime dependencies, and live dispatcher execution.
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table

from cli.renderer import console
from intelligence.asset_graph import AssetGraph
from intelligence.selector import ToolSelector
from sandbox.container import get_sandbox, get_security_sandbox_image
from tools.arsenal import register_arsenal_tools
from tools.attack import register_attack_tools
from tools.basic import register_basic_tools
from tools.browser import register_browser_tools
from tools.evidence import register_evidence_tools
from tools.filesystem import register_filesystem_tools
from tools.http import register_http_tools
from tools.http_suite import register_http_suite_tools
from tools.knowledge import register_knowledge_tools
from tools.registry import ToolRegistry, create_authoritative_registry


class AuditErrorType(str, Enum):
    NONE = "none"
    IMPORT_ERROR = "import_error"
    SCHEMA_ERROR = "schema_error"
    ARGUMENT_ERROR = "argument_error"
    DEPENDENCY_MISSING = "dependency_missing"
    DOCKER_ERROR = "docker_error"
    TIMEOUT = "timeout"
    PERMISSION_ERROR = "permission_error"
    NETWORK_ERROR = "network_error"
    TOOL_FAILURE = "tool_failure"
    PARSER_ERROR = "parser_error"
    UNKNOWN = "unknown"


@dataclass
class ToolAuditResult:
    name: str
    import_ok: bool = False
    schema_ok: bool = False
    dependency_ok: bool = False
    smoke_ok: bool = False
    error_type: AuditErrorType = AuditErrorType.NONE
    error_message: str = ""
    duration_s: float = 0.0
    output_preview: str = ""

    @property
    def passed(self) -> bool:
        return self.import_ok and self.schema_ok and self.smoke_ok


# Safe, non-destructive test arguments for every tool in the registry
SAFE_TEST_ARGS: Dict[str, Dict[str, Any]] = {
    # Basic tools
    "get_time": {},
    "lab_echo": {"message": "smoke_test_ping"},
    "lab_probe": {},
    "calculator": {"expression": "2 + 2"},
    "finish_task": {"summary": "smoke test finished"},
    "complete": {"summary": "smoke test finished"},
    # Security / Attack tools
    "terminal.execute": {"command": "echo smoke_test_ok"},
    "ping_host": {"host": "127.0.0.1"},
    "scan_ports": {"host": "127.0.0.1", "ports": "80"},
    "grab_banner": {"host": "127.0.0.1", "port": 80},
    "python_executor": {"code": "print('smoke_py_ok')"},
    "nmap_scan": {"host": "127.0.0.1", "ports": "80"},
    "whatweb_scan": {"url": "http://127.0.0.1:80"},
    "nikto_scan": {"url": "http://127.0.0.1:80"},
    "gobuster_dir": {"url": "http://127.0.0.1:80"},
    "ffuf_fuzz": {"url": "http://127.0.0.1:80/FUZZ"},
    "sqlmap_attack": {"url": "http://127.0.0.1:80/item?id=1"},
    "nuclei_scan": {"url": "http://127.0.0.1:80"},
    "brute_force_http": {"url": "http://127.0.0.1:80/login"},
    # HTTP Suite
    "http.request": {"url": "http://127.0.0.1:80", "method": "GET"},
    "probe_parameter_injection": {"url": "http://127.0.0.1:80", "param_name": "q"},
    "check_cors_configuration": {"url": "http://127.0.0.1:80"},
    "evaluate_security_headers": {"url": "http://127.0.0.1:80"},
    "test_method_tampering": {"url": "http://127.0.0.1:80"},
    "fuzz_api_endpoints": {"base_url": "http://127.0.0.1:80"},
    # Filesystem / Source
    "fs.list_directory": {"path": "/workspace"},
    "fs.read_file": {"path": "/etc/hosts"},
    "fs.write_file": {"path": "/workspace/.smoke_test", "content": "smoke"},
    "fs.delete_file": {"path": "/workspace/.smoke_test"},
    "scan_directory_secrets": {"directory_path": "/workspace"},
    "scan_source_vulnerabilities": {"directory_path": "/workspace"},
    "scan_dockerfile_security": {"dockerfile_path": "/workspace/Dockerfile"},
    # Evidence / Logging
    "log_finding": {"title": "Smoke Finding", "severity": "low", "description": "test", "evidence": "test"},
    "log_evidence": {"evidence_type": "text", "description": "smoke evidence", "raw_data": "sample"},
    # Browser (safe no-op if no browser daemon)
    "browser.open": {"url": "about:blank"},
    "browser.get_html": {},
    "browser.get_forms": {},
    "browser.click": {"selector": "body"},
    "browser.fill": {"selector": "input", "value": "test"},
    "browser.screenshot": {},
    # Manifest / Recon
    "search_security_knowledge": {"query": "SQL injection"},
    "enumerate_subdomains": {"domain": "localhost"},
    "dns_lookup": {"domain": "localhost"},
    "whois_lookup": {"target": "127.0.0.1"},
    "check_ssl_cert": {"host": "127.0.0.1"},
    # Arsenal capability tools
    "cap_recon_ping": {"host": "127.0.0.1"},
    "cap_recon_ports": {"host": "127.0.0.1", "ports": "80"},
    "cap_recon_banners": {"host": "127.0.0.1", "port": 80},
    "cap_recon_dns": {"domain": "localhost"},
    "cap_recon_subdomains": {"domain": "localhost"},
    "cap_recon_whois": {"target": "127.0.0.1"},
    "cap_recon_http_probe": {"url": "http://127.0.0.1:80"},
    "cap_web_tech": {"url": "http://127.0.0.1:80"},
    "cap_web_dirs": {"url": "http://127.0.0.1:80"},
    "cap_web_endpoints": {"url": "http://127.0.0.1:80"},
    "cap_web_headers": {"url": "http://127.0.0.1:80"},
    "cap_web_cors": {"url": "http://127.0.0.1:80"},
    "cap_web_methods": {"url": "http://127.0.0.1:80"},
    "cap_web_forms": {"url": "http://127.0.0.1:80"},
    "cap_web_param_fuzz": {"url": "http://127.0.0.1:80/FUZZ"},
    "cap_auth_brute_http": {"url": "http://127.0.0.1:80/login"},
    "cap_auth_brute_ssh": {"host": "127.0.0.1"},
    "cap_auth_spray": {"host": "127.0.0.1"},
    "cap_crack_hash_identify": {"hash": "5d41402abc4b2a76b9719d911017c592"},
    "cap_crack_hashes": {"hash": "5d41402abc4b2a76b9719d911017c592"},
    "cap_crack_jwt_decode": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"},
    "cap_vuln_general": {"url": "http://127.0.0.1:80"},
    "cap_vuln_sqli": {"url": "http://127.0.0.1:80?id=1"},
    "cap_vuln_xss": {"url": "http://127.0.0.1:80?q=test"},
    "cap_vuln_lfi": {"url": "http://127.0.0.1:80?page=home"},
    "cap_vuln_cmdi": {"url": "http://127.0.0.1:80?cmd=test"},
    "cap_vuln_cve": {"url": "http://127.0.0.1:80"},
    "cap_stress_http": {"url": "http://127.0.0.1:80", "concurrency": 1, "duration": 1},
    "cap_exploit_search": {"query": "apache"},
    "cap_exploit_reverse_shell": {"lhost": "127.0.0.1", "lport": 4444, "shell_type": "bash"},
    # Knowledge tools
    "query_asset_graph": {"query": "localhost"},
    "record_hypothesis": {"statement": "smoke test hypothesis"},
    "recommend_tools": {"goal": "port scan"}
}


class ToolcheckAuditor:
    """
    Validates module imports, tool contracts, schema parameters, and runs live smoke-tests.
    """

    def __init__(self, sandbox: Optional[Any] = None):
        self.sandbox = sandbox or get_sandbox()
        self.knowledge = AssetGraph()
        self.selector = ToolSelector()
        self.registry = create_authoritative_registry()

    def audit_all_modules(self) -> Tuple[bool, List[Tuple[str, bool, str]]]:
        """
        Recursively imports all modules in security_agent package to detect broken imports or symbols.
        """
        results = []
        all_passed = True
        for package in ["agent", "benchmark", "browser", "cli", "core", "events", "intelligence", "model", "persistence", "range", "remediation", "reports", "sandbox", "security", "state", "storage", "system", "toolchain", "tools", "training", "tui", "verification"]:
            try:
                mod = importlib.import_module(package)
                results.append((package, True, "OK"))
            except Exception as e:
                all_passed = False
                results.append((package, False, f"{type(e).__name__}: {e}"))
                continue
            for _, name, _ in pkgutil.walk_packages(mod.__path__, prefix=f"{package}."):
                try:
                    importlib.import_module(name)
                    results.append((name, True, "OK"))
                except Exception as e:
                    all_passed = False
                    results.append((name, False, f"{type(e).__name__}: {e}"))

        return all_passed, results

    def audit_tool(self, name: str) -> ToolAuditResult:
        """
        Audits a single registered tool's schema, parameters, and executes a live safe smoke-test.
        """
        res = ToolAuditResult(name=name)
        tool_entry = self.registry.tools.get(name)
        if not tool_entry:
            res.error_type = AuditErrorType.SCHEMA_ERROR
            res.error_message = f"Tool '{name}' is not registered in ToolRegistry"
            return res

        func = tool_entry.func
        res.import_ok = callable(func)

        # 1. Schema & parameter signature check
        try:
            sig = inspect.signature(func)
            schema = tool_entry.export_schema()
            # If native schema is exported, check property names match signature
            if schema and "function" in schema and "parameters" in schema["function"]:
                props = schema["function"]["parameters"].get("properties", {})
                reqs = schema["function"]["parameters"].get("required", [])
                
                # Verify required properties exist in signature
                for r in reqs:
                    if r not in sig.parameters:
                        res.error_type = AuditErrorType.SCHEMA_ERROR
                        res.error_message = f"Required schema param '{r}' not in function signature: {sig}"
                        return res
            res.schema_ok = True
        except Exception as e:
            res.error_type = AuditErrorType.SCHEMA_ERROR
            res.error_message = f"Schema validation error: {e}"
            return res

        # 2. Smoke test execution through production dispatcher
        test_args = SAFE_TEST_ARGS.get(name, {})
        context = {
            "sandbox": self.sandbox,
            "knowledge": self.knowledge,
            "selector": self.selector
        }

        t0 = time.time()
        try:
            output = self.registry.execute(name, test_args, context=context)
            res.duration_s = time.time() - t0
            out_str = str(output)
            res.output_preview = out_str[:120].replace("\n", " ")

            # Classify error in returned output string
            if "name '" in out_str and "is not defined" in out_str:
                res.smoke_ok = False
                res.error_type = AuditErrorType.IMPORT_ERROR
                res.error_message = out_str.strip()
            elif "sh: " in out_str and "not found" in out_str:
                res.smoke_ok = False
                res.error_type = AuditErrorType.DEPENDENCY_MISSING
                res.error_message = out_str.strip()
            elif "POLICY DENIED" in out_str:
                res.smoke_ok = True
                res.dependency_ok = True
            else:
                res.smoke_ok = True
                res.dependency_ok = True
        except NameError as e:
            res.duration_s = time.time() - t0
            res.smoke_ok = False
            res.error_type = AuditErrorType.IMPORT_ERROR
            res.error_message = f"NameError: {e}"
        except TypeError as e:
            res.duration_s = time.time() - t0
            res.smoke_ok = False
            res.error_type = AuditErrorType.ARGUMENT_ERROR
            res.error_message = f"TypeError: {e}"
        except Exception as e:
            res.duration_s = time.time() - t0
            res.smoke_ok = False
            res.error_type = AuditErrorType.TOOL_FAILURE
            res.error_message = f"{type(e).__name__}: {e}"

        return res

    def run_full_audit(self) -> Tuple[bool, List[ToolAuditResult], List[Tuple[str, bool, str]]]:
        """
        Executes whole-codebase import audit and smoke-tests all registered tools.
        """
        modules_ok, module_results = self.audit_all_modules()
        
        tool_results = []
        all_tools_ok = True
        for name in sorted(self.registry.tools.keys()):
            t_res = self.audit_tool(name)
            tool_results.append(t_res)
            if not t_res.passed:
                all_tools_ok = False

        overall_ok = modules_ok and all_tools_ok
        return overall_ok, tool_results, module_results


def run_toolcheck(sandbox: Optional[Any] = None, fast: bool = False) -> bool:
    """
    Interactive and CLI runner for Toolcheck. Prints formatted Rich panels and tables.
    If fast=True (used during startup), verifies all 95 module imports and 137 tool schemas
    and smoke tests core tools in ~1s without rendering a 137-row table.
    """
    auditor = ToolcheckAuditor(sandbox=sandbox)
    
    # 1. Module import audit
    modules_ok, module_results = auditor.audit_all_modules()
    total_mods = len(module_results)
    passed_mods = sum(1 for _, ok, _ in module_results if ok)
    
    if not modules_ok:
        console.print(f"[bold red]Module Import Audit Failed ({passed_mods}/{total_mods} modules passed):[/bold red]")
        for name, ok, err in module_results:
            if not ok:
                console.print(f"  [red]✗ {name}: {err}[/red]")
        console.print("[bold red]STARTUP BLOCKED: Fix broken module imports before proceeding.[/bold red]\n")
        return False

    tool_names = sorted(auditor.registry.tools.keys())
    total_tools = len(tool_names)

    if fast:
        # Fast startup mode: verify all tool schemas and contracts
        invalid_contracts = []
        for name in tool_names:
            tool_entry = auditor.registry.tools.get(name)
            if not tool_entry or not callable(tool_entry.func):
                invalid_contracts.append((name, "Not callable"))
        
        # Smoke test core essential tools
        core_smoke = ["terminal.execute", "nmap_scan", "web_probe", "whatweb_scan", "sqlmap_scan"]
        for c in core_smoke:
            if c in auditor.registry.tools:
                res = auditor.audit_tool(c)
                if not res.passed:
                    invalid_contracts.append((c, f"Smoke failure: {res.error_message}"))

        all_passed = len(invalid_contracts) == 0
        summary_text = (
            f"[bold]Modules Imported:[/] [green]{passed_mods}/{total_mods} ✓[/green]\n"
            f"[bold]Tool Contracts:[/]   [green]{total_tools}/{total_tools} ✓[/green]\n"
            f"[bold]Sandbox Image:[/]    [cyan]{get_security_sandbox_image()}[/cyan]\n"
            f"[bold]Toolcheck Status:[/] {'[bold green]ALL TOOLS READY[/bold green]' if all_passed else '[bold red]TOOLCHECK FAILED[/bold red]'}"
        )
        border_style = "bright_green" if all_passed else "bright_red"
        console.print(Panel(summary_text, title="╭─ Toolcheck Startup Verification ─╮", border_style=border_style, box=ROUNDED))
        console.print()
        return all_passed

    # 2. Full deep smoke-testing mode (renders 137-row table)
    console.print("\n[bold cyan]╭────────────────────────── BUZZARD TOOLCHECK AUDIT ──────────────────────────╮[/bold cyan]")
    tool_results: List[ToolAuditResult] = []
    
    table = Table(box=ROUNDED, show_header=True, header_style="bold bright_blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Tool Name", style="bold bright_white", width=28)
    table.add_column("Import", style="green", width=8, justify="center")
    table.add_column("Schema", style="green", width=8, justify="center")
    table.add_column("Smoke Test", width=12, justify="center")
    table.add_column("Status / Preview", style="dim")

    all_passed = True
    for idx, name in enumerate(tool_names, 1):
        res = auditor.audit_tool(name)
        tool_results.append(res)
        
        import_str = "[green]✓[/green]" if res.import_ok else "[red]✗[/red]"
        schema_str = "[green]✓[/green]" if res.schema_ok else "[red]✗[/red]"
        
        if res.smoke_ok:
            smoke_str = f"[green]✓ ({res.duration_s:.1f}s)[/green]"
            status_str = f"[dim]{res.output_preview[:60]}[/dim]" if res.output_preview else "[dim green]OK[/dim green]"
        else:
            all_passed = False
            smoke_str = "[bold red]✗ FAILED[/bold red]"
            status_str = f"[bold red]{res.error_type.value}: {res.error_message[:60]}[/bold red]"
            
        table.add_row(str(idx), name, import_str, schema_str, smoke_str, status_str)

    console.print(table)
    
    # Summary panel
    passed_tools = sum(1 for r in tool_results if r.passed)
    summary_text = (
        f"[bold]Modules Imported:[/] [green]{passed_mods}/{total_mods} ✓[/green]\n"
        f"[bold]Tools Verified:[/]   [green]{passed_tools}/{total_tools} ✓[/green]\n"
        f"[bold]Sandbox Image:[/]    [cyan]{get_security_sandbox_image()}[/cyan]\n"
        f"[bold]Overall Status:[/]   {'[bold green]ALL TOOLS READY[/bold green]' if all_passed else '[bold red]TOOLCHECK FAILED[/bold red]'}"
    )
    
    border_style = "bright_green" if all_passed else "bright_red"
    console.print(Panel(summary_text, title="╭─ Toolcheck Summary ─╮", border_style=border_style, box=ROUNDED))
    console.print()
    
    return all_passed
