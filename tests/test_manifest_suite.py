"""
Tests for Manifest Suite Tools (All 34 tools from Four-Model Manifest).
"""
import os
import pytest
from security_agent.tools.registry import ToolRegistry
from security_agent.tools.manifest_suite import (
    edit_file,
    glob_files,
    grep_search,
    file_metadata,
    web_search,
    web_fetch,
    dns_reverse_lookup,
    dns_query,
    tcp_connectivity_check,
    service_inventory,
    file_identify,
    strings_extract,
    static_analysis,
    register_manifest_tools
)
from security_agent.storage.db import StorageManager

def test_edit_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("Hello Old World")
    res = edit_file(str(f), "Old", "New")
    assert "Successfully updated" in res
    assert f.read_text() == "Hello New World"

def test_glob_and_grep(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("import os\npassword = 'supersecret'\neval('1+1')\n")
    glob_res = glob_files(str(tmp_path / "*.py"))
    assert "sample.py" in glob_res
    
    grep_res = grep_search("supersecret", str(tmp_path))
    assert "supersecret" in grep_res

def test_file_metadata(tmp_path):
    f = tmp_path / "info.txt"
    f.write_text("content")
    res = file_metadata(str(f))
    assert "Size:" in res
    assert "Permissions:" in res

def test_static_analysis(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text("eval(user_input)\npassword = '12345'\n")
    res = static_analysis(str(f))
    assert "[High]" in res or "[Medium]" in res

def test_dns_and_tcp_checks():
    res_tcp = tcp_connectivity_check("127.0.0.1", 65432)
    assert "Connection" in res_tcp
    
    res_dns = dns_query("localhost", "A")
    assert "localhost" in res_dns or "127.0.0.1" in res_dns

def test_manifest_tool_registry():
    registry = ToolRegistry()
    register_manifest_tools(registry)
    assert "edit_file" in registry.tools
    assert "web_search" in registry.tools
    assert "service_inventory" in registry.tools
    assert "static_analysis" in registry.tools
