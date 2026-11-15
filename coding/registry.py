"""
Lean tool registry for Buzzard Code (roadmap H).

Constructs a focused ToolRegistry populated exclusively with coding, inspection,
and workflow capabilities, omitting heavy pentest / security scanning modules.
"""

from __future__ import annotations

from typing import Optional

from tools.registry import ToolRegistry


def create_coding_registry() -> ToolRegistry:
    """
    Builds a lightweight ToolRegistry containing only coding tools.
    Loads significantly faster and uses less memory than the full security registry.
    """
    registry = ToolRegistry()

    # Core Terminal execution & basic tools
    from tools.basic import register_basic_tools
    register_basic_tools(registry)

    from tools.security import terminal_execute
    registry.register(
        name="terminal.execute",
        description="Executes a shell command in the active sandbox after operator approval. Arguments: command (str).",
        func=terminal_execute,
    )

    # Evidence tools
    from tools.evidence import register_evidence_tools
    register_evidence_tools(registry)

    # Filesystem operations
    from tools.filesystem import register_filesystem_tools
    register_filesystem_tools(registry)

    # Git operations
    from tools.git_tools import register_git_tools
    register_git_tools(registry)

    # Process & background shell management
    from tools.process_manager import register_process_tools
    from tools.shell_manager import register_shell_tool
    register_process_tools(registry)
    register_shell_tool(registry)

    # Checkpoints & atomic workspace rewind
    from agent.workspace_checkpoints import register_checkpoint_tools
    register_checkpoint_tools(registry)

    # Code index & semantic search
    from tools.code_index import register_code_index_tools
    register_code_index_tools(registry)

    # Web search & documentation fetch
    from tools.web_tools import register_web_tools
    register_web_tools(registry)

    # Browser UI checks
    from tools.browser_tools import register_browser_tools
    register_browser_tools(registry)

    # Test relevance analysis
    from tools.related_tests import register_related_tests_tool
    register_related_tests_tool(registry)

    # LSP (Language Server Protocol) code intelligence
    from tools.lsp_tools import register_lsp_tools
    register_lsp_tools(registry)

    # Persistent project memory
    from agent.project_memory import register_memory_tools
    register_memory_tools(registry)

    # Git branch / commit / PR workflows
    from tools.git_workflow import register_git_workflow_tools
    register_git_workflow_tools(registry)

    # Subagent delegation
    from agent.subagents import register_subagent_tools
    register_subagent_tools(registry)

    return registry
