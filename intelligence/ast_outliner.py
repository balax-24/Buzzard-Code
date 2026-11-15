"""
AST Skeleton Outliner and Context-Aware Selective Unfolder for Buzzard Code.

Eliminates the 800-line context window limit and 90% token waste by providing:
1. Hierarchical code outlines (symbols, signatures, docstrings, line numbers).
2. Selective symbol unfolding (fetches only the target function/method block).
3. Token savings calculation to minimize LLM context window pressure.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SymbolOutlineNode:
    name: str
    kind: str  # 'function', 'async_function', 'class', 'method'
    start_line: int
    end_line: int
    signature: str
    docstring: Optional[str] = None
    children: List[SymbolOutlineNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "signature": self.signature,
            "docstring": self.docstring,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class FileOutline:
    file_path: str
    total_lines: int
    raw_token_estimate: int
    outline_token_estimate: int
    savings_percent: float
    symbols: List[SymbolOutlineNode] = field(default_factory=list)

    def render_skeleton(self) -> str:
        """Renders a concise, human/agent-readable outline skeleton."""
        lines = [
            f"# File: {self.file_path} ({self.total_lines} lines | ~{self.outline_token_estimate} tokens, saved {self.savings_percent:.1f}%)"
        ]

        def _format_node(node: SymbolOutlineNode, depth: int = 0) -> None:
            indent = "  " * depth
            doc = f' """{node.docstring.splitlines()[0]}"""' if node.docstring else ""
            lines.append(f"{indent}• [{node.kind}] {node.signature} [L{node.start_line}-L{node.end_line}]{doc}")
            for child in node.children:
                _format_node(child, depth + 1)

        for sym in self.symbols:
            _format_node(sym, depth=0)

        return "\n".join(lines)


class AstOutliner:
    """
    Parses source files into structural outlines and selectively unfolds targeted nodes.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def generate_outline(self, rel_path: str) -> FileOutline:
        """Generates an AST structural outline of a file."""
        abs_path = self.workspace_root / rel_path
        if not abs_path.exists() or not abs_path.is_file():
            return FileOutline(file_path=rel_path, total_lines=0, raw_token_estimate=0, outline_token_estimate=0, savings_percent=0.0)

        content = abs_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        total_lines = len(lines)
        raw_tokens = max(1, len(content) // 4)

        if abs_path.suffix == ".py":
            symbols = self._parse_python_ast(content)
        else:
            symbols = self._parse_generic_symbols(lines)

        outline_text = "\n".join(s.name for s in symbols)
        outline_tokens = max(1, len(outline_text) // 4 + len(symbols) * 8)
        savings = max(0.0, (1.0 - (outline_tokens / raw_tokens)) * 100.0)

        return FileOutline(
            file_path=rel_path,
            total_lines=total_lines,
            raw_token_estimate=raw_tokens,
            outline_token_estimate=outline_tokens,
            savings_percent=savings,
            symbols=symbols,
        )

    def unfold_symbol(self, rel_path: str, symbol_name: str, context_lines: int = 2) -> Dict[str, Any]:
        """
        Selectively extracts and returns only the code block for a specific symbol.
        """
        outline = self.generate_outline(rel_path)
        abs_path = self.workspace_root / rel_path
        if not abs_path.exists():
            return {"error": f"File not found: {rel_path}"}

        target_node = self._find_symbol(outline.symbols, symbol_name)
        if not target_node:
            return {"error": f"Symbol '{symbol_name}' not found in {rel_path}"}

        all_lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, target_node.start_line - context_lines)
        end = min(len(all_lines), target_node.end_line + context_lines)

        selected_snippet = []
        for idx in range(start, end + 1):
            line_no = idx
            line_txt = all_lines[idx - 1]
            marker = "▶" if target_node.start_line <= line_no <= target_node.end_line else " "
            selected_snippet.append(f"{marker} {line_no:4d} | {line_txt}")

        return {
            "file_path": rel_path,
            "symbol": target_node.to_dict(),
            "start_line": start,
            "end_line": end,
            "snippet": "\n".join(selected_snippet),
        }

    def _find_symbol(self, nodes: List[SymbolOutlineNode], name: str) -> Optional[SymbolOutlineNode]:
        for node in nodes:
            if node.name == name or f"{node.name}()" == name:
                return node
            child_match = self._find_symbol(node.children, name)
            if child_match:
                return child_match
        return None

    def _parse_python_ast(self, content: str) -> List[SymbolOutlineNode]:
        symbols: List[SymbolOutlineNode] = []
        try:
            tree = ast.parse(content)
        except Exception:
            return self._parse_generic_symbols(content.splitlines())

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(self._build_func_node(node))
            elif isinstance(node, ast.ClassDef):
                cls_node = SymbolOutlineNode(
                    name=node.name,
                    kind="class",
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    signature=f"class {node.name}",
                    docstring=ast.get_docstring(node),
                )
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        cls_node.children.append(self._build_func_node(item, is_method=True))
                symbols.append(cls_node)
        return symbols

    def _build_func_node(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_method: bool = False) -> SymbolOutlineNode:
        kind = "method" if is_method else ("async_function" if isinstance(node, ast.AsyncFunctionDef) else "function")
        args_str = ", ".join(arg.arg for arg in node.args.args)
        ret_ann = ""
        if node.returns and hasattr(node.returns, "id"):
            ret_ann = f" -> {node.returns.id}"

        sig = f"def {node.name}({args_str}){ret_ann}"
        if isinstance(node, ast.AsyncFunctionDef):
            sig = f"async {sig}"

        return SymbolOutlineNode(
            name=node.name,
            kind=kind,
            start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            signature=sig,
            docstring=ast.get_docstring(node),
        )

    def _parse_generic_symbols(self, lines: List[str]) -> List[SymbolOutlineNode]:
        symbols = []
        func_re = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function|def|fn|func)\s+([A-Za-z0-9_]+)\s*\((.*?)\)")
        class_re = re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z0-9_]+)")

        for idx, line in enumerate(lines, start=1):
            f_match = func_re.match(line)
            if f_match:
                name, args = f_match.groups()
                symbols.append(
                    SymbolOutlineNode(
                        name=name,
                        kind="function",
                        start_line=idx,
                        end_line=idx,
                        signature=f"{name}({args})",
                    )
                )
                continue

            c_match = class_re.match(line)
            if c_match:
                name = c_match.group(1)
                symbols.append(
                    SymbolOutlineNode(
                        name=name,
                        kind="class",
                        start_line=idx,
                        end_line=idx,
                        signature=f"class {name}",
                    )
                )

        return symbols
