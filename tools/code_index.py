"""
Repository index and code search for Buzzard Code.

Builds a lightweight, in-memory symbol index of the active workspace so the agent can find
definitions, references and related files without reading whole trees:

- code_symbols: where a function, class or method is defined
- code_references: where a name is used, with the enclosing definition for each use
- code_related: the files a file imports and the files that import it

Python is parsed with ``ast``; other common languages use per-language definition patterns.
The index is refreshed incrementally: only files whose size or mtime changed are re-parsed.
Read-only and confined to the workspace boundary.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from tools.filesystem import get_active_workspace, get_safe_path

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_RESULTS = 50

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist", "build", "target",
    ".next", ".dart_tool", ".idea", ".vscode", "coverage", ".gradle",
})

LANGUAGE_BY_EXT = {
    ".py": "python", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".go": "go", ".rs": "rust", ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".dart": "dart",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".hpp": "c", ".rb": "ruby", ".php": "php",
}

_IDENT = r"[A-Za-z_$][\w$]*"
DEFINITION_PATTERNS: Dict[str, List[Tuple[str, re.Pattern[str]]]] = {
    "js": [
        ("class", re.compile(rf"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+({_IDENT})")),
        ("function", re.compile(rf"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*({_IDENT})")),
        ("function", re.compile(rf"^\s*(?:export\s+)?(?:const|let|var)\s+({_IDENT})\s*=\s*(?:async\s+)?(?:\([^)]*\)|{_IDENT})\s*=>")),
        ("interface", re.compile(rf"^\s*(?:export\s+)?(?:interface|type|enum)\s+({_IDENT})")),
    ],
    "go": [
        ("function", re.compile(rf"^func\s+(?:\([^)]*\)\s*)?({_IDENT})\s*\(")),
        ("type", re.compile(rf"^type\s+({_IDENT})\s+")),
    ],
    "rust": [
        ("function", re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+({_IDENT})")),
        ("type", re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+({_IDENT})")),
    ],
    "java": [
        ("class", re.compile(rf"^\s*(?:(?:public|private|protected|abstract|final|static)\s+)*(?:class|interface|enum|record)\s+({_IDENT})")),
        ("method", re.compile(rf"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized)\s+)+[\w<>\[\],\s]+?\s+({_IDENT})\s*\(")),
    ],
    "kotlin": [
        ("class", re.compile(rf"^\s*(?:\w+\s+)*(?:class|interface|object)\s+({_IDENT})")),
        ("function", re.compile(rf"^\s*(?:\w+\s+)*fun\s+(?:<[^>]*>\s*)?(?:{_IDENT}\.)?({_IDENT})\s*\(")),
    ],
    "csharp": [
        ("class", re.compile(rf"^\s*(?:\w+\s+)*(?:class|interface|struct|enum|record)\s+({_IDENT})")),
        ("method", re.compile(rf"^\s*(?:(?:public|private|protected|internal|static|virtual|override|async|abstract)\s+)+[\w<>\[\],\s]+?\s+({_IDENT})\s*\(")),
    ],
    "dart": [
        ("class", re.compile(rf"^\s*(?:abstract\s+)?(?:class|mixin|enum|extension)\s+({_IDENT})")),
        ("function", re.compile(rf"^\s*(?:static\s+)?(?:Future<[^>]*>|void|[A-Z]\w*(?:<[^>]*>)?|int|double|bool|String|dynamic)\??\s+({_IDENT})\s*\([^;]*$")),
    ],
    "c": [
        ("type", re.compile(rf"^\s*(?:typedef\s+)?(?:struct|class|enum|union)\s+({_IDENT})\s*[{{:]")),
        ("function", re.compile(rf"^(?!\s*(?:if|for|while|switch|return|else)\b)[\w:*&<>\s]+?\b({_IDENT})\s*\([^;]*\)\s*(?:const\s*)?\{{?\s*$")),
    ],
    "ruby": [
        ("class", re.compile(rf"^\s*(?:class|module)\s+({_IDENT})")),
        ("method", re.compile(rf"^\s*def\s+(?:self\.)?({_IDENT}[?!=]?)")),
    ],
    "php": [
        ("class", re.compile(rf"^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+({_IDENT})")),
        ("function", re.compile(rf"^\s*(?:(?:public|private|protected|static)\s+)*function\s+({_IDENT})")),
    ],
}

_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")
_JS_IMPORT = re.compile(r"""(?:import\s[^'"]*?from\s*|import\s*\(\s*|require\s*\(\s*|^\s*import\s+)['"]([^'"]+)['"]""")


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    path: str
    line: int
    end_line: int
    container: str = ""

    @property
    def qualified(self) -> str:
        return f"{self.container}.{self.name}" if self.container else self.name


@dataclass
class FileEntry:
    signature: Tuple[int, int]
    language: str
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


def _python_entry(rel: str, text: str, signature: Tuple[int, int]) -> FileEntry:
    entry = FileEntry(signature=signature, language="python")
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _regex_entry(rel, text, signature, "python")

    def visit(node: ast.AST, container: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                kind = "class" if isinstance(child, ast.ClassDef) else ("method" if container else "function")
                end = getattr(child, "end_lineno", None) or child.lineno
                entry.symbols.append(Symbol(child.name, kind, rel, child.lineno, end, container))
                visit(child, f"{container}.{child.name}" if container else child.name)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                if isinstance(child, ast.ImportFrom):
                    module = "." * child.level + (child.module or "")
                    if child.module:
                        entry.imports.append(module)
                    joiner = "." if child.module else ""
                    entry.imports.extend(f"{module}{joiner}{alias.name}" for alias in child.names if alias.name != "*")
                else:
                    entry.imports.extend(alias.name for alias in child.names)
            else:
                visit(child, container)

    visit(tree, "")
    return entry


def _regex_entry(rel: str, text: str, signature: Tuple[int, int], language: str) -> FileEntry:
    entry = FileEntry(signature=signature, language=language)
    patterns = DEFINITION_PATTERNS.get(language, [])
    for number, line in enumerate(text.splitlines(), 1):
        if language == "python":
            match = _PY_IMPORT.match(line)
            if match:
                entry.imports.append(match.group(1) or match.group(2))
            continue
        if language == "js":
            entry.imports.extend(_JS_IMPORT.findall(line))
        for kind, pattern in patterns:
            match = pattern.match(line)
            if match:
                entry.symbols.append(Symbol(match.group(1), kind, rel, number, number))
                break
    return entry


class CodeIndex:
    """Incremental symbol and import index for one workspace."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.files: Dict[str, FileEntry] = {}
        self.truncated = False
        self._modules: Optional[Dict[str, str]] = None
        self._lock = threading.Lock()

    def _candidate_files(self) -> List[str]:
        """Tracked plus untracked-but-not-ignored files when in git, else a filtered walk."""
        git = shutil.which("git")
        if git and os.path.isdir(os.path.join(self.root, ".git")):
            try:
                result = subprocess.run(
                    [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                    cwd=self.root, capture_output=True, timeout=20,
                )
                if result.returncode == 0:
                    names = [n.decode("utf-8", "replace") for n in result.stdout.split(b"\0") if n]
                    return [n for n in names if not (set(n.split("/")[:-1]) & SKIP_DIRS)]
            except (OSError, subprocess.SubprocessError):
                pass  # fall back to walking the tree
        found: List[str] = []
        for current, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(current, d))]
            for name in files:
                found.append(os.path.relpath(os.path.join(current, name), self.root).replace("\\", "/"))
        return found

    def refresh(self) -> None:
        with self._lock:
            candidates = [p for p in self._candidate_files() if os.path.splitext(p)[1].lower() in LANGUAGE_BY_EXT]
            self.truncated = len(candidates) > MAX_FILES
            candidates = sorted(candidates)[:MAX_FILES]
            seen = set()
            for rel in candidates:
                full = os.path.join(self.root, rel)
                try:
                    stat = os.stat(full)
                except OSError:
                    continue
                if stat.st_size > MAX_FILE_BYTES or os.path.islink(full):
                    continue
                seen.add(rel)
                signature = (stat.st_size, stat.st_mtime_ns)
                cached = self.files.get(rel)
                if cached and cached.signature == signature:
                    continue
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError:
                    continue
                language = LANGUAGE_BY_EXT[os.path.splitext(rel)[1].lower()]
                if language == "python":
                    self.files[rel] = _python_entry(rel, text, signature)
                else:
                    self.files[rel] = _regex_entry(rel, text, signature, language)
            for stale in set(self.files) - seen:
                del self.files[stale]
            self._modules = None

    def symbols(self) -> List[Symbol]:
        return [symbol for entry in self.files.values() for symbol in entry.symbols]

    def enclosing(self, rel: str, line: int) -> Optional[Symbol]:
        entry = self.files.get(rel)
        if not entry:
            return None
        best: Optional[Symbol] = None
        for symbol in entry.symbols:
            if symbol.line <= line <= symbol.end_line and (best is None or symbol.line >= best.line):
                best = symbol
        return best

    def _python_modules(self) -> Dict[str, str]:
        if self._modules is None:
            self._modules = {self._module_name(rel): rel for rel, entry in self.files.items() if entry.language == "python"}
        return self._modules

    def _module_name(self, rel: str) -> str:
        stem = os.path.splitext(rel)[0].replace("/", ".")
        return stem[: -len(".__init__")] if stem.endswith(".__init__") else stem

    def resolve_import(self, source: str, target: str) -> Optional[str]:
        """Maps an import string in ``source`` to an indexed file, when it is local."""
        if self.files.get(source, FileEntry((0, 0), "")).language == "python" or source.endswith(".py"):
            if target.startswith("."):
                depth = len(target) - len(target.lstrip("."))
                package = source.split("/")[:-1]
                package = package[: len(package) - (depth - 1)] if depth > 1 else package
                target = ".".join(package + [target.lstrip(".")]).strip(".")
            modules = self._python_modules()
            while target:
                if target in modules:
                    return modules[target]
                if "src." + target in modules:
                    return modules["src." + target]
                if "." not in target:
                    break
                target = target.rsplit(".", 1)[0]
            return None
        if not target.startswith("."):
            return None
        base = os.path.normpath(os.path.join(os.path.dirname(source), target)).replace("\\", "/")
        for suffix in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js"):
            if base + suffix in self.files:
                return base + suffix
        return None


_indexes: Dict[str, CodeIndex] = {}
_indexes_lock = threading.Lock()


def get_index() -> CodeIndex:
    """Returns the refreshed index for the active workspace."""
    root = os.path.abspath(get_active_workspace())
    with _indexes_lock:
        index = _indexes.setdefault(root, CodeIndex(root))
    index.refresh()
    return index


def _scope_filter(path: str) -> str:
    """Normalises an optional sub-path filter, enforcing the workspace boundary."""
    if not path or path in (".", "./"):
        return ""
    safe = get_safe_path(path)
    rel = os.path.relpath(safe, get_active_workspace()).replace("\\", "/")
    return "" if rel == "." else rel.rstrip("/")


def _in_scope(rel: str, scope: str) -> bool:
    return not scope or rel == scope or rel.startswith(scope + "/")


def _footer(index: CodeIndex) -> str:
    return f"\n(Index truncated to the first {MAX_FILES} source files.)" if index.truncated else ""


def code_symbols(query: str, kind: str = "", path: str = ".") -> str:
    """
    Finds where functions, classes and methods are defined.
    Arguments:
        query: Symbol name or part of it (case-insensitive). 'Class.method' narrows to a container.
        kind: Optional filter: function, class, method, type or interface.
        path: Optional sub-directory or file to search within (default '.').
    """
    query = str(query or "").strip()
    if not query:
        return "Error: query must name a symbol."
    try:
        scope = _scope_filter(path)
        index = get_index()
    except PermissionError as error:
        return f"Error: {error}"
    needle = query.lower()
    matches = []
    for symbol in index.symbols():
        if not _in_scope(symbol.path, scope) or (kind and symbol.kind != kind):
            continue
        target = symbol.qualified.lower() if "." in needle else symbol.name.lower()
        if needle in target:
            exact = symbol.name.lower() == needle.split(".")[-1]
            matches.append((0 if exact else 1, symbol.path, symbol.line, symbol))
    if not matches:
        return f"No definitions match '{query}'." + _footer(index)
    matches.sort(key=lambda item: item[:3])
    lines = [f"{s.path}:{s.line}  {s.kind} {s.qualified}" for *_rest, s in matches[:MAX_RESULTS]]
    extra = f"\n... {len(matches) - MAX_RESULTS} more; narrow the query or path." if len(matches) > MAX_RESULTS else ""
    return "\n".join(lines) + extra + _footer(index)


def code_references(symbol: str, path: str = ".") -> str:
    """
    Finds where a name is used, excluding its definitions, and names the function or class
    each use sits in (its caller).
    Arguments:
        symbol: Exact identifier to look for, e.g. 'apply_discount'.
        path: Optional sub-directory or file to search within (default '.').
    """
    name = str(symbol or "").strip().split(".")[-1]
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return "Error: symbol must be a single identifier such as 'apply_discount'."
    try:
        scope = _scope_filter(path)
        index = get_index()
    except PermissionError as error:
        return f"Error: {error}"
    word = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
    definitions = {(s.path, s.line) for s in index.symbols() if s.name == name}
    results = []
    total = 0
    for rel in sorted(index.files):
        if not _in_scope(rel, scope):
            continue
        try:
            with open(os.path.join(index.root, rel), "r", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    if (rel, number) in definitions or not word.search(line):
                        continue
                    total += 1
                    if len(results) < MAX_RESULTS:
                        owner = index.enclosing(rel, number)
                        where = f"  [in {owner.qualified}]" if owner else ""
                        results.append(f"{rel}:{number}{where}: {line.strip()[:160]}")
        except OSError:
            continue
    if not results:
        return f"No references to '{name}' found outside its definitions." + _footer(index)
    extra = f"\n... {total - MAX_RESULTS} more; narrow the path." if total > MAX_RESULTS else ""
    return f"{total} reference(s) to '{name}':\n" + "\n".join(results) + extra + _footer(index)


def code_related(path: str) -> str:
    """
    Lists the local files a source file imports and the files that import it.
    Arguments:
        path: Source file in the workspace, e.g. 'src/pricing.py'.
    """
    try:
        rel = _scope_filter(path)
        index = get_index()
    except PermissionError as error:
        return f"Error: {error}"
    entry = index.files.get(rel)
    if entry is None:
        return f"Error: '{path}' is not an indexed source file."
    imports = sorted({r for r in (index.resolve_import(rel, i) for i in entry.imports) if r and r != rel})
    importers = sorted(
        other for other, other_entry in index.files.items()
        if other != rel and any(index.resolve_import(other, i) == rel for i in other_entry.imports)
    )
    tests = sorted(p for p in importers if re.search(r"(^|/)(tests?/|test_|.*_test\.|.*\.test\.|.*\.spec\.)", p))
    defined = ", ".join(s.qualified for s in entry.symbols[:20]) or "none"
    parts = [
        f"{rel} ({entry.language})",
        f"Defines: {defined}",
        "Imports: " + (", ".join(imports) or "no local files"),
        "Imported by: " + (", ".join(importers[:MAX_RESULTS]) or "no local files"),
    ]
    if tests:
        parts.append("Tests: " + ", ".join(tests))
    return "\n".join(parts) + _footer(index)


def register_code_index_tools(registry) -> None:
    """Registers the read-only repository index tools."""
    from tools.registry import ToolCategory

    common = dict(
        category=ToolCategory.AUTOMATION, risk_level="LOW", read_only=True,
        sandbox_required=False, scope_required=False, approval_required=False, timeout=60,
    )
    registry.register(
        name="code_symbols",
        description="Finds where functions, classes and methods are defined across the repository. Arguments: query (str), kind (str, optional: function/class/method/type/interface), path (str, default '.').",
        func=code_symbols, **common,
    )
    registry.register(
        name="code_references",
        description="Finds every use of an identifier outside its definitions, naming the function or class each use is in (its callers). Arguments: symbol (str), path (str, default '.').",
        func=code_references, **common,
    )
    registry.register(
        name="code_related",
        description="Lists the local files a source file imports, the files that import it, and its tests. Arguments: path (str).",
        func=code_related, **common,
    )
    from tools.semantic_search import register_semantic_search_tool
    register_semantic_search_tool(registry)
