"""
Related-test selection (roadmap item C2): run the tests that cover what changed while working,
and leave the full suite to the completion gate.

`related_tests` is read-only. It finds the source files that differ from HEAD (or the paths
given), follows the repository index's import graph backwards up to MAX_DEPTH levels to the test
files that reach them, and returns the exact command to run only those tests. The agent runs that
command through `terminal.execute`, so the user approves it like any other command.

Commands are produced for pytest and Go. For other languages the related test files are listed
and the project's own test command should be used.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from tools.code_index import get_index
from tools.filesystem import get_active_workspace, get_safe_path

MAX_DEPTH = 3
MAX_LISTED = 40

_TEST_FILE = re.compile(
    r"(^|/)(tests?/|__tests__/|test_[^/]*$|[^/]*_test\.[a-z]+$|conftest\.py$|[^/]*\.(test|spec)\.[a-z]+$)"
)


def is_test_file(path: str) -> bool:
    return bool(_TEST_FILE.search(path.replace("\\", "/")))


def _changed_files(root: Path) -> List[str]:
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=30, check=False, stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()[:200]}")
        return result.stdout

    paths = set(git("diff", "--name-only", "HEAD").splitlines())
    paths.update(git("ls-files", "--others", "--exclude-standard").splitlines())
    return sorted(path.replace("\\", "/") for path in paths if path.strip())


def reverse_imports(index) -> Dict[str, Set[str]]:
    """Maps each indexed file to the indexed files that import it."""
    importers: Dict[str, Set[str]] = {}
    for source, entry in index.files.items():
        for target in entry.imports:
            resolved = index.resolve_import(source, target)
            if resolved and resolved != source:
                importers.setdefault(resolved, set()).add(source)
    return importers


def tests_reaching(changed: Iterable[str], importers: Dict[str, Set[str]], depth: int = MAX_DEPTH) -> Set[str]:
    """Test files that import a changed file directly or through up to `depth` levels."""
    tests: Set[str] = {path for path in changed if is_test_file(path)}
    frontier = {path for path in changed if not is_test_file(path)}
    seen = set(frontier)
    for _ in range(depth):
        following: Set[str] = set()
        for path in frontier:
            for importer in importers.get(path, ()):
                if is_test_file(importer):
                    tests.add(importer)
                elif importer not in seen:
                    seen.add(importer)
                    following.add(importer)
        frontier = following
    return tests


def _project_python(root: Path) -> str:
    for folder in (".venv", "venv"):
        relative = Path(folder) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if (root / relative).is_file():
            return str(relative)
    return "python"


def _go_packages(paths: Iterable[str]) -> List[str]:
    packages = {"./" + os.path.dirname(path) if os.path.dirname(path) else "." for path in paths}
    return sorted(package.replace("\\", "/") for package in packages)


def related_tests(paths: str = "") -> str:
    """
    Finds the tests related to changed files and returns the command that runs only those.
    Arguments:
        paths: Optional files to start from, separated by spaces. Default: files changed since HEAD.
    """
    root = Path(get_active_workspace())
    try:
        if paths.strip():
            changed = []
            for path in paths.split():
                safe = Path(get_safe_path(path))
                changed.append(os.path.relpath(safe, root).replace("\\", "/"))
        else:
            changed = _changed_files(root)
    except (PermissionError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        return f"Error: {error}"
    if not changed:
        return "No changed files, so there are no related tests to run."

    python_changed = [path for path in changed if path.endswith(".py")]
    go_changed = [path for path in changed if path.endswith(".go")]
    other_changed = [path for path in changed if path not in python_changed and path not in go_changed]
    sections: List[str] = []

    if python_changed or other_changed:
        index = get_index()
        tests = sorted(tests_reaching(python_changed + other_changed, reverse_imports(index)))
        python_tests = [path for path in tests if path.endswith(".py") and (root / path).is_file()]
        other_tests = [path for path in tests if not path.endswith(".py")]
        if python_tests:
            listed = " ".join(f'"{path}"' if " " in path else path for path in python_tests[:MAX_LISTED])
            sections.append(
                f"Python tests related to the change ({len(python_tests)}):\n"
                f"  {_project_python(root)} -m pytest -q {listed}"
            )
        elif python_changed:
            sections.append("No Python test imports the changed files; run the project's test command to be safe.")
        if other_tests:
            sections.append(
                "Other related test files (run them with the project's test command):\n  "
                + "\n  ".join(other_tests[:MAX_LISTED])
            )
    if go_changed:
        sections.append("Go packages with changes:\n  go test " + " ".join(_go_packages(go_changed)))

    sections.append("Run the command with terminal.execute. The completion gate still runs the full test suite at the end.")
    return "\n\n".join(sections)


def register_related_tests_tool(registry) -> None:
    from tools.registry import ToolCategory

    registry.register(
        name="related_tests",
        description=(
            "Finds the tests that cover the files changed since HEAD (or given paths) through the import graph, "
            "and returns the command that runs only those. Read-only; run the command with terminal.execute. "
            "Arguments: paths (str, optional, space-separated)."
        ),
        func=related_tests,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=False,
        approval_required=False,
        timeout=60,
    )
