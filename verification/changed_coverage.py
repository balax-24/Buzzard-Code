"""
Changed-line coverage for the completion gate (roadmap item C3), Python projects first.

When the project's own environment has coverage.py 6.3 or newer, the gate runs its pytest
command under coverage. Afterwards this module reads coverage's SQLite data file directly
(no coverage import needed in Buzzard's environment) and reports which changed lines of
non-test Python code the tests executed.

Design decisions:
- Detecting coverage.py looks for installed files in the project's virtual environment; it
  never runs the project's interpreter before the user approves the test command.
- Coverage data is written to a temporary directory outside the repository, so it never
  appears as a changed file.
- Executable lines come from Python's ``ast``: a changed line counts when it lies in a simple
  statement or in the header of a compound statement. Comments, blank lines and docstrings
  inside a block are not counted. Coverage records the first line of a multi-line statement,
  so a changed line maps to the first line of its statement.
- Anything that cannot be measured is reported as ``measured: False`` with a reason; it is
  never estimated.
"""

from __future__ import annotations

import ast
import os
import re
import sqlite3
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

COVERAGE_SETTINGS = ("auto", "off")
MIN_COVERAGE_VERSION = (6, 3)  # first release with `coverage run --data-file`
SUPPORTED_SCHEMA_VERSIONS = {7}
MAX_LISTED_UNCOVERED = 40

_PYTEST_COMMAND = re.compile(r"^(?P<python>\S+)\s+-m\s+pytest(?P<rest>(\s.*)?)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
_TEST_FILE = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)")


@dataclass
class ChangedLineCoverage:
    """What the tests executed of the changed, executable, non-test Python lines."""

    measured: bool
    reason: str = ""
    tool: str = "coverage.py"
    covered: int = 0
    total: int = 0
    uncovered: Dict[str, List[int]] = field(default_factory=dict)

    @property
    def percent(self) -> Optional[float]:
        if not self.measured or self.total == 0:
            return None
        return round(100.0 * self.covered / self.total, 1)

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["percent"] = self.percent
        return data

    def summary(self) -> str:
        if not self.measured:
            return f"not measured ({self.reason})"
        if self.total == 0:
            return "no executable non-test Python lines changed"
        text = f"{self.covered}/{self.total} changed lines run by tests ({self.percent}%)"
        missing = [f"{path}:{', '.join(map(str, lines))}" for path, lines in sorted(self.uncovered.items())]
        if missing:
            text += "; not run: " + "; ".join(missing)
        return text


def not_measured(reason: str) -> ChangedLineCoverage:
    return ChangedLineCoverage(measured=False, reason=reason)


# -- deciding whether coverage can run --------------------------------------------------


def coverage_setting(settings: Dict[str, object]) -> Tuple[Optional[str], Optional[str]]:
    """Returns (setting, error). The project setting `coverage` is "auto" (default) or "off"."""
    value = settings.get("coverage", "auto")
    if value not in COVERAGE_SETTINGS:
        return None, f'coverage must be "auto" or "off" in .buzzard/project.json, not {value!r}'
    return str(value), None


def _version_tuple(text: str) -> Tuple[int, ...]:
    parts = []
    for piece in text.split(".")[:2]:
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def installed_coverage_version(workspace: Path, python: str) -> Optional[Tuple[int, ...]]:
    """Finds coverage.py in the project's virtual environment by its files, without running it."""
    interpreter = Path(python)
    if not interpreter.is_absolute():
        interpreter = workspace / interpreter
    if interpreter.parent.name.lower() not in ("scripts", "bin"):
        return None  # not a virtual environment we can inspect safely
    environment = interpreter.parent.parent
    patterns = ("Lib/site-packages/coverage-*.dist-info", "lib/python*/site-packages/coverage-*.dist-info")
    versions = [
        _version_tuple(match.name[len("coverage-"):-len(".dist-info")])
        for pattern in patterns
        for match in environment.glob(pattern)
    ]
    return max(versions) if versions else None


def wrap_pytest_command(command: str, data_file: Path) -> Optional[str]:
    """Runs `<python> -m pytest ...` under coverage; returns None for any other command shape."""
    match = _PYTEST_COMMAND.match(command.strip())
    if not match:
        return None
    return f'{match["python"]} -m coverage run --data-file="{data_file}" -m pytest{match["rest"] or ""}'


def coverage_data_path(workspace: Path) -> Path:
    """A fixed data-file path per workspace under BUZZARD_HOME, outside the repository."""
    import hashlib

    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:16]
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard")
    return base / "coverage" / key / "coverage.db"


# -- changed lines ------------------------------------------------------------------------


def _git(root: Path, args: List[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30, check=False, stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def parse_added_lines(diff_text: str) -> Dict[str, Set[int]]:
    """New-side line numbers added or changed by a `git diff -U0` output."""
    lines: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    for row in diff_text.splitlines():
        if row.startswith("+++ "):
            target = row[4:].strip()
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            continue
        header = _HUNK_HEADER.match(row)
        if header and current:
            start = int(header["start"])
            count = int(header["count"]) if header["count"] is not None else 1
            lines.setdefault(current, set()).update(range(start, start + count))
    return lines


def changed_python_lines(root: Path) -> Dict[str, Set[int]]:
    """Changed lines of non-test Python files: modified tracked files plus every line of new ones."""
    changed = parse_added_lines(_git(root, ["diff", "-U0", "--no-color", "--no-ext-diff", "HEAD", "--", "*.py"]))
    for relative in _git(root, ["ls-files", "--others", "--exclude-standard", "--", "*.py"]).splitlines():
        path = root / relative
        try:
            count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
        changed[relative] = set(range(1, count + 1))
    return {
        relative: lines for relative, lines in changed.items()
        if lines and relative.endswith(".py") and not _TEST_FILE.search(relative.replace("\\", "/"))
    }


def statement_start_lines(source: str, lines: Iterable[int]) -> Dict[int, int]:
    """Maps each executable changed line to the first line of its statement."""
    tree = ast.parse(source)
    spans: List[Tuple[int, int, int]] = []  # (first, last, statement start)
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # docstrings and bare strings are not executable lines
        end = getattr(node, "end_lineno", None) or node.lineno
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
            end = max(node.lineno, body[0].lineno - 1)  # only the header of a compound statement
        # coverage.py records a decorated definition at its first decorator line
        decorators = getattr(node, "decorator_list", None) or []
        start = min([node.lineno] + [decorator.lineno for decorator in decorators])
        spans.append((start, end, start))
    mapping: Dict[int, int] = {}
    for line in lines:
        owners = [span for span in spans if span[0] <= line <= span[1]]
        if owners:
            mapping[line] = max(owners)[2]  # the innermost statement starts last
    return mapping


# -- executed lines -----------------------------------------------------------------------


def decode_numbits(numbits: bytes) -> Set[int]:
    """coverage.py stores line sets as bitmaps: bit j of byte i means line 8*i + j."""
    return {index * 8 + bit for index, byte in enumerate(numbits) for bit in range(8) if byte & (1 << bit)}


def executed_lines(data_file: Path) -> Dict[str, Set[int]]:
    """Reads executed lines per absolute file path from a coverage.py data file."""
    if not data_file.is_file():
        raise ValueError("the test run produced no coverage data")
    connection = sqlite3.connect(f"{data_file.resolve().as_uri()}?mode=ro", uri=True)
    try:
        version = connection.execute("select version from coverage_schema").fetchone()
        if not version or version[0] not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported coverage data format (schema {version[0] if version else 'unknown'})")
        paths = dict(connection.execute("select id, path from file"))
        executed: Dict[str, Set[int]] = {}
        for file_id, numbits in connection.execute("select file_id, numbits from line_bits"):
            executed.setdefault(paths[file_id], set()).update(decode_numbits(numbits))
        for file_id, start, end in connection.execute("select file_id, fromno, tono from arc"):
            executed.setdefault(paths[file_id], set()).update(n for n in (start, end) if n > 0)
        return executed
    except sqlite3.Error as error:
        raise ValueError(f"unreadable coverage data: {error}") from error
    finally:
        connection.close()


def measure_changed_line_coverage(root: Path, data_file: Path) -> ChangedLineCoverage:
    """Compares the changed executable lines with what the test run executed."""
    try:
        changed = changed_python_lines(root)
        executed_by_path = executed_lines(data_file)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        return not_measured(str(error))
    executed = {os.path.normcase(os.path.realpath(path)): lines for path, lines in executed_by_path.items()}
    result = ChangedLineCoverage(measured=True)
    for relative, lines in sorted(changed.items()):
        path = root / relative
        try:
            starts = statement_start_lines(path.read_text(encoding="utf-8", errors="replace"), lines)
        except (OSError, SyntaxError, ValueError):
            continue  # the syntax gate reports unparsable files separately
        ran = executed.get(os.path.normcase(os.path.realpath(path)), set())
        missing = sorted(line for line, start in starts.items() if start not in ran)
        result.total += len(starts)
        result.covered += len(starts) - len(missing)
        if missing:
            result.uncovered[relative.replace("\\", "/")] = missing[:MAX_LISTED_UNCOVERED]
    return result
