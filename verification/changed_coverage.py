"""
Changed-line coverage for the completion gate (roadmap item C3).

The gate wraps the project's own test command with that ecosystem's coverage tool, then reports
which changed, executable, non-test lines the tests ran. One adapter per ecosystem:

| Ecosystem | Test command shapes | Coverage tool | Report read |
|---|---|---|---|
| Python | `<python> -m pytest ...`, `pytest ...` | coverage.py 6.3+ in the project's virtualenv | SQLite data file |
| Go | `go test ...` | built in (`-coverprofile`, `-coverpkg=./...`) | cover profile |
| JavaScript / TypeScript | `npm/pnpm/yarn/bun test`, `npx ...` | c8 in `node_modules/.bin` | LCOV |
| Rust | `cargo test ...` | cargo-llvm-cov on PATH | LCOV |

Design decisions:
- Tools are found from installed files only; nothing from the project runs before the user
  approves the exact, wrapped test command.
- Reports go to a fixed directory per workspace under ``BUZZARD_HOME/coverage/``, outside the
  repository: they never appear as changed files, and the command text stays the same across
  runs, so "allow for session" keeps matching. Old reports are removed before each run.
- Python executable lines come from ``ast`` (a changed line maps to the first line of its
  statement; decorated definitions map to the first decorator, as coverage.py records them).
  For Go, a changed line is executable when it lies inside a coverage block; for LCOV, when the
  tool instrumented it (has a ``DA`` record).
- Changed files that the report does not mention are listed as unmeasured, not counted as
  uncovered or covered.
- Anything that cannot be measured is reported as ``measured: False`` with a reason; nothing
  is estimated. Docker test runs are not measured: the coverage tool would have to exist inside
  the container image, which the gate cannot confirm.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

COVERAGE_SETTINGS = ("auto", "off")
MIN_COVERAGE_VERSION = (6, 3)  # first coverage.py release with `coverage run --data-file`
SUPPORTED_SCHEMA_VERSIONS = {7}
MAX_LISTED_UNCOVERED = 40
MAX_LISTED_UNMEASURED = 20

_PYTEST_COMMAND = re.compile(r'^(?P<python>"[^"]+"|\S+)\s+-m\s+pytest(?P<rest>(\s.*)?)$')
_BARE_PYTEST = re.compile(r"^pytest(?P<rest>(\s.*)?)$")
_GO_TEST = re.compile(r"^go\s+test(?P<rest>(\s.*)?)$")
_CARGO_TEST = re.compile(r"^cargo\s+test(?P<rest>(\s.*)?)$")
_NODE_TEST = re.compile(r"^(npm|pnpm|yarn|bun)(\s+run)?\s+test(\s.*)?$|^npx\s+\S+")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
_GO_BLOCK = re.compile(r"^(?P<file>.+):(?P<start>\d+)\.\d+,(?P<end>\d+)\.\d+ \d+ (?P<count>\d+)$")

_TEST_FILE = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)")
_GO_TEST_FILE = re.compile(r"_test\.go$")
_JS_TEST_FILE = re.compile(r"(^|/)(__tests__/|tests?/)|\.(test|spec)\.[cm]?[jt]sx?$")
_RUST_TEST_FILE = re.compile(r"(^|/)(tests|benches|examples)/")

JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


@dataclass
class ChangedLineCoverage:
    """What the tests executed of the changed, executable, non-test lines."""

    measured: bool
    reason: str = ""
    tool: str = "coverage.py"
    covered: int = 0
    total: int = 0
    uncovered: Dict[str, List[int]] = field(default_factory=dict)
    unmeasured_files: List[str] = field(default_factory=list)

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
            text = "no executable non-test lines changed"
        else:
            text = f"{self.covered}/{self.total} changed lines run by tests ({self.percent}%)"
            missing = [f"{path}:{', '.join(map(str, lines))}" for path, lines in sorted(self.uncovered.items())]
            if missing:
                text += "; not run: " + "; ".join(missing)
        if self.unmeasured_files:
            text += "; not in the coverage report: " + ", ".join(self.unmeasured_files)
        return text


def not_measured(reason: str, tool: str = "coverage.py") -> ChangedLineCoverage:
    return ChangedLineCoverage(measured=False, reason=reason, tool=tool)


@dataclass
class CoveragePlan:
    """The command to approve and run, and how to read its coverage afterwards."""

    command: str
    pending: ChangedLineCoverage
    collect: Optional[Callable[[], ChangedLineCoverage]] = None

    def result(self) -> ChangedLineCoverage:
        return self.collect() if self.collect is not None else self.pending


# -- settings and locations ------------------------------------------------------------


def coverage_setting(settings: Dict[str, object]) -> Tuple[Optional[str], Optional[str]]:
    """Returns (setting, error). The project setting `coverage` is "auto" (default) or "off"."""
    value = settings.get("coverage", "auto")
    if value not in COVERAGE_SETTINGS:
        return None, f'coverage must be "auto" or "off" in .buzzard/project.json, not {value!r}'
    return str(value), None


def coverage_directory(workspace: Path) -> Path:
    """A fixed directory per workspace under BUZZARD_HOME, outside the repository."""
    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:16]
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard")
    return base / "coverage" / key


def coverage_data_path(workspace: Path) -> Path:
    return coverage_directory(workspace) / "coverage-data"


def _fresh(path: Path) -> None:
    """Removes a previous run's report so stale data is never read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


# -- changed lines -----------------------------------------------------------------------


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


def changed_lines(root: Path, extensions: Tuple[str, ...], is_test: Callable[[str], bool]) -> Dict[str, Set[int]]:
    """Changed lines of non-test source files: modified tracked files plus every line of new ones."""
    patterns = [f"*{extension}" for extension in extensions]
    changed = parse_added_lines(_git(root, ["diff", "-U0", "--no-color", "--no-ext-diff", "HEAD", "--", *patterns]))
    for relative in _git(root, ["ls-files", "--others", "--exclude-standard", "--", *patterns]).splitlines():
        try:
            count = len((root / relative).read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
        changed[relative] = set(range(1, count + 1))
    return {
        relative.replace("\\", "/"): lines for relative, lines in changed.items()
        if lines and relative.endswith(extensions) and not is_test(relative.replace("\\", "/"))
    }


def changed_python_lines(root: Path) -> Dict[str, Set[int]]:
    return changed_lines(root, (".py",), lambda path: bool(_TEST_FILE.search(path)))


def _normalized(path: Path | str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _compare(
    root: Path,
    changed: Dict[str, Set[int]],
    report: Dict[str, Tuple[Set[int], Set[int]]],
    tool: str,
    executable_for: Optional[Callable[[str, Set[int]], Dict[int, int]]] = None,
) -> ChangedLineCoverage:
    """report maps a normalized absolute path to (executable lines, executed lines)."""
    result = ChangedLineCoverage(measured=True, tool=tool)
    for relative, lines in sorted(changed.items()):
        entry = report.get(_normalized(root / relative))
        if executable_for is not None:
            try:
                starts = executable_for(relative, lines)
            except (OSError, SyntaxError, ValueError):
                continue  # the syntax gate reports unparsable files separately
            ran = entry[1] if entry else set()
        else:
            if entry is None:
                if len(result.unmeasured_files) < MAX_LISTED_UNMEASURED:
                    result.unmeasured_files.append(relative)
                continue
            executable, ran = entry
            starts = {line: line for line in lines if line in executable}
        missing = sorted(line for line, start in starts.items() if start not in ran)
        result.total += len(starts)
        result.covered += len(starts) - len(missing)
        if missing:
            result.uncovered[relative] = missing[:MAX_LISTED_UNCOVERED]
    return result


# -- Python: coverage.py ---------------------------------------------------------------------


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


def wrap_pytest_command(command: str, data_file: Path, python: Optional[str] = None) -> Optional[str]:
    """Runs pytest under coverage. Bare `pytest` needs the project's interpreter passed as python."""
    text = command.strip()
    match = _PYTEST_COMMAND.match(text)
    if match:
        interpreter, rest = match["python"], match["rest"] or ""
    else:
        bare = _BARE_PYTEST.match(text)
        if not bare or not python:
            return None
        interpreter, rest = python, bare["rest"] or ""
    return f'{interpreter} -m coverage run --data-file="{data_file}" -m pytest{rest}'


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
    """Python: compares the changed executable lines with what coverage.py recorded."""
    try:
        changed = changed_python_lines(root)
        executed = {_normalized(path): (set(), lines) for path, lines in executed_lines(data_file).items()}
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        return not_measured(str(error))

    def executable_for(relative: str, lines: Set[int]) -> Dict[int, int]:
        return statement_start_lines((root / relative).read_text(encoding="utf-8", errors="replace"), lines)

    return _compare(root, changed, executed, "coverage.py", executable_for)


# -- Go: go test -coverprofile -----------------------------------------------------------------


def go_module_path(root: Path) -> Optional[str]:
    try:
        for line in (root / "go.mod").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("module "):
                return line.split(None, 1)[1].strip().strip('"')
    except OSError:
        return None
    return None


def parse_go_profile(text: str, root: Path, module: str) -> Dict[str, Tuple[Set[int], Set[int]]]:
    """Reads a Go cover profile into (executable, executed) lines per normalized absolute path."""
    report: Dict[str, Tuple[Set[int], Set[int]]] = {}
    for row in text.splitlines():
        match = _GO_BLOCK.match(row.strip())
        if not match:
            continue
        name = match["file"]
        if name.startswith(module + "/"):
            path = root / name[len(module) + 1:]
        elif os.path.isabs(name):
            path = Path(name)
        else:
            continue  # a package outside this module
        lines = set(range(int(match["start"]), int(match["end"]) + 1))
        executable, executed = report.setdefault(_normalized(path), (set(), set()))
        executable.update(lines)
        if int(match["count"]) > 0:
            executed.update(lines)
    return report


def wrap_go_command(command: str, profile: Path) -> Optional[str]:
    match = _GO_TEST.match(command.strip())
    if not match:
        return None
    return f'go test -coverprofile="{profile}" -coverpkg=./...{match["rest"] or ""}'


def measure_go(root: Path, profile: Path) -> ChangedLineCoverage:
    tool = "go test -cover"
    module = go_module_path(root)
    if not module:
        return not_measured("go.mod has no module line", tool)
    try:
        report = parse_go_profile(profile.read_text(encoding="utf-8", errors="replace"), root, module)
        changed = changed_lines(root, (".go",), lambda path: bool(_GO_TEST_FILE.search(path)))
    except FileNotFoundError:
        return not_measured("the test run produced no cover profile", tool)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        return not_measured(str(error), tool)
    return _compare(root, changed, report, tool)


# -- LCOV: c8 (JavaScript/TypeScript) and cargo-llvm-cov (Rust) ---------------------------------


def parse_lcov(text: str, root: Path) -> Dict[str, Tuple[Set[int], Set[int]]]:
    """Reads LCOV `SF`/`DA` records into (instrumented, executed) lines per normalized path."""
    report: Dict[str, Tuple[Set[int], Set[int]]] = {}
    current: Optional[Tuple[Set[int], Set[int]]] = None
    for row in text.splitlines():
        if row.startswith("SF:"):
            source = Path(row[3:].strip())
            current = report.setdefault(_normalized(source if source.is_absolute() else root / source), (set(), set()))
        elif row.startswith("DA:") and current is not None:
            fields = row[3:].split(",")
            try:
                line, hits = int(fields[0]), int(float(fields[1]))
            except (IndexError, ValueError):
                continue
            current[0].add(line)
            if hits > 0:
                current[1].add(line)
        elif row.startswith("end_of_record"):
            current = None
    return report


def _node_bin(workspace: Path, name: str) -> Optional[Path]:
    folder = workspace / "node_modules" / ".bin"
    for candidate in ((f"{name}.cmd", name) if os.name == "nt" else (name,)):
        if (folder / candidate).is_file():
            return folder / candidate
    return None


def wrap_c8_command(command: str, c8: Path, report_directory: Path) -> Optional[str]:
    if not _NODE_TEST.match(command.strip()):
        return None
    return (
        f'"{c8}" --all --reporter=lcovonly --reports-dir="{report_directory}" '
        f'--temp-directory="{report_directory / "raw"}" {command.strip()}'
    )


def wrap_cargo_command(command: str, lcov_file: Path) -> Optional[str]:
    match = _CARGO_TEST.match(command.strip())
    if not match:
        return None
    return f'cargo llvm-cov --lcov --output-path "{lcov_file}"{match["rest"] or ""}'


def measure_lcov(
    root: Path, lcov_file: Path, tool: str, extensions: Tuple[str, ...], is_test: Callable[[str], bool]
) -> ChangedLineCoverage:
    try:
        report = parse_lcov(lcov_file.read_text(encoding="utf-8", errors="replace"), root)
        changed = changed_lines(root, extensions, is_test)
    except FileNotFoundError:
        return not_measured("the test run produced no LCOV report", tool)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        return not_measured(str(error), tool)
    return _compare(root, changed, report, tool)


# -- planning ------------------------------------------------------------------------------


def plan_coverage(workspace: Path, command: str, runner: Optional[str], settings: Dict[str, object], python: str) -> CoveragePlan:
    """Chooses the adapter for the project's test command, or explains why coverage is not measured."""
    setting, problem = coverage_setting(settings)
    if problem:
        return CoveragePlan(command, not_measured(problem))
    if setting == "off":
        return CoveragePlan(command, not_measured("turned off in .buzzard/project.json"))
    directory = coverage_directory(workspace)
    text = command.strip()
    try:
        if _PYTEST_COMMAND.match(text) or _BARE_PYTEST.match(text):
            return _plan_python(workspace, text, python, directory)
        if _GO_TEST.match(text):
            profile = directory / "go-cover-profile"
            _fresh(profile)
            return CoveragePlan(
                wrap_go_command(text, profile) or text, not_measured("tests did not finish", "go test -cover"),
                lambda: measure_go(workspace, profile),
            )
        if _CARGO_TEST.match(text):
            tool = "cargo-llvm-cov"
            if shutil.which("cargo-llvm-cov") is None:
                return CoveragePlan(text, not_measured("cargo-llvm-cov is not installed (cargo install cargo-llvm-cov)", tool))
            lcov_file = directory / "rust-lcov"
            _fresh(lcov_file)
            return CoveragePlan(
                wrap_cargo_command(text, lcov_file) or text, not_measured("tests did not finish", tool),
                lambda: measure_lcov(workspace, lcov_file, tool, (".rs",), lambda path: bool(_RUST_TEST_FILE.search(path))),
            )
        if _NODE_TEST.match(text):
            tool = "c8"
            c8 = _node_bin(workspace, "c8")
            if c8 is None:
                return CoveragePlan(text, not_measured("c8 is not installed in node_modules (npm install --save-dev c8)", tool))
            report_directory = directory / "c8"
            _fresh(report_directory)
            return CoveragePlan(
                wrap_c8_command(text, c8, report_directory) or text, not_measured("tests did not finish", tool),
                lambda: measure_lcov(
                    workspace, report_directory / "lcov.info", tool, JS_EXTENSIONS,
                    lambda path: bool(_JS_TEST_FILE.search(path)),
                ),
            )
    except OSError as error:
        return CoveragePlan(command, not_measured(f"could not prepare the coverage output: {error}"))
    return CoveragePlan(command, not_measured(f"no coverage support for the test command `{text}`"))


def _plan_python(workspace: Path, command: str, python: str, directory: Path) -> CoveragePlan:
    version = installed_coverage_version(workspace, python)
    if version is None:
        return CoveragePlan(command, not_measured("coverage.py is not installed in the project's virtual environment"))
    if version < MIN_COVERAGE_VERSION:
        return CoveragePlan(command, not_measured("coverage.py 6.3 or newer is needed"))
    data_file = directory / "coverage-data"
    wrapped = wrap_pytest_command(command, data_file, python)
    if wrapped is None:
        return CoveragePlan(command, not_measured("could not find the project's Python interpreter"))
    _fresh(data_file)
    return CoveragePlan(wrapped, not_measured("tests did not finish"), lambda: measure_changed_line_coverage(workspace, data_file))
