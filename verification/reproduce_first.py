"""
Reproduce-first check for bug fixes (roadmap item C1), Python/pytest first.

A bug fix is proven when at least one test fails on the original code and passes with the fix.
After the gate's test run passes, this module checks out HEAD into a throwaway git worktree
outside the repository, copies in the current test files, runs the same pytest command there
with the project's interpreter, and compares JUnit XML results test by test.

Design decisions:
- Only real test failures (``<failure>``) on the original code count. Errors (``<error>``,
  such as import or collection problems) do not, so a broken environment cannot pass as proof.
- The comparison is per test id, so a test that fails before and passes after is the proof; the
  suite's exit codes alone are not used.
- The "before" command is shown to the user for approval like any other command.
- Mode is set by ``reproduce_first`` in ``.buzzard/project.json``: ``"warn"`` (default) records
  the result, ``"require"`` makes the gate reject an unreproduced bug fix, ``"off"`` skips it.
  The default does not block, because the check can miss a real reproduction (for example when
  the project is installed into its virtualenv in editable mode, so tests import the fixed code).
- Anything that cannot be checked is reported as ``not_checked`` with a reason; it never rejects.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

REPRODUCE_MODES = ("warn", "require", "off")
MAX_LISTED_TESTS = 20

_BUG_FIX_TASK = re.compile(
    r"\b(fix|fixes|fixing|bug|bugs|broken|crash|crashes|regression|incorrect|wrong|error|errors|fail|fails|failing)\b",
    re.IGNORECASE,
)
_PYTEST_MODULE = re.compile(r'^(?P<python>"[^"]+"|\S+)\s+-m\s+pytest(?P<rest>(\s.*)?)$')
_BARE_PYTEST = re.compile(r"^pytest(?P<rest>(\s.*)?)$")
_TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*$|[^/]*_test\.[a-z]+$|conftest\.py$|[^/]*\.(test|spec)\.[a-z]+$)")


@dataclass
class ReproductionResult:
    status: str  # "reproduced", "not_reproduced" or "not_checked"
    reason: str = ""
    reproduced_tests: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def not_checked(reason: str) -> ReproductionResult:
    return ReproductionResult(status="not_checked", reason=reason)


def is_bug_fix_task(goal: str) -> bool:
    return bool(_BUG_FIX_TASK.search(goal or ""))


def reproduce_mode(settings: Dict[str, object]) -> Tuple[Optional[str], Optional[str]]:
    value = settings.get("reproduce_first", "warn")
    if value not in REPRODUCE_MODES:
        return None, f'reproduce_first must be "warn", "require" or "off" in .buzzard/project.json, not {value!r}'
    return str(value), None


def check_directory(workspace: Path) -> Path:
    """Fixed per-workspace location under BUZZARD_HOME, outside the repository."""
    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:16]
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard")
    return base / "reproduce" / key


def split_pytest_command(command: str, python: str) -> Optional[Tuple[str, str]]:
    """Returns (interpreter, pytest arguments) for `<python> -m pytest ...` or bare `pytest ...`."""
    text = command.strip()
    match = _PYTEST_MODULE.match(text)
    if match:
        return match["python"], (match["rest"] or "")
    bare = _BARE_PYTEST.match(text)
    if bare and python:
        return python, (bare["rest"] or "")
    return None


def with_junit(command: str, junit_file: Path) -> str:
    """Adds a JUnit XML report to a pytest command; works inside a coverage wrapper too."""
    return f'{command.rstrip()} --junitxml="{junit_file}"'


def junit_results(xml_file: Path) -> Tuple[Set[str], Set[str]]:
    """Returns (failed, passed) test ids. Errors and skips are in neither set."""
    if not xml_file.is_file():
        raise ValueError("the test run wrote no JUnit report")
    try:
        root = ElementTree.parse(xml_file).getroot()
    except ElementTree.ParseError as error:
        raise ValueError(f"unreadable JUnit report: {error}") from error
    failed: Set[str] = set()
    passed: Set[str] = set()
    for case in root.iter("testcase"):
        test_id = f'{case.get("classname", "")}::{case.get("name", "")}'
        kinds = {child.tag for child in case}
        if "failure" in kinds:
            failed.add(test_id)
        elif not kinds & {"error", "skipped"}:
            passed.add(test_id)
    return failed, passed


def changed_test_files(root: Path) -> List[str]:
    """Test files that differ from HEAD (modified or new), relative to the repository."""
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
    return sorted(path for path in paths if _TEST_PATH.search(path.replace("\\", "/")) and (root / path).is_file())


class BaseCheckout:
    """A detached git worktree of HEAD outside the repository, removed on exit."""

    def __init__(self, root: Path, path: Path):
        self.root = root
        self.path = path

    def __enter__(self) -> "BaseCheckout":
        self._remove()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "-C", str(self.root), "worktree", "add", "--detach", "--force", str(self.path), "HEAD"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError(f"could not check out the original code: {result.stderr.strip()[:200]}")
        return self

    def copy_in(self, relative_paths: List[str]) -> None:
        for relative in relative_paths:
            target = self.path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.root / relative, target)

    def _remove(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "worktree", "remove", "--force", str(self.path)],
            capture_output=True, timeout=120, check=False, stdin=subprocess.DEVNULL,
        )
        if self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        subprocess.run(["git", "-C", str(self.root), "worktree", "prune"], capture_output=True,
                       timeout=60, check=False, stdin=subprocess.DEVNULL)

    def __exit__(self, *exc_info: object) -> None:
        self._remove()


def check_reproduction(
    root: Path,
    pytest_command: str,
    python: str,
    after_junit: Path,
    approve: Optional[Callable[[str], bool]],
    run_in: Callable[[Path, str], int],
) -> ReproductionResult:
    """
    Runs the tests on the original code and compares them with the fixed run's JUnit report.
    run_in(directory, command) runs a command in a directory and returns its exit code.
    """
    split = split_pytest_command(pytest_command, python)
    if split is None:
        return not_checked("only pytest test commands are checked so far")
    interpreter, arguments = split
    interpreter = interpreter.strip('"')
    interpreter_path = Path(interpreter)
    if not interpreter_path.is_absolute() and (root / interpreter_path).exists():
        interpreter = str((root / interpreter_path).resolve())  # the checkout has no virtualenv
    try:
        failed_after, passed_after = junit_results(after_junit)
    except ValueError as error:
        return not_checked(str(error))
    directory = check_directory(root)
    base_junit = directory / "before-junit"
    try:
        if base_junit.exists():
            base_junit.unlink()
        tests = changed_test_files(root)
        before_command = with_junit(f'"{interpreter}" -m pytest{arguments}', base_junit)
        if approve is not None and not approve(before_command):
            return not_checked("running the tests on the original code was not approved")
        with BaseCheckout(root, directory / "checkout") as checkout:
            checkout.copy_in(tests)
            run_in(checkout.path, before_command)
        failed_before, _ = junit_results(base_junit)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        return not_checked(str(error))
    proof = sorted(failed_before & passed_after)
    if proof:
        return ReproductionResult("reproduced", reproduced_tests=proof[:MAX_LISTED_TESTS])
    if failed_after:
        return not_checked("some tests still fail after the fix")
    return ReproductionResult(
        "not_reproduced",
        reason="no test failed on the original code and passed with the fix",
    )
