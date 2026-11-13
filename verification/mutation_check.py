"""
Mutation check for changed code (roadmap C5).

Passing tests prove little if they would also pass with the change broken. This check makes
one small change at a time to the changed Python lines (flip a comparison, swap + and -, and
and or, True and False, add 1 to a number, drop a `not`) and runs the tests on each mutant.
A mutant that no test catches ("survived") is a line the tests do not really check.

It runs in a detached checkout of HEAD with the current changes copied in, outside the
repository, so the user's files are never modified. It is off by default because it runs the
test suite once per mutant: set "mutation_check" to "warn" or "require" in
.buzzard/project.json, and "mutation_max" (1-30, default 10) to bound the cost.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

from verification.reproduce_first import BaseCheckout, split_pytest_command

MUTATION_MODES = ("off", "warn", "require")
DEFAULT_MAX_MUTANTS = 10
MAX_MUTANTS_LIMIT = 30

_COMPARE_SWAPS = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE,
    ast.LtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In,
}
_BINARY_SWAPS = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.Div: ast.Mult, ast.FloorDiv: ast.Mult}
_SYMBOLS = {
    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.GtE: ">=", ast.Gt: ">", ast.LtE: "<=", ast.Is: "is",
    ast.IsNot: "is not", ast.In: "in", ast.NotIn: "not in", ast.Add: "+", ast.Sub: "-", ast.Mult: "*",
    ast.Div: "/", ast.FloorDiv: "//", ast.And: "and", ast.Or: "or",
}


@dataclass
class Mutant:
    path: str
    line: int
    description: str
    source: str = field(repr=False, default="")


@dataclass
class MutationResult:
    status: str  # "checked" or "not_checked"
    reason: str = ""
    mutants: int = 0
    killed: int = 0
    survived: List[Dict[str, object]] = field(default_factory=list)

    @property
    def score(self) -> Optional[int]:
        return round(100 * self.killed / self.mutants) if self.mutants else None

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["score"] = self.score
        return data


def not_checked(reason: str) -> MutationResult:
    return MutationResult(status="not_checked", reason=reason)


def mutation_settings(settings: Dict[str, object]) -> Tuple[Optional[str], int, Optional[str]]:
    """Returns (mode, max mutants, problem). An invalid setting is a problem, never a silent default."""
    mode = settings.get("mutation_check", "off")
    if mode not in MUTATION_MODES:
        return None, 0, f'mutation_check must be "off", "warn" or "require" in .buzzard/project.json, not {mode!r}'
    limit = settings.get("mutation_max", DEFAULT_MAX_MUTANTS)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_MUTANTS_LIMIT:
        return None, 0, f"mutation_max must be a whole number from 1 to {MAX_MUTANTS_LIMIT}, not {limit!r}"
    return str(mode), limit, None


def _candidates(tree: ast.AST, lines: Set[int]) -> Iterator[Tuple[int, str, Callable[[ast.AST], None]]]:
    """(line, description, mutate) for each mutation point on a changed line, in source order."""
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line not in lines:
            continue
        if isinstance(node, ast.Compare) and type(node.ops[0]) in _COMPARE_SWAPS:
            old = type(node.ops[0])
            yield line, f"`{_SYMBOLS[old]}` -> `{_SYMBOLS[_COMPARE_SWAPS[old]]}`", \
                lambda n, new=_COMPARE_SWAPS[old]: n.ops.__setitem__(0, new())
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINARY_SWAPS:
            old = type(node.op)
            yield line, f"`{_SYMBOLS[old]}` -> `{_SYMBOLS[_BINARY_SWAPS[old]]}`", \
                lambda n, new=_BINARY_SWAPS[old]: setattr(n, "op", new())
        elif isinstance(node, ast.BoolOp):
            old = type(node.op)
            new_op = ast.Or if old is ast.And else ast.And
            yield line, f"`{_SYMBOLS[old]}` -> `{_SYMBOLS[new_op]}`", lambda n, new=new_op: setattr(n, "op", new())
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            yield line, f"`{node.value}` -> `{not node.value}`", lambda n: setattr(n, "value", not n.value)
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            yield line, f"`{node.value}` -> `{node.value + 1}`", lambda n: setattr(n, "value", n.value + 1)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield line, "removed `not`", None  # handled in generate_mutants: replaces the node


def generate_mutants(relative_path: str, source: str, lines: Set[int], limit: int) -> List[Mutant]:
    """Mutants of one file, at most `limit`, spread over the changed lines (one per line first)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    found = list(enumerate(_candidates(tree, lines)))
    # Prefer one mutant per line before a second on the same line, so a small budget covers more lines
    seen_lines: Set[int] = set()
    first, rest = [], []
    for item in found:
        (first if item[1][0] not in seen_lines else rest).append(item)
        seen_lines.add(item[1][0])
    mutants = []
    for index, (line, description, mutate) in first + rest:
        if len(mutants) >= limit:
            break
        mutated = copy.deepcopy(tree)
        target = _nth_candidate_node(mutated, lines, index)
        if target is None:
            continue
        if mutate is None:  # `not x` -> `x`
            parent = _parent_of(mutated, target)
            if parent is None:
                continue
            _replace_child(parent, target, target.operand)
        else:
            mutate(target)
        try:
            mutants.append(Mutant(relative_path, line, description, ast.unparse(ast.fix_missing_locations(mutated))))
        except (ValueError, TypeError, RecursionError):
            continue
    return mutants


def _nth_candidate_node(tree: ast.AST, lines: Set[int], index: int) -> Optional[ast.AST]:
    count = -1
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line not in lines:
            continue
        if (
            (isinstance(node, ast.Compare) and type(node.ops[0]) in _COMPARE_SWAPS)
            or (isinstance(node, ast.BinOp) and type(node.op) in _BINARY_SWAPS)
            or isinstance(node, ast.BoolOp)
            or (isinstance(node, ast.Constant) and (isinstance(node.value, bool) or type(node.value) is int))
            or (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not))
        ):
            count += 1
            if count == index:
                return node
    return None


def _parent_of(tree: ast.AST, child: ast.AST) -> Optional[ast.AST]:
    for node in ast.walk(tree):
        for value in ast.iter_child_nodes(node):
            if value is child:
                return node
    return None


def _replace_child(parent: ast.AST, old: ast.AST, new: ast.AST) -> None:
    for name, value in ast.iter_fields(parent):
        if value is old:
            setattr(parent, name, new)
            return
        if isinstance(value, list):
            for position, item in enumerate(value):
                if item is old:
                    value[position] = new
                    return


def mutation_directory(workspace: Path) -> Path:
    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:16]
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard")
    return base / "mutation" / key


def _checkout_command(root: Path, command: str, python: str) -> str:
    """The test command for the checkout: a relative virtualenv interpreter becomes absolute (the checkout has none)."""
    split = split_pytest_command(command, python)
    if split is None:
        return command
    interpreter, arguments = split
    path = Path(interpreter.strip('"'))
    if not path.is_absolute() and (root / path).exists():
        return f'"{(root / path).resolve()}" -m pytest{arguments}'
    return command


def check_mutations(
    root: Path,
    test_command: str,
    python: str,
    changed_lines: Dict[str, Set[int]],
    changed_files: List[str],
    limit: int,
    approve: Optional[Callable[[str], bool]],
    run_in: Callable[[Path, str], int],
) -> MutationResult:
    """
    Runs the tests once per mutant in a checkout of HEAD plus the current changes.
    run_in(directory, command) runs a command and returns its exit code.
    """
    mutants: List[Mutant] = []
    for relative, lines in sorted(changed_lines.items()):
        if not relative.endswith(".py") or len(mutants) >= limit:
            continue
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        mutants.extend(generate_mutants(relative, source, lines, limit - len(mutants)))
    if not mutants:
        return not_checked("no changed Python line has anything to mutate")
    command = _checkout_command(root, test_command, python)
    if approve is not None and not approve(command):
        return not_checked("running the tests on mutated code was not approved")
    result = MutationResult(status="checked", mutants=len(mutants))
    try:
        with BaseCheckout(root, mutation_directory(root) / "checkout") as checkout:
            present = [path for path in changed_files if (root / path).is_file()]
            checkout.copy_in(present)
            for path in changed_files:
                if not (root / path).exists():
                    (checkout.path / path).unlink(missing_ok=True)  # deleted in the working tree
            if run_in(checkout.path, command) != 0:
                return not_checked("the tests do not pass in a clean checkout of the changes")
            for mutant in mutants:
                target = checkout.path / mutant.path
                original = target.read_bytes()
                try:
                    target.write_text(mutant.source, encoding="utf-8")
                    caught = run_in(checkout.path, command) != 0
                finally:
                    target.write_bytes(original)
                if caught:
                    result.killed += 1
                else:
                    result.survived.append({"path": mutant.path, "line": mutant.line, "change": mutant.description})
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        return not_checked(str(error))
    return result
