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
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

from verification.changed_coverage import JS_EXTENSIONS, _GO_TEST_FILE, _JS_TEST_FILE, _RUST_TEST_FILE, changed_lines
from verification.changed_coverage import changed_python_lines
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


# Text mutations for JavaScript, TypeScript and Go: (pattern, replacement for each matched text).
# Spaced forms for < > + - avoid generics, arrows, ++ and unary minus.
_TEXT_SWAPS = {
    "===": "!==", "!==": "===", "==": "!=", "!=": "==", " <= ": " > ", " >= ": " < ", " < ": " >= ",
    " > ": " <= ", "&&": "||", "||": "&&", " + ": " - ", " - ": " + ", "true": "false", "false": "true",
}
_TEXT_OPERATOR = re.compile(
    r"(?<![=!<>])(===|!==|==|!=)(?![=])|( <= | >= | < | > | \+ | - )|(&&|\|\|)|\b(true|false)\b"
)
TEXT_EXTENSIONS = (*JS_EXTENSIONS, ".go", ".rs")


def _code_spans(line: str) -> List[Tuple[int, int]]:
    """Index ranges of a line that are code: outside string literals and before a // comment."""
    spans, start, quote, index = [], 0, "", 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote, start = "", index + 1
        elif char in "\"'`":
            spans.append((start, index))
            quote = char
        elif line.startswith("//", index):
            spans.append((start, index))
            return spans
        index += 1
    if not quote:
        spans.append((start, len(line)))
    return spans


def generate_text_mutants(relative_path: str, source: str, lines: Set[int], limit: int) -> List[Mutant]:
    """Operator swaps on changed lines of JavaScript, TypeScript or Go, outside strings and comments."""
    source_lines = source.splitlines(keepends=True)
    found: List[Tuple[int, int, int, str, str]] = []  # line, start, end, old, new
    for number in sorted(lines):
        if not 1 <= number <= len(source_lines):
            continue
        text = source_lines[number - 1]
        if text.lstrip().startswith(("//", "/*", "*", "import ", "package ")):
            continue
        for begin, end in _code_spans(text):
            for match in _TEXT_OPERATOR.finditer(text, begin, end):
                old = match.group(0)
                found.append((number, match.start(), match.end(), old, _TEXT_SWAPS[old]))
    seen: Set[int] = set()
    first, rest = [], []
    for item in found:
        (first if item[0] not in seen else rest).append(item)
        seen.add(item[0])
    mutants = []
    for number, start, end, old, new in (first + rest)[:limit]:
        mutated = list(source_lines)
        line = mutated[number - 1]
        mutated[number - 1] = line[:start] + new + line[end:]
        mutants.append(Mutant(relative_path, number, f"`{old.strip()}` -> `{new.strip()}`", "".join(mutated)))
    return mutants


def changed_source_lines(root: Path) -> Dict[str, Set[int]]:
    """Changed non-test lines of every language the mutation check can mutate."""
    lines = dict(changed_python_lines(root))
    lines.update(changed_lines(root, JS_EXTENSIONS, lambda path: bool(_JS_TEST_FILE.search(path))))
    lines.update(changed_lines(root, (".go",), lambda path: bool(_GO_TEST_FILE.search(path))))
    lines.update(changed_lines(root, (".rs",), lambda path: bool(_RUST_TEST_FILE.search(path))))
    return lines


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
    workers: int = 1,
) -> MutationResult:
    """
    Runs the tests once per mutant in checkouts of HEAD plus the current changes.
    run_in(directory, command) runs a command and returns its exit code.
    workers: bounded parallelism (1-4) across mutant evaluations.
    """
    mutants: List[Mutant] = []
    for relative, lines in sorted(changed_lines.items()):
        if not relative.endswith((".py", *TEXT_EXTENSIONS)) or len(mutants) >= limit:
            continue
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        generate = generate_mutants if relative.endswith(".py") else generate_text_mutants
        mutants.extend(generate(relative, source, lines, limit - len(mutants)))
    if not mutants:
        return not_checked("no changed Python, JavaScript, TypeScript, Go or Rust line has anything to mutate")
    command = _checkout_command(root, test_command, python)
    if approve is not None and not approve(command):
        return not_checked("running the tests on mutated code was not approved")
    result = MutationResult(status="checked", mutants=len(mutants))

    workers = max(1, min(workers, len(mutants), 4))
    if workers == 1:
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

    import queue
    from concurrent.futures import ThreadPoolExecutor

    try:
        checkouts: List[BaseCheckout] = []
        present = [path for path in changed_files if (root / path).is_file()]
        for i in range(workers):
            co = BaseCheckout(root, mutation_directory(root) / f"checkout_{i}")
            co.__enter__()
            checkouts.append(co)
            co.copy_in(present)
            for path in changed_files:
                if not (root / path).exists():
                    (co.path / path).unlink(missing_ok=True)
            if run_in(co.path, command) != 0:
                for c in checkouts:
                    c.__exit__(None, None, None)
                return not_checked("the tests do not pass in a clean checkout of the changes")

        checkout_queue: "queue.Queue[BaseCheckout]" = queue.Queue()
        for co in checkouts:
            checkout_queue.put(co)

        def run_single_mutant(m: Mutant) -> Tuple[bool, Mutant]:
            co = checkout_queue.get()
            try:
                target = co.path / m.path
                original = target.read_bytes()
                try:
                    target.write_text(m.source, encoding="utf-8")
                    caught = run_in(co.path, command) != 0
                finally:
                    target.write_bytes(original)
                return (caught, m)
            finally:
                checkout_queue.put(co)

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for caught, m in executor.map(run_single_mutant, mutants):
                    if caught:
                        result.killed += 1
                    else:
                        result.survived.append({"path": m.path, "line": m.line, "change": m.description})
        finally:
            for c in checkouts:
                c.__exit__(None, None, None)

    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        return not_checked(str(error))

    return result
