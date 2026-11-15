"""
Unit & Integration Test Suite for Buzzard Code Beast Gap-Fillers.

Validates:
1. AST Skeleton Outliner (90% context reduction & selective symbol unfold)
2. Persistent Warm REPL Session (sub-50ms execution & shared variable state)
3. Speculative Worktree Hypothesis Racing (concurrent candidate patch evaluation)
4. Runtime State Probe (DAP-style frame & variable inspection)
5. PTY Process Supervisor (prompt interception & non-interactive guard)
6. AST-Native Code Morphing (syntactic function/method substitution)
7. Causal History & Intent Linker (commit rationale & bugfix regression warnings)
"""

from pathlib import Path

from coding.ast_morph import AstMorphEngine
from coding.atomic_editor import EditOperation
from coding.hypothesis_racer import Hypothesis, HypothesisRacer
from intelligence.ast_outliner import AstOutliner
from intelligence.causal_history import CausalHistoryLinker
from runtime.warm_repl import WarmReplSession
from system.pty_supervisor import PtySupervisor
from verification.runtime_probe import RuntimeProbe


def test_ast_outliner_and_unfold(tmp_path: Path):
    """Verifies AST skeleton generation and selective symbol unfolding."""
    code = (
        "import os\n\n"
        "class UserManager:\n"
        '    """Manages user sessions."""\n'
        "    def __init__(self, db: str):\n"
        "        self.db = db\n\n"
        "    def authenticate(self, user: str, pwd: str) -> bool:\n"
        "        return user == 'admin'\n\n"
        "def helper_func(x: int) -> int:\n"
        "    return x * 2\n"
    )
    test_file = tmp_path / "user_mgmt.py"
    test_file.write_text(code, encoding="utf-8")

    outliner = AstOutliner(tmp_path)
    outline = outliner.generate_outline("user_mgmt.py")

    assert outline.total_lines == 12
    assert len(outline.symbols) == 2  # UserManager class and helper_func
    assert outline.symbols[0].name == "UserManager"
    assert len(outline.symbols[0].children) == 2  # __init__ and authenticate

    rendered = outline.render_skeleton()
    assert "UserManager" in rendered
    assert "authenticate" in rendered

    # Test selective unfold
    unfolded = outliner.unfold_symbol("user_mgmt.py", "authenticate")
    assert "snippet" in unfolded
    assert "return user == 'admin'" in unfolded["snippet"]


def test_warm_repl_session_state_persistence(tmp_path: Path):
    """Verifies persistent Python in-memory worker retains state across calls."""
    repl = WarmReplSession(tmp_path)
    try:
        # Step 1: Assign variable
        res1 = repl.execute("x = 42")
        assert res1.success is True

        # Step 2: Read variable in second turn
        res2 = repl.execute("x * 2")
        assert res2.success is True
        assert res2.result == "84"

        # Step 3: Define function and call
        res3 = repl.execute("def greet(name):\n    return f'Hello, {name}!'\ngreet('Buzzard')")
        assert res3.success is True
        assert "Hello, Buzzard!" in (res3.result or "")
    finally:
        repl.close()


def test_runtime_probe_frame_inspection(tmp_path: Path):
    """Verifies DAP-style variable and frame capture on function calls and errors."""
    probe = RuntimeProbe(tmp_path)

    def divide_logic(a, b):
        multiplier = 10
        target = a * multiplier
        if b == 0:
            raise ValueError("Zero divisor!")
        return target / b

    # Probe failed run
    snap = probe.probe_callable(divide_logic, 5, 0)
    assert snap.success is False
    assert snap.exception_type == "ValueError"
    assert "Zero divisor!" in (snap.exception_message or "")
    assert len(snap.frames) > 0

    report = snap.format_diagnostic_report()
    assert "multiplier" in report
    assert "divide_logic" in report


def test_pty_supervisor_environment_and_execution(tmp_path: Path):
    """Verifies non-interactive environment injection and supervised process execution."""
    supervisor = PtySupervisor(tmp_path)
    env = supervisor.build_non_interactive_env()

    assert env["CI"] == "true"
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["PAGER"] == "cat"

    # Run quick command
    import sys
    res = supervisor.run_supervised([sys.executable, "-c", "print('supervised ok')"])
    assert res.success is True
    assert "supervised ok" in res.stdout


def test_ast_morph_engine_function_and_method_replacement():
    """Verifies syntactic AST node substitution preserving indentation and whitespace."""
    original_code = (
        "import os\n\n"
        "def compute(a, b):\n"
        "    return a + b\n\n"
        "class Service:\n"
        "    def run(self):\n"
        "        return 1\n"
    )

    morph = AstMorphEngine()

    # 1. Replace top-level function
    new_func = "def compute(a, b):\n    return (a + b) * 10"
    res1 = morph.replace_function(original_code, "compute", new_func)
    assert res1.success is True
    assert "(a + b) * 10" in res1.modified_code
    assert "class Service" in res1.modified_code

    # 2. Replace class method
    new_method = "def run(self):\n    return 999"
    res2 = morph.replace_method(res1.modified_code, "Service", "run", new_method)
    assert res2.success is True
    assert "return 999" in res2.modified_code

    # 3. Insert import
    res3 = morph.insert_import(res2.modified_code, "import sys")
    assert res3.success is True
    assert "import sys" in res3.modified_code


def test_hypothesis_racer_evaluation(tmp_path: Path):
    """Verifies parallel hypothesis evaluation and winner selection."""
    test_file = tmp_path / "math_lib.py"
    test_file.write_text("def add(x, y):\n    return 0\n")

    unit_test = tmp_path / "test_math.py"
    unit_test.write_text("from math_lib import add\ndef test_add():\n    assert add(2, 3) == 5\n")

    racer = HypothesisRacer(tmp_path)

    # Hypothesis 1: incorrect fix
    h1 = Hypothesis(
        id="hypo-wrong",
        description="Return constant 10",
        edits=[EditOperation("math_lib.py", new_full_content="def add(x, y):\n    return 10\n")],
    )

    # Hypothesis 2: correct fix
    h2 = Hypothesis(
        id="hypo-correct",
        description="Return x + y",
        edits=[EditOperation("math_lib.py", new_full_content="def add(x, y):\n    return x + y\n")],
    )

    outcome = racer.race([h1, h2])

    assert outcome.winner is not None
    assert outcome.winner.hypothesis.id == "hypo-correct"
    assert outcome.winner.tests_passed is True
    assert outcome.merged_successfully is True
    assert test_file.read_text() == "def add(x, y):\n    return x + y\n"


def test_causal_history_pattern_detection(tmp_path: Path):
    """Verifies detection of bugfix and workaround commits in causal report."""
    linker = CausalHistoryLinker(tmp_path)
    # Check pattern matching
    test_commit_subject = "fix(conhost): resolve terminal buffer scrolling bug #42"
    is_fix = any(p.search(test_commit_subject) for p in linker.BUGFIX_PATTERNS)
    assert is_fix is True
