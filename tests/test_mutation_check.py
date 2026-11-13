"""Tests for the optional mutation check of changed lines (roadmap C5)."""

import json
import shutil
import subprocess
import sys

import pytest

from verification.coding_verifier import CodingVerifier
from verification.evidence_report import build_evidence_report
from verification.mutation_check import generate_mutants, mutation_settings


@pytest.mark.parametrize("settings, expected", [
    ({}, ("off", 10, None)),
    ({"mutation_check": "warn", "mutation_max": 3}, ("warn", 3, None)),
    ({"mutation_check": "require"}, ("require", 10, None)),
])
def test_valid_settings(settings, expected):
    assert mutation_settings(settings) == expected


@pytest.mark.parametrize("settings", [
    {"mutation_check": "yes"}, {"mutation_check": "warn", "mutation_max": 0},
    {"mutation_check": "warn", "mutation_max": 31}, {"mutation_check": "warn", "mutation_max": True},
    {"mutation_check": "warn", "mutation_max": "5"},
])
def test_invalid_settings_are_reported(settings):
    mode, _, problem = mutation_settings(settings)
    assert mode is None and problem


SOURCE = """def check(a, b, items):
    if a == b and not items:
        return a + 1
    return a > b or True
"""


def test_each_operator_is_mutated_and_only_on_changed_lines():
    mutants = generate_mutants("m.py", SOURCE, {2, 3, 4}, limit=30)
    changes = {(m.line, m.description) for m in mutants}
    assert (2, "`==` -> `!=`") in changes and (2, "`and` -> `or`") in changes and (2, "removed `not`") in changes
    assert (3, "`+` -> `-`") in changes and (3, "`1` -> `2`") in changes
    assert (4, "`>` -> `<=`") in changes and (4, "`True` -> `False`") in changes and (4, "`or` -> `and`") in changes
    by_change = {m.description: m.source for m in mutants}
    assert "a != b" in by_change["`==` -> `!=`"] and "if a == b and items" in by_change["removed `not`"]
    assert generate_mutants("m.py", SOURCE, {1}, limit=30) == []  # the def line has nothing to mutate
    for mutant in mutants:
        compile(mutant.source, "m.py", "exec")  # every mutant is valid Python


def test_a_small_budget_covers_different_lines_first():
    mutants = generate_mutants("m.py", SOURCE, {2, 3, 4}, limit=3)
    assert sorted(m.line for m in mutants) == [2, 3, 4]


def test_unparseable_source_gives_no_mutants():
    assert generate_mutants("m.py", "def broken(:\n", {1}, limit=5) == []


# -- end to end through the completion gate ----------------------------------------------------

@pytest.fixture
def repo(tmp_path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    root = tmp_path / "shop"
    root.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@t")
    git("config", "user.name", "T")
    (root / "calc.py").write_text("def add(a, b):\n    return a - b\n\n\ndef is_big(x):\n    return False\n", encoding="utf-8")
    (root / "test_calc.py").write_text("from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "start")
    # The change: add is fixed (and tested); is_big is new logic that no test checks
    (root / "calc.py").write_text("def add(a, b):\n    return a + b\n\n\ndef is_big(x):\n    return x > 10\n", encoding="utf-8")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    return root


def configure(root, **settings):
    (root / ".buzzard").mkdir(exist_ok=True)
    (root / ".buzzard" / "project.json").write_text(json.dumps({
        "test_command": f'"{sys.executable}" -m pytest -q -p no:cacheprovider', "coverage": "off",
        "reproduce_first": "off", **settings}), encoding="utf-8")


def test_warn_reports_the_untested_line_and_leaves_files_alone(repo):
    configure(repo, mutation_check="warn")
    before = (repo / "calc.py").read_bytes()
    result = CodingVerifier(workspace=str(repo)).verify_task("Fix the add function in calc.py")
    assert result.passed, result.message
    mutation = result.mutation
    assert mutation["status"] == "checked" and mutation["mutants"] == 3
    assert mutation["killed"] == 1  # `+` -> `-` breaks test_add
    assert {item["line"] for item in mutation["survived"]} == {6}  # `>` and `10` on is_big's line
    assert (repo / "calc.py").read_bytes() == before
    report = build_evidence_report(result, repo, 0, 0)
    assert "Mutation check: 1 of 3 deliberate breakages caught" in report and "calc.py:6" in report


def test_require_rejects_until_the_line_is_tested(repo):
    configure(repo, mutation_check="require")
    rejected = CodingVerifier(workspace=str(repo)).verify_task("Fix the add function in calc.py")
    assert not rejected.passed and "mutation_check is \"require\"" in rejected.message
    assert "calc.py:6" in rejected.message
    (repo / "test_calc.py").write_text(
        "from calc import add, is_big\n\n\ndef test_add():\n    assert add(2, 3) == 5\n\n\n"
        "def test_is_big():\n    assert is_big(11) and not is_big(10)\n", encoding="utf-8")
    accepted = CodingVerifier(workspace=str(repo)).verify_task("Fix the add function in calc.py")
    assert accepted.passed, accepted.message
    assert accepted.mutation["survived"] == [] and accepted.mutation["score"] == 100


def test_off_by_default_and_refused_approval(repo):
    configure(repo)
    assert CodingVerifier(workspace=str(repo)).verify_task("Fix the add function in calc.py").mutation is None
    configure(repo, mutation_check="warn")
    asked = []

    def approve(command):
        asked.append(command)
        return len(asked) == 1  # the main test run is approved, the mutation runs are not

    result = CodingVerifier(workspace=str(repo), command_approver=approve).verify_task("Fix the add function in calc.py")
    assert result.passed
    assert result.mutation == {"status": "not_checked", "reason": "running the tests on mutated code was not approved",
                               "mutants": 0, "killed": 0, "survived": [], "score": None}


def test_invalid_setting_is_shown_not_ignored(repo):
    configure(repo, mutation_check="always")
    result = CodingVerifier(workspace=str(repo)).verify_task("Fix the add function in calc.py")
    assert result.passed and result.mutation["status"] == "not_checked"
    assert "mutation_check must be" in result.mutation["reason"]
