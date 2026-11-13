"""Tests for changed-line coverage in the completion gate (roadmap C3)."""

import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from verification import changed_coverage as cc
from verification.changed_coverage import (
    ChangedLineCoverage,
    coverage_setting,
    decode_numbits,
    installed_coverage_version,
    measure_changed_line_coverage,
    parse_added_lines,
    statement_start_lines,
    wrap_pytest_command,
)
from verification.evidence_report import _coverage_text

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def encode_numbits(lines):
    """The inverse of coverage.py's numbits format, for building test data files."""
    size = max(lines) // 8 + 1
    data = bytearray(size)
    for line in lines:
        data[line // 8] |= 1 << (line % 8)
    return bytes(data)


def write_coverage_db(path: Path, executed: dict, schema: int = 7, arcs: dict | None = None) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        "create table coverage_schema (version integer);"
        "create table file (id integer primary key, path text);"
        "create table line_bits (file_id integer, context_id integer, numbits blob);"
        "create table arc (file_id integer, context_id integer, fromno integer, tono integer);"
    )
    connection.execute("insert into coverage_schema values (?)", (schema,))
    for index, (file_path, lines) in enumerate(executed.items(), 1):
        connection.execute("insert into file values (?, ?)", (index, str(file_path)))
        if lines:
            connection.execute("insert into line_bits values (?, 0, ?)", (index, encode_numbits(lines)))
        for start, end in (arcs or {}).get(file_path, []):
            connection.execute("insert into arc values (?, 0, ?, ?)", (index, start, end))
    connection.commit()
    connection.close()


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    (root / "pricing.py").write_text(
        "def total(items):\n"            # 1
        "    return sum(items)\n"         # 2
        "\n"                              # 3
        "def discount(price, rate):\n"    # 4
        "    return price - rate\n",      # 5
        encoding="utf-8",
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    return root


def test_numbits_round_trip():
    assert decode_numbits(encode_numbits({1, 2, 9, 64})) == {1, 2, 9, 64}
    assert decode_numbits(b"") == set()


def test_wrap_only_python_module_pytest_commands(tmp_path):
    data = tmp_path / "c.db"
    assert wrap_pytest_command(".venv/Scripts/python.exe -m pytest -q", data) == (
        f'.venv/Scripts/python.exe -m coverage run --data-file="{data}" -m pytest -q'
    )
    assert wrap_pytest_command("python -m pytest", data).endswith("-m pytest")
    assert wrap_pytest_command("pytest -q", data) is None
    assert wrap_pytest_command("npm test", data) is None
    assert wrap_pytest_command("python -m pytest -q && rm -rf /", data).endswith("&& rm -rf /")


def test_setting_validation():
    assert coverage_setting({}) == ("auto", None)
    assert coverage_setting({"coverage": "off"}) == ("off", None)
    setting, error = coverage_setting({"coverage": True})
    assert setting is None and "auto" in error


def test_parse_added_lines_handles_counts_and_deletions():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -2 +2 @@\n-x\n+y\n"
        "@@ -10,0 +11,3 @@\n+a\n+b\n+c\n"
        "@@ -20,2 +23,0 @@\n-gone\n-gone\n"
        "diff --git a/old.py b/old.py\n--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert parse_added_lines(diff) == {"a.py": {2, 11, 12, 13}}


def test_statement_mapping_skips_comments_blanks_and_docstrings():
    source = (
        "@decorator\n"           # 1
        "def f(a,\n"             # 2
        "      b):\n"            # 3
        '    """Doc."""\n'       # 4
        "    # comment\n"        # 5
        "\n"                     # 6
        "    x = (a +\n"         # 7
        "         b)\n"          # 8
        "    if x:\n"            # 9
        "        return x\n"     # 10
    )
    mapping = statement_start_lines(source, range(1, 11))
    assert mapping == {1: 1, 2: 1, 3: 1, 7: 7, 8: 7, 9: 9, 10: 10}


def test_installed_version_is_found_by_files_without_running_python(tmp_path):
    site = tmp_path / ".venv" / "Lib" / "site-packages"
    (site / "coverage-7.6.1.dist-info").mkdir(parents=True)
    (tmp_path / ".venv" / "Scripts").mkdir()
    assert installed_coverage_version(tmp_path, ".venv/Scripts/python.exe") == (7, 6)
    assert installed_coverage_version(tmp_path, "python") is None
    assert installed_coverage_version(tmp_path / "missing", ".venv/bin/python") is None


def test_measure_reports_covered_and_uncovered_changed_lines(repo, tmp_path):
    (repo / "pricing.py").write_text(
        "def total(items):\n"
        "    return sum(items) + 0\n"          # changed, runs
        "\n"
        "def discount(price, rate):\n"
        "    return price - price * rate\n",   # changed, never runs
        encoding="utf-8",
    )
    (repo / "test_pricing.py").write_text("def test_x():\n    pass\n", encoding="utf-8")  # test files are excluded
    data = tmp_path / "coverage.db"
    write_coverage_db(data, {repo / "pricing.py": {1, 2, 4}})
    result = measure_changed_line_coverage(repo, data)
    assert result.measured and (result.covered, result.total) == (1, 2)
    assert result.uncovered == {"pricing.py": [5]}
    assert result.percent == 50.0
    assert "1/2 changed lines run by tests (50.0%)" in _coverage_text(result.to_dict())
    assert "`pricing.py` 5" in _coverage_text(result.to_dict())


def test_new_files_count_every_executable_line_and_branch_data_is_read(repo, tmp_path):
    (repo / "fees.py").write_text("FEE = 2\n\ndef fee(x):\n    return x + FEE\n", encoding="utf-8")
    data = tmp_path / "coverage.db"
    write_coverage_db(data, {repo / "fees.py": set()}, arcs={repo / "fees.py": [(-1, 1), (1, 3), (3, -1)]})
    result = measure_changed_line_coverage(repo, data)
    assert (result.covered, result.total) == (2, 3)
    assert result.uncovered == {"fees.py": [4]}


@pytest.mark.parametrize("problem", ["missing", "schema", "garbage"])
def test_unmeasurable_data_is_reported_not_guessed(repo, tmp_path, problem):
    data = tmp_path / "coverage.db"
    if problem == "schema":
        write_coverage_db(data, {repo / "pricing.py": {1}}, schema=99)
    elif problem == "garbage":
        data.write_bytes(b"not a database")
    result = measure_changed_line_coverage(repo, data)
    assert not result.measured and result.reason
    assert _coverage_text(result.to_dict()).startswith("not measured (")


def test_no_executable_changes():
    assert ChangedLineCoverage(measured=True).summary() == "no executable non-test lines changed"


def test_gate_wraps_command_and_records_coverage(repo, tmp_path, monkeypatch):
    from verification.coding_verifier import CodingVerifier

    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    (repo / "pyproject.toml").write_text("[project]\nname='shop'\n", encoding="utf-8")
    (repo / ".venv" / "Scripts").mkdir(parents=True)
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / ".venv" / "Lib" / "site-packages" / "coverage-7.6.1.dist-info").mkdir(parents=True)
    for python_dir in ("Scripts", "bin"):
        (repo / ".venv" / python_dir / ("python.exe" if python_dir == "Scripts" else "python")).write_text("", encoding="utf-8")
    (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    (repo / "pricing.py").write_text(
        "def total(items):\n    return sum(items) + 0\n\ndef discount(price, rate):\n    return price - rate\n",
        encoding="utf-8",
    )
    commands = []

    def fake_execute(command, timeout=None, **kwargs):
        commands.append(command)
        data_file = Path(command.split('--data-file="', 1)[1].split('"', 1)[0])
        write_coverage_db(data_file, {repo / "pricing.py": {1, 2, 4}})
        return {"exit_code": 0, "stdout": "1 passed", "stderr": ""}

    verifier = CodingVerifier(workspace=str(repo), command_approver=lambda command: True)
    monkeypatch.setattr(verifier.sandbox, "execute", fake_execute)
    result = verifier.verify_task("update the total function")
    assert result.passed, result.message
    assert "-m coverage run --data-file=" in commands[0] and commands[0].endswith("-m pytest -q")
    assert str(tmp_path / "home") in commands[0] and str(repo) not in commands[0].split("--data-file=")[1]
    assert result.changed_line_coverage["measured"] is True
    assert (result.changed_line_coverage["covered"], result.changed_line_coverage["total"]) == (1, 1)


def test_gate_without_coverage_installed_runs_plain_command(repo, tmp_path, monkeypatch):
    from verification.coding_verifier import CodingVerifier

    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    (repo / "pyproject.toml").write_text("[project]\nname='shop'\n", encoding="utf-8")
    (repo / "pricing.py").write_text("def total(items):\n    return 0\n", encoding="utf-8")
    commands = []
    verifier = CodingVerifier(workspace=str(repo), command_approver=lambda command: True)
    monkeypatch.setattr(verifier.sandbox, "execute",
                        lambda command, timeout=None, **kwargs: commands.append(command) or {"exit_code": 0, "stdout": "", "stderr": ""})
    result = verifier.verify_task("update the total function")
    assert result.passed and "coverage" not in commands[0]
    assert result.changed_line_coverage == ChangedLineCoverage(
        measured=False, reason="coverage.py is not installed in the project's virtual environment"
    ).to_dict()


# -- adapters for other ecosystems -------------------------------------------------------------

from verification.changed_coverage import (  # noqa: E402
    parse_go_profile,
    parse_lcov,
    plan_coverage,
    wrap_c8_command,
    wrap_cargo_command,
    wrap_go_command,
)


def test_bare_pytest_uses_the_project_interpreter(tmp_path):
    data = tmp_path / "c.db"
    assert wrap_pytest_command("pytest -x tests", data, ".venv/bin/python") == (
        f'.venv/bin/python -m coverage run --data-file="{data}" -m pytest -x tests'
    )
    assert wrap_pytest_command("pytest", data) is None


def test_command_wrappers(tmp_path):
    out = tmp_path / "out"
    assert wrap_go_command("go test ./... -race", out) == f'go test -coverprofile="{out}" -coverpkg=./... ./... -race'
    assert wrap_cargo_command("cargo test --workspace", out) == f'cargo llvm-cov --lcov --output-path "{out}" --workspace'
    c8 = tmp_path / "c8"
    wrapped = wrap_c8_command("npm test", c8, out)
    assert wrapped.startswith(f'"{c8}" --all --reporter=lcovonly') and wrapped.endswith(" npm test")
    assert wrap_c8_command("make test", c8, out) is None
    assert wrap_go_command("gotest", out) is None


def test_go_profile_maps_module_paths_and_counts(tmp_path):
    profile = (
        "mode: set\n"
        "example.com/shop/pricing.go:3.30,5.2 1 1\n"
        "example.com/shop/pricing.go:7.33,9.2 1 0\n"
        "other.org/dep/x.go:1.1,2.2 1 1\n"
    )
    report = parse_go_profile(profile, tmp_path, "example.com/shop")
    executable, executed = report[os.path.normcase(os.path.realpath(tmp_path / "pricing.go"))]
    assert executable == {3, 4, 5, 7, 8, 9} and executed == {3, 4, 5}
    assert len(report) == 1


def test_lcov_parsing(tmp_path):
    text = f"TN:\nSF:{tmp_path / 'a.js'}\nDA:1,1\nDA:2,0\nDA:bad\nend_of_record\nSF:src/b.ts\nDA:4,3\nend_of_record\n"
    report = parse_lcov(text, tmp_path)
    assert report[os.path.normcase(os.path.realpath(tmp_path / "a.js"))] == ({1, 2}, {1})
    assert report[os.path.normcase(os.path.realpath(tmp_path / "src" / "b.ts"))] == ({4}, {4})


def test_plan_explains_missing_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cc.shutil, "which", lambda name: None)
    plans = {
        "npm test": "c8 is not installed",
        "cargo test": "cargo-llvm-cov is not installed",
        "make test": "no coverage support",
        "pytest": "coverage.py is not installed",
    }
    for command, reason in plans.items():
        plan = plan_coverage(tmp_path, command, None, {}, "python")
        assert plan.command == command and reason in plan.pending.reason and plan.collect is None
    off = plan_coverage(tmp_path, "go test ./...", None, {"coverage": "off"}, "python")
    assert off.command == "go test ./..." and "turned off" in off.pending.reason


def test_plan_removes_stale_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    stale = cc.coverage_directory(tmp_path) / "go-cover-profile"
    stale.parent.mkdir(parents=True)
    stale.write_text("old", encoding="utf-8")
    plan = plan_coverage(tmp_path, "go test ./...", "go", {}, "python")
    assert not stale.exists() and "-coverprofile=" in plan.command
    assert "no cover profile" in plan.result().reason or not plan.result().measured


@pytest.fixture
def go_repo(tmp_path):
    root = tmp_path / "goshop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    (root / "go.mod").write_text("module example.com/goshop\n\ngo 1.21\n", encoding="utf-8")
    (root / "pricing.go").write_text("package goshop\n\nfunc Total(a, b int) int {\n\treturn a + b\n}\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    return root


def test_go_measurement_with_unmeasured_file(go_repo, tmp_path):
    (go_repo / "pricing.go").write_text(
        "package goshop\n\nfunc Total(a, b int) int {\n\treturn a + b + 0\n}\n\nfunc Discount(p int) int {\n\treturn p - 1\n}\n",
        encoding="utf-8",
    )
    (go_repo / "extra.go").write_text("package goshop\n\nvar X = 1\n", encoding="utf-8")
    profile = tmp_path / "go.out"
    profile.write_text(
        "mode: set\nexample.com/goshop/pricing.go:3.26,5.2 1 1\nexample.com/goshop/pricing.go:7.25,9.2 1 0\n",
        encoding="utf-8",
    )
    result = cc.measure_go(go_repo, profile)
    assert result.measured
    # git aligns the trailing "}" with the old one, so lines 7-8 are the changed lines of Discount
    assert result.uncovered == {"pricing.go": [7, 8]}
    assert result.covered >= 1 and result.total == result.covered + 2
    assert result.unmeasured_files == ["extra.go"]
    assert "not in the coverage report" in _coverage_text(result.to_dict())
