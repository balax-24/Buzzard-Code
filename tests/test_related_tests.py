"""Tests for related-test selection (roadmap C2)."""

import shutil
import subprocess
import sys

import pytest

from tools import code_index
from tools.filesystem import set_active_workspace
from tools.related_tests import is_test_file, related_tests
from tools.related_tests import tests_reaching as find_reaching_tests

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    write(root, "shop/__init__.py", "")
    write(root, "shop/pricing.py", "def price(x):\n    return x\n")
    write(root, "shop/cart.py", "from shop.pricing import price\n\ndef total(items):\n    return sum(price(i) for i in items)\n")
    write(root, "shop/users.py", "def name():\n    return 'a'\n")
    write(root, "tests/test_cart.py", "from shop.cart import total\n\ndef test_total():\n    assert total([1, 2]) == 3\n")
    write(root, "tests/test_users.py", "from shop.users import name\n\ndef test_name():\n    assert name() == 'a'\n")
    write(root, "svc/handler.go", "package svc\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    set_active_workspace(str(root))
    code_index._indexes.clear()
    yield root
    set_active_workspace(None)
    code_index._indexes.clear()


def test_test_file_patterns():
    for path in ("tests/test_a.py", "a_test.go", "src/__tests__/x.js", "b.spec.ts", "conftest.py"):
        assert is_test_file(path), path
    for path in ("shop/cart.py", "src/testing_utils.py", "main.go"):
        assert not is_test_file(path), path


def test_transitive_importers_and_depth_limit():
    importers = {"a.py": {"b.py"}, "b.py": {"c.py"}, "c.py": {"tests/test_c.py"}, "x.py": {"tests/test_x.py"}}
    assert find_reaching_tests(["a.py"], importers) == {"tests/test_c.py"}
    assert find_reaching_tests(["a.py"], importers, depth=2) == set()
    assert find_reaching_tests(["tests/test_new.py"], importers) == {"tests/test_new.py"}


def test_change_selects_only_tests_that_reach_it(repo):
    write(repo, "shop/pricing.py", "def price(x):\n    return x * 1\n")
    out = related_tests()
    assert "-m pytest -q tests/test_cart.py" in out
    assert "test_users.py" not in out
    assert "full test suite" in out


def test_returned_command_runs_and_passes(repo):
    write(repo, "shop/pricing.py", "def price(x):\n    return x * 1\n")
    command = related_tests().split("\n")[1].strip()
    command = command.replace("python", f'"{sys.executable}"', 1) if command.startswith("python ") else command
    result = subprocess.run(command, cwd=repo, shell=True, capture_output=True, text=True)
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stdout + result.stderr


def test_explicit_paths_go_packages_and_no_changes(repo):
    assert related_tests() == "No changed files, so there are no related tests to run."
    write(repo, "svc/handler.go", "package svc\n\nfunc H() {}\n")
    out = related_tests()
    assert "go test ./svc" in out
    assert "test_users.py" in related_tests("shop/users.py")
    assert related_tests("../outside.py").startswith("Error")


def test_changed_file_without_tests_says_so(repo):
    write(repo, "shop/new.py", "X = 1\n")
    assert "No Python test imports the changed files" in related_tests()
