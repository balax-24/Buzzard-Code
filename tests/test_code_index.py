"""Tests for the repository index tools: definitions, references, related files."""

import os
import time

import pytest

from tools import code_index
from tools.code_index import code_references, code_related, code_symbols
from tools.filesystem import set_active_workspace


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repo(tmp_path):
    _write(tmp_path, "shop/__init__.py", "")
    _write(tmp_path, "shop/pricing.py", (
        "TAX = 0.1\n"
        "\n"
        "def apply_discount(price, rate):\n"
        "    return price * (1 - rate)\n"
        "\n"
        "class Cart:\n"
        "    def total(self, items):\n"
        "        return sum(apply_discount(i, 0.1) for i in items)\n"
    ))
    _write(tmp_path, "shop/checkout.py", (
        "from .pricing import apply_discount\n"
        "\n"
        "def checkout(price):\n"
        "    return apply_discount(price, 0.2)\n"
    ))
    _write(tmp_path, "tests/test_pricing.py", (
        "from shop.pricing import apply_discount\n"
        "\n"
        "def test_discount():\n"
        "    assert apply_discount(100, 0.5) == 50\n"
    ))
    _write(tmp_path, "web/util.ts", "export function formatPrice(value: number) {\n  return value.toFixed(2)\n}\n")
    _write(tmp_path, "web/app.ts", "import { formatPrice } from './util'\nexport const render = (p: number) => formatPrice(p)\n")
    _write(tmp_path, "node_modules/lib/index.js", "function apply_discount() {}\n")
    set_active_workspace(str(tmp_path))
    code_index._indexes.clear()
    yield tmp_path
    set_active_workspace(None)
    code_index._indexes.clear()


def test_symbols_finds_python_definitions_with_kind_and_line(repo):
    out = code_symbols("apply_discount")
    assert "shop/pricing.py:3  function apply_discount" in out
    assert "node_modules" not in out


def test_symbols_qualified_method_and_kind_filter(repo):
    assert "shop/pricing.py:7  method Cart.total" in code_symbols("Cart.total")
    assert "Cart" in code_symbols("cart", kind="class")
    assert "No definitions" in code_symbols("cart", kind="function")


def test_symbols_indexes_typescript(repo):
    assert "web/util.ts:1  function formatPrice" in code_symbols("formatPrice")
    assert "web/app.ts:2  function render" in code_symbols("render")


def test_references_report_callers_and_skip_definition(repo):
    out = code_references("apply_discount")
    assert "shop/pricing.py:3" not in out
    assert "shop/pricing.py:8  [in Cart.total]" in out
    assert "shop/checkout.py:4  [in checkout]" in out
    assert "tests/test_pricing.py:4  [in test_discount]" in out
    assert "node_modules" not in out


def test_references_respect_word_boundaries(repo):
    _write(repo, "shop/extra.py", "apply_discount_v2 = 1\n")
    assert "extra.py" not in code_references("apply_discount")


def test_related_lists_imports_importers_and_tests(repo):
    out = code_related("shop/pricing.py")
    assert "Imported by: shop/checkout.py, tests/test_pricing.py" in out
    assert "Tests: tests/test_pricing.py" in out
    assert "Imports: shop/pricing.py" in code_related("shop/checkout.py")
    assert "Imports: web/util.ts" in code_related("web/app.ts")


def test_index_refreshes_after_edit_and_delete(repo):
    assert "No definitions" in code_symbols("new_helper")
    target = _write(repo, "shop/pricing.py", "def new_helper():\n    pass\n")
    future = time.time() + 5
    os.utime(target, (future, future))
    assert "shop/pricing.py:1  function new_helper" in code_symbols("new_helper")
    os.remove(repo / "shop" / "checkout.py")
    assert "checkout.py" not in code_symbols("checkout")


def test_syntax_error_file_does_not_break_index(repo):
    _write(repo, "broken.py", "def half_written(:\n")
    assert "No definitions" in code_symbols("half_written")
    assert "broken.py" not in code_references("apply_discount")


def test_invalid_input_and_boundary_errors(repo):
    assert code_symbols("").startswith("Error")
    assert code_references("a b").startswith("Error")
    assert code_related("missing.py").startswith("Error")
    assert code_symbols("x", path="../outside").startswith("Error")


def test_path_scope_limits_results(repo):
    out = code_references("apply_discount", path="tests")
    assert "tests/test_pricing.py" in out and "shop/" not in out
