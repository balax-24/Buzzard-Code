"""Task-relevant repository map ranking and budget behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.code_index import CodeIndex


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_repo_map_prioritizes_task_symbol_and_import_neighbors(tmp_path: Path) -> None:
    from agent.repo_map import build_repo_map

    _write(tmp_path, "shop/pricing.py", "def apply_discount(price, rate):\n    return price * rate\n")
    _write(tmp_path, "shop/checkout.py", "from .pricing import apply_discount\ndef checkout():\n    return apply_discount(1, 2)\n")
    _write(tmp_path, "tests/test_pricing.py", "from shop.pricing import apply_discount\ndef test_discount():\n    assert apply_discount(1, 2)\n")
    _write(tmp_path, "web/layout.py", "def render_page():\n    return None\n")

    index = CodeIndex(str(tmp_path))
    index.refresh()
    first = build_repo_map(index, "Fix apply_discount in shop/pricing.py")

    assert first.splitlines()[1].startswith("- shop/pricing.py")
    assert "shop/checkout.py" in first
    assert "tests/test_pricing.py" in first
    assert "web/layout.py" not in first or first.index("web/layout.py") > first.index("shop/checkout.py")
    assert first == build_repo_map(index, "Fix apply_discount in shop/pricing.py")


def test_repo_map_obeys_character_budget_and_rejects_invalid_budget(tmp_path: Path) -> None:
    from agent.repo_map import build_repo_map

    _write(tmp_path, "package/module.py", "class ALongClassName:\n    pass\n")
    index = CodeIndex(str(tmp_path))
    index.refresh()

    rendered = build_repo_map(index, "module", budget_chars=120)
    assert len(rendered) <= 120
    assert rendered.startswith("Repository map")

    with pytest.raises(ValueError, match="budget_chars must be positive"):
        build_repo_map(index, "module", budget_chars=0)


def test_repo_map_empty_index_returns_empty_string(tmp_path: Path) -> None:
    from agent.repo_map import build_repo_map

    assert build_repo_map(CodeIndex(str(tmp_path)), "find a symbol") == ""
