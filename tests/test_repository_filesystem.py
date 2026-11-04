import os
import tempfile
import shutil
import pytest
from tools.filesystem import (
    get_safe_path,
    get_active_workspace,
    set_active_workspace,
    file_list,
    file_read,
    file_view,
    file_write,
    file_edit,
    file_search,
    register_filesystem_tools,
)
from tools.registry import ToolRegistry


@pytest.fixture
def temp_workspace():
    td = tempfile.mkdtemp()
    set_active_workspace(td)
    yield td
    set_active_workspace(None)
    shutil.rmtree(td, ignore_errors=True)


def test_workspace_resolution_and_nested_paths(temp_workspace):
    assert get_active_workspace() == os.path.abspath(temp_workspace)

    # Allowed nested file path
    safe = get_safe_path("src/core/utils.py")
    assert safe == os.path.join(os.path.abspath(temp_workspace), "src", "core", "utils.py")


def test_path_traversal_forbidden(temp_workspace):
    with pytest.raises(PermissionError):
        get_safe_path("../outside.py")

    with pytest.raises(PermissionError):
        get_safe_path("..\\outside.py")

    with pytest.raises(PermissionError):
        get_safe_path("src/../../outside.py")


def test_file_view_line_numbers(temp_workspace):
    file_write("example.py", "line 1\nline 2\nline 3\nline 4\nline 5\n")
    
    # Full view
    out = file_view("example.py")
    assert "1 | line 1" in out
    assert "5 | line 5" in out

    # Range view
    range_out = file_view("example.py", start_line=2, end_line=4)
    assert "2 | line 2" in range_out
    assert "4 | line 4" in range_out
    assert "1 | line 1" not in range_out
    assert "5 | line 5" not in range_out


def test_file_edit_surgical_search_replace(temp_workspace):
    file_write("service.py", "def compute():\n    return 42\n")

    res = file_edit("service.py", "return 42", "return 100")
    assert "Successfully edited 'service.py'" in res
    assert "-    return 42" in res
    assert "+    return 100" in res

    updated = file_read("service.py")
    assert "return 100" in updated
    assert "return 42" not in updated


def test_file_edit_missing_pattern(temp_workspace):
    file_write("service.py", "def compute():\n    return 42\n")

    res = file_edit("service.py", "return 999", "return 100")
    assert "Error: Expected original text was not found" in res


def test_file_edit_ambiguous_matches(temp_workspace):
    file_write("service.py", "x = 1\nx = 1\n")

    res = file_edit("service.py", "x = 1", "x = 2")
    assert "Error: Ambiguous match" in res
    assert "replace_all=True" in res

    # With replace_all
    res_all = file_edit("service.py", "x = 1", "x = 2", replace_all=True)
    assert "Successfully edited" in res_all
    updated = file_read("service.py")
    assert updated == "x = 2\nx = 2\n"


def test_filesystem_registry_registration():
    reg = ToolRegistry()
    register_filesystem_tools(reg)

    assert "file_read" in reg.tools
    assert "file_view" in reg.tools
    assert "file_write" in reg.tools
    assert "file_edit" in reg.tools
    assert "directory_list" in reg.tools
    assert "file_search" in reg.tools

    assert "file.view" in reg.tools
    assert "file.edit" in reg.tools
