"""Cross-Platform Portability & Security Invariant Regression Tests.
Validates Windows (win32) and Linux (POSIX) runtime parity for:
1. Concurrency locking (msvcrt / fcntl abstraction)
2. Safe workspace path traversal prevention (drive letters, UNC, relative traversal)
3. Temporary path resolution across platforms
4. Filesystem fallback without shell dependency
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

from persistence.engagement_store import EngagementLock, EngagementLockError
from security.kill_switch import KILL_FILE_PATHS, KillSwitch
from tools.filesystem import set_active_workspace, get_safe_path, file_read, file_write


def test_engagement_lock_concurrency_and_release(tmp_path):
    """
    Verifies that EngagementLock asquires non-blocking mutual exclusion,
    rejects concurrent acquisition attempts with EngagementLockError,
    and cleanly releases locks across platforms.
    """
    lock_file = tmp_path / "test.lock"
    lock1 = EngagementLock(lock_file)
    lock2 = EngagementLock(lock_file)

    # First acquisition succeeds
    lock1.acquire()
    assert lock1._fd is not None

    # Second acquisition on same target must raise EngagementLockError
    with pytest.raises(EngagementLockError):
        lock2.acquire()

    # Release first lock
    lock1.release()
    assert lock1._fd is None

    # Now second lock can acquire successfully
    lock2.acquire()
    assert lock2._fd is not None
    lock2.release()
    assert lock2._fd is None


def test_get_safe_path_security_invariants():
    """
    Verifies that get_safe_path strictly prevents all traversal mechanisms
    including POSIX traversal, Windows backslashes, drive qualification, and UNC.
    """
    workspace = os.path.abspath("data/workspace")
    # The default workspace depends on local folders, so a fresh clone must set it explicitly
    set_active_workspace(workspace)

    # Valid relative paths stay inside workspace
    assert get_safe_path("normal.txt") == os.path.join(workspace, "normal.txt")
    assert get_safe_path("sub/nested.txt") == os.path.join(workspace, "sub", "nested.txt")
    assert get_safe_path("/workspace/target.txt") == os.path.join(workspace, "target.txt")

    # Directory traversal attacks must be rejected with PermissionError
    traversal_vectors = [
        "../escaped.txt",
        r"..\escaped.txt",
        "../../etc/passwd",
        r"..\..\Windows\System32\cmd.exe",
        "/etc/shadow",
        r"\Windows\System32",
        r"C:\Windows\System32",
        "C:/Windows/System32",
        r"D:\Windows\System32",
        r"\\remote-server\share\evil.bat",
        "//remote-server/share/evil.bat",
    ]

    for vector in traversal_vectors:
        with pytest.raises(PermissionError, match="Access denied"):
            get_safe_path(vector)


def test_kill_file_paths_tempdir():
    """
    Verifies that KILL_FILE_PATHS contains a valid temp directory path on the current OS.
    """
    temp_dir = Path(tempfile.gettempdir())
    expected_temp_kill = temp_dir / "security_agent.kill"
    assert expected_temp_kill in KILL_FILE_PATHS


def test_filesystem_fallback_low_level():
    """
    Verifies that file_read and file_write fall back to OS descriptor I/O
    without invoking shell 'cat' when builtins.open is inaccessible.
    """
    import unittest.mock as mock

    test_dir = tempfile.mkdtemp()
    old_cwd = os.getcwd()
    os.chdir(test_dir)
    try:
        os.makedirs(os.path.abspath("data/workspace"), exist_ok=True)

        # Normal write first
        write_res = file_write("sample.txt", "Initial content")
        assert "Successfully wrote" in write_res

        # Fallback read when builtins.open fails
        with mock.patch("builtins.open", side_effect=PermissionError("Mock open failure")):
            read_content = file_read("sample.txt")
            assert read_content == "Initial content"

        # Fallback write when builtins.open fails
        with mock.patch("builtins.open", side_effect=PermissionError("Mock open failure")):
            fallback_res = file_write("fallback_written.txt", "Fallback content")
            assert "using fallback write" in fallback_res or "Successfully wrote" in fallback_res

        # Verify fallback write content can be read back
        assert file_read("fallback_written.txt") == "Fallback content"
    finally:
        os.chdir(old_cwd)
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
