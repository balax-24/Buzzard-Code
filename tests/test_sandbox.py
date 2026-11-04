import os
import pytest
from sandbox.container import get_sandbox, LocalSandboxFallback, DockerSandbox, BlockedSandbox

def test_sandbox_factory_resolution():
    """
    Checks that get_sandbox returns a SandboxProvider instance.
    """
    sandbox = get_sandbox()
    assert isinstance(sandbox, (DockerSandbox, LocalSandboxFallback, BlockedSandbox))

def test_local_fallback_execution():
    """
    Tests executing a basic command using the local execution fallback.
    """
    sandbox = LocalSandboxFallback()
    res = sandbox.execute("echo 'hello sandbox'")
    
    assert res["exit_code"] == 0
    assert "hello sandbox" in res["stdout"]
    assert res["sandboxed"] is False

def test_local_fallback_timeout():
    """
    Tests that commands exceeding timeout are killed.
    """
    sandbox = LocalSandboxFallback()
    import sys
    cmd = "sleep 5" if os.name != "nt" else f'"{sys.executable}" -c "import time; time.sleep(5)"'
    res = sandbox.execute(cmd, timeout=0.5)
    
    assert res["exit_code"] in (-1, 124)
    assert "timed out" in res["stderr"]

def test_force_local_factory():
    """
    Checks that forcing local provider resolves to LocalSandboxFallback.
    """
    sandbox = get_sandbox(force_local=True)
    assert isinstance(sandbox, LocalSandboxFallback)
