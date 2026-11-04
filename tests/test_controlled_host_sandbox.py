import os
import sys
import tempfile
import shutil
import pytest
from security_agent.sandbox.container import ControlledHostSandbox
from security_agent.security.kill_switch import KillSwitch
from security_agent.tools.filesystem import set_active_workspace


@pytest.fixture
def temp_ws():
    td = tempfile.mkdtemp()
    set_active_workspace(td)
    yield td
    set_active_workspace(None)
    shutil.rmtree(td, ignore_errors=True)


def test_controlled_host_sandbox_workspace_scope(temp_ws):
    sandbox = ControlledHostSandbox(workspace=temp_ws)
    # Create a test file
    test_file = os.path.join(temp_ws, "hello.txt")
    with open(test_file, "w") as f:
        f.write("test_scope")

    res = sandbox.execute(f'"{sys.executable}" -c "print(open(\'hello.txt\').read())"')
    assert res["exit_code"] == 0
    assert "test_scope" in res["stdout"]


def test_controlled_host_sandbox_blocks_dangerous_commands():
    sandbox = ControlledHostSandbox()
    res1 = sandbox.execute("sudo rm -rf /")
    assert res1["exit_code"] == 126
    assert "SECURITY BLOCKED" in res1["stderr"]

    res2 = sandbox.execute("rm -rf /")
    assert res2["exit_code"] == 126
    assert "SECURITY BLOCKED" in res2["stderr"]


def test_controlled_host_sandbox_kill_switch_enforcement():
    sandbox = ControlledHostSandbox()
    ks = KillSwitch.get_instance()
    ks.trigger("Test kill switch")
    try:
        res = sandbox.execute("echo test")
        assert res["exit_code"] == 126
        assert "Kill switch is currently armed" in res["stderr"]
    finally:
        ks.reset()


def test_controlled_host_sandbox_timeout():
    sandbox = ControlledHostSandbox()
    # Execute command that sleeps longer than timeout
    res = sandbox.execute(f'"{sys.executable}" -c "import time; time.sleep(5)"', timeout=0.5)
    assert res["exit_code"] == 124
    assert "timed out" in res["stderr"].lower()
