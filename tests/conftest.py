import pytest
import os
import tempfile

@pytest.fixture
def temp_db():
    """
    Creates a temporary database file for testing and cleans it up after.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def isolated_buzzard_home(tmp_path_factory, monkeypatch):
    """Keeps task journals and other per-user state out of the real ~/.buzzard during tests.

    Tests that need a specific BUZZARD_HOME still set their own with monkeypatch.
    """
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path_factory.mktemp("buzzard-home")))
