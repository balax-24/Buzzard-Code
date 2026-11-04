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
