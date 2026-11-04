import pytest
from pathlib import Path
from security_agent.persistence.engagement_store import EngagementLock, EngagementLockError

def test_concurrent_writer_prevention(tmp_path):
    lock_file = tmp_path / "test.lock"
    lock1 = EngagementLock(lock_file)
    lock2 = EngagementLock(lock_file)

    lock1.acquire()
    # Second writer cannot acquire
    with pytest.raises(EngagementLockError):
        lock2.acquire()

    lock1.release()
    # Now second writer can acquire
    lock2.acquire()
    lock2.release()
