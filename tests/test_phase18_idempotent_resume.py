import pytest
from intelligence.action_identity import ActionIdentity
from intelligence.action_history import ActionHistoryStore

def test_idempotent_resume_deduplication():
    hist = ActionHistoryStore()
    key1 = ActionIdentity.generate_canonical_key("http_request", {"url": "http://10.0.0.1/api"}, "10.0.0.1").canonical_key
    hist.record_action("a1", "http_request", {"url": "http://10.0.0.1/api"}, "10.0.0.1", 5.0, 5.0, 1.0)

    reps = hist.get_repetition_count(key1)
    assert reps == 1
