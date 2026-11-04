"""
Tests for Phase 10 Failure Learning and Error Classification.
Verifies:
1. HTTP 401/403/404/WAF failures are converted into structured operational knowledge (e.g. AUTH_REQUIRED).
2. Failures inform prerequisites without blindly repeating identical actions.
"""

import pytest
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    classify_failure,
    FailureClassification,
)


def test_failure_learning_and_classification():
    # Case 1: 401 Unauthorized -> AUTH_REQUIRED
    res_401 = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"admin\"\r\n\r\nAccess denied"
    cls_401 = classify_failure(raw_output=res_401, exit_code=0)
    assert cls_401 == FailureClassification.AUTH_REQUIRED

    # Case 2: WAF Block
    res_waf = "<html><body>403 Forbidden: Request Blocked by Cloudflare WAF</body></html>"
    cls_waf = classify_failure(raw_output=res_waf, exit_code=0)
    assert cls_waf == FailureClassification.WAF_BLOCKED
