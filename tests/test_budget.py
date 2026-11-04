"""Tests for the BudgetTracker."""

import time
import pytest
from agent.budget import BudgetConfig, BudgetTracker


class TestBudgetTracker:
    def test_initial_state(self):
        tracker = BudgetTracker()
        assert tracker.tool_calls == 0
        assert tracker.requests == 0
        assert tracker.model_tokens_total == 0
        assert not tracker.is_exceeded()

    def test_record_tool_calls(self):
        tracker = BudgetTracker()
        tracker.record_tool_call()
        tracker.record_tool_call()
        assert tracker.tool_calls == 2

    def test_record_requests(self):
        tracker = BudgetTracker()
        tracker.record_request()
        assert tracker.requests == 1

    def test_record_tokens(self):
        tracker = BudgetTracker()
        tracker.record_model_tokens(input_tokens=100, output_tokens=50)
        tracker.record_model_tokens(input_tokens=200, output_tokens=100)
        assert tracker.model_input_tokens == 300
        assert tracker.model_output_tokens == 150
        assert tracker.model_tokens_total == 450

    def test_exceeded_tool_calls(self):
        config = BudgetConfig(max_tool_calls=5)
        tracker = BudgetTracker(config=config)
        for _ in range(6):
            tracker.record_tool_call()
        assert tracker.is_exceeded()

    def test_exceeded_requests(self):
        config = BudgetConfig(max_requests=3)
        tracker = BudgetTracker(config=config)
        for _ in range(4):
            tracker.record_request()
        assert tracker.is_exceeded()

    def test_exceeded_time(self):
        config = BudgetConfig(duration_seconds=1)
        tracker = BudgetTracker(config=config)
        tracker.start_time = time.time() - 2  # started 2 seconds ago
        assert tracker.is_exceeded()

    def test_not_exceeded(self):
        config = BudgetConfig(max_tool_calls=100, max_requests=100)
        tracker = BudgetTracker(config=config)
        tracker.record_tool_call()
        tracker.record_request()
        assert not tracker.is_exceeded()

    def test_status_dict(self):
        config = BudgetConfig(max_tool_calls=10, max_requests=20)
        tracker = BudgetTracker(config=config)
        tracker.record_tool_call()
        tracker.record_tool_call()
        tracker.record_request()
        
        status = tracker.get_status()
        assert status["tool_calls"]["used"] == 2
        assert status["tool_calls"]["limit"] == 10
        assert status["tool_calls"]["pct"] == 20
        assert status["requests"]["used"] == 1
        assert status["exceeded"] is False

    def test_warnings(self):
        config = BudgetConfig(max_tool_calls=10, warning_threshold=0.80)
        tracker = BudgetTracker(config=config)
        
        # No warning yet
        assert len(tracker.check_warnings()) == 0
        
        # Use 8 of 10 tool calls (80%)
        for _ in range(8):
            tracker.record_tool_call()
        
        warnings = tracker.check_warnings()
        assert any(w["category"] == "tool_calls" for w in warnings)
        
        # Calling again should not re-warn
        assert len(tracker.check_warnings()) == 0

    def test_serialization_roundtrip(self):
        config = BudgetConfig(max_tool_calls=50, max_requests=100)
        tracker = BudgetTracker(config=config)
        tracker.record_tool_call()
        tracker.record_tool_call()
        tracker.record_request()
        tracker.record_model_tokens(input_tokens=500, output_tokens=200)
        
        d = tracker.to_dict()
        restored = BudgetTracker.from_dict(d)
        
        assert restored.tool_calls == 2
        assert restored.requests == 1
        assert restored.model_input_tokens == 500
        assert restored.model_output_tokens == 200
        assert restored.config.max_tool_calls == 50

    def test_format_display(self):
        tracker = BudgetTracker()
        tracker.record_tool_call()
        tracker.record_request()
        display = tracker.format_display()
        assert "Tool calls:" in display
        assert "Requests:" in display
        assert "Tokens:" in display

    def test_high_risk_tracking(self):
        config = BudgetConfig(max_high_risk_actions=3)
        tracker = BudgetTracker(config=config)
        tracker.record_high_risk()
        tracker.record_high_risk()
        assert not tracker.is_exceeded()
        tracker.record_high_risk()
        tracker.record_high_risk()
        assert tracker.is_exceeded()
