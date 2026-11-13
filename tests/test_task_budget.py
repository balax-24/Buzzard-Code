"""Tests for per-task budgets on coding tasks (roadmap E4 and F5)."""

from types import SimpleNamespace

import pytest

from agent.durable_tasks import load_journal
from agent.intent import is_coding_task
from agent.run_session import ALLOW, RunSession
from agent.subagents import charge_parent
from agent.budget import BudgetTracker
from agent.task_budget import BUDGETED_TURN_LIMIT, TaskBudget, TaskBudgetError, task_budget_from
from events.bus import EventBus
from sandbox.container import BlockedSandbox
from storage.db import StorageManager
from tools.filesystem import get_active_workspace, set_active_workspace
from tools.registry import create_authoritative_registry

GOAL = "Explain how calc.py works"


def test_settings_are_read_and_validated():
    assert task_budget_from({}) == TaskBudget()
    assert task_budget_from({"task_budget": {"max_tokens": 1000, "max_usd": 1, "max_minutes": 0.5, "max_turns": 9}}) == \
        TaskBudget(max_turns=9, max_tokens=1000, max_usd=1.0, max_minutes=0.5)
    for bad in ([], {"max_tokens": 0}, {"max_tokens": 1.5}, {"max_turns": 501}, {"max_usd": "2"},
                {"max_tokens": True}, {"budget": 1}):
        with pytest.raises(TaskBudgetError):
            task_budget_from({"task_budget": bad})


def test_turn_limit_and_reasons():
    assert TaskBudget().turn_limit(25) == 25
    assert TaskBudget(max_tokens=10).turn_limit(25) == BUDGETED_TURN_LIMIT
    assert TaskBudget(max_tokens=10, max_turns=7).turn_limit(25) == 7
    budget = TaskBudget(max_tokens=100, max_usd=1.0, max_minutes=1)
    assert budget.exceeded(99, 0.5, 30) is None
    assert "token limit reached (100 of 100)" == budget.exceeded(100, None, 0)
    assert "cost limit" in budget.exceeded(0, 1.0, 0)
    assert budget.exceeded(0, None, 0) is None  # unknown cost never counts as over budget
    assert "time limit" in budget.exceeded(0, 0.0, 61)


def test_subagent_usage_is_charged_to_the_parent():
    parent = SimpleNamespace(budget=BudgetTracker(), _task_cost_usd=0.0)
    child = SimpleNamespace(budget=BudgetTracker(), provider=SimpleNamespace(model_name="muse-spark-1.3"))
    child.budget.record_model_tokens(input_tokens=1_000_000, output_tokens=0)
    charge_parent(parent, child)
    assert parent.budget.model_tokens_total == 1_000_000
    assert parent._task_cost_usd == pytest.approx(1.25)


# -- through a real loop -----------------------------------------------------------------------

def call(name, **arguments):
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class Reader:
    """Reads a file every turn, reporting `tokens` prompt tokens, and answers on call `answer_on`."""

    def __init__(self, tokens=1000, answer_on=None, model_name="scripted"):
        self.tokens, self.answer_on, self.model_name, self.calls = tokens, answer_on, model_name, 0

    def is_available(self):
        return True

    def capabilities(self):
        return {"native_tools": True}

    def chat(self, messages, tools=None, options=None):
        self.calls += 1
        metrics = {"prompt_eval_count": self.tokens, "eval_count": 10}
        if self.answer_on is not None and self.calls >= self.answer_on:
            return {"message": {"role": "assistant", "content": "calc.py adds numbers.", "tool_calls": []},
                    "done": True, "metrics": metrics}
        # a different argument each turn, so the loop's repeat detector does not stop it first
        return {"message": {"role": "assistant", "content": "",
                            "tool_calls": [call("file_view", path="calc.py", start_line=1, end_line=self.calls)]},
                "done": True, "metrics": metrics}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    monkeypatch.setattr("agent.loop.get_sandbox", lambda: BlockedSandbox(reason="test"))
    previous = get_active_workspace()
    set_active_workspace(str(tmp_path))
    yield tmp_path
    set_active_workspace(previous)


def session(workspace, provider, budget=None, max_iterations=4, bus=None):
    config = {"workspace": str(workspace)}
    if budget is not None:
        config["task_budget"] = budget
    return RunSession(provider=provider, registry=create_authoritative_registry(),
                      storage=StorageManager(db_path=str(workspace / "audit.db")), config=config,
                      ask_approval=lambda request: ALLOW, max_iterations=max_iterations, event_bus=bus)


def test_goal_is_a_coding_task():
    assert is_coding_task(GOAL)


def test_token_limit_stops_the_task_as_paused_with_the_reason(workspace):
    provider = Reader(tokens=1000)
    outcome = session(workspace, provider, {"max_tokens": 2500}, max_iterations=20).run(
        GOAL, "localhost", ["localhost"], session_id="task-budget")
    assert outcome.status == "paused"
    assert "token limit reached" in outcome.error and "/tasks resume task-budget" in outcome.error
    assert provider.calls == 3  # 1010 + 1010 + 1010 tokens: the third call crosses 2500
    assert load_journal("task-budget").unfinished


def test_cost_limit_uses_the_model_price(workspace):
    provider = Reader(tokens=100_000, model_name="muse-spark-1.3")  # about $0.125 per call
    outcome = session(workspace, provider, {"max_usd": 0.2}, max_iterations=20).run(GOAL, "localhost", ["localhost"])
    assert outcome.status == "paused" and "cost limit reached" in outcome.error
    assert provider.calls == 2


def test_a_budget_raises_the_fixed_turn_limit(workspace):
    without = Reader(answer_on=7)
    assert session(workspace, without, max_iterations=4).run(GOAL, "localhost", ["localhost"]).status != "completed"
    assert without.calls == 4
    budgeted = Reader(answer_on=7)
    outcome = session(workspace, budgeted, {"max_tokens": 1_000_000}, max_iterations=4).run(GOAL, "localhost", ["localhost"])
    assert outcome.status == "completed", outcome.error
    assert budgeted.calls == 7


def test_unknown_price_with_a_money_limit_warns(workspace):
    events = []
    bus = EventBus()
    bus.subscribe_all(events.append)
    provider = Reader(answer_on=1)
    session(workspace, provider, {"max_usd": 1.0}, bus=bus).run(GOAL, "localhost", ["localhost"])
    warnings = [e.payload for e in events if getattr(e.type, "value", "") == "budget.warning"]
    assert any("cannot be enforced" in str(w.get("message")) for w in warnings)


def test_invalid_setting_fails_the_task_with_its_message(workspace):
    outcome = session(workspace, Reader(answer_on=1), {"max_tokens": -5}).run(GOAL, "localhost", ["localhost"])
    assert outcome.status == "failed" and "task_budget.max_tokens must be greater than 0" in outcome.error
