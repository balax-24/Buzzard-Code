import pytest
from agent.intent import (
    is_coding_task,
    is_security_task,
    is_actionable_task,
    classify_intent,
)


def test_coding_intent_routing_examples():
    # Exact required examples from user specification:
    assert is_coding_task("Fix the bug in auth.py")
    assert is_coding_task("Add a feature to this project")
    assert is_coding_task("Refactor this function")
    assert is_coding_task("Run the tests and fix failures")
    assert is_coding_task("Explain this repository")

    assert classify_intent("Fix the bug in auth.py") == "CODING"
    assert classify_intent("Add a feature to this project") == "CODING"
    assert classify_intent("Refactor this function") == "CODING"
    assert classify_intent("Run the tests and fix failures") == "CODING"
    assert classify_intent("Explain this repository") == "CODING"

    assert is_actionable_task("Fix the bug in auth.py")
    assert is_actionable_task("Run the tests and fix failures")


def test_conversational_queries_preserved():
    # Non-coding casual queries must remain conversational
    assert not is_coding_task("hello")
    assert not is_coding_task("hi there")
    assert not is_coding_task("who are you")
    assert not is_coding_task("thanks!")
    assert not is_coding_task("how are you doing today?")

    assert classify_intent("hello") == "CONVERSATIONAL"
    assert classify_intent("who are you") == "CONVERSATIONAL"
    assert not is_actionable_task("hello")
    assert not is_actionable_task("who are you")


def test_security_queries_classified():
    assert is_security_task("Run an nmap scan on 10.0.0.5")
    assert is_security_task("Find sqli and xss vulnerabilities on http://target.local")
    assert classify_intent("Run an nmap scan on 10.0.0.5") == "SECURITY"
    assert is_actionable_task("Run an nmap scan on 10.0.0.5")

