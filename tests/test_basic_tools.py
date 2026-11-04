import pytest
import re
from security_agent.tools.basic import get_time, calculator
from security_agent.tools.registry import ToolRegistry, Tool

def test_get_time():
    """
    Verifies that get_time returns a string matching date format YYYY-MM-DD HH:MM:SS.
    """
    res = get_time()
    assert isinstance(res, str)
    pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
    assert re.match(pattern, res) is not None

def test_calculator_valid():
    """
    Verifies valid evaluations in the safe calculator.
    """
    assert calculator("2 + 2") == "4"
    assert calculator("3 * (4 - 1)") == "9"
    assert calculator("2**3") == "8"
    assert calculator("10 / 4") == "2.5"
    assert calculator("-5 + 3") == "-2"

def test_calculator_invalid():
    """
    Verifies invalid expressions return a descriptive error.
    """
    assert "Error:" in calculator("abc")
    assert "Error:" in calculator("2 / 0")
    assert "Error:" in calculator("2 +")

def test_calculator_safety():
    """
    Verifies that unsafe commands are rejected.
    """
    unsafe_expr = "__import__('os').system('ls')"
    res = calculator(unsafe_expr)
    assert "Error:" in res
    assert "Unsupported AST" in res

def test_tool_registry():
    """
    Verifies registration and execution inside ToolRegistry.
    """
    registry = ToolRegistry()
    registry.register("get_time", "Get current time", get_time)
    registry.register("calc", "Run math", calculator)
    
    assert "get_time" in registry.tools
    assert "calc" in registry.tools
    
    # Run tools
    time_res = registry.execute("get_time", {})
    assert "2026" in time_res or "20" in time_res  # basic check
    
    calc_res = registry.execute("calc", {"expression": "12 * 12"})
    assert calc_res == "144"
