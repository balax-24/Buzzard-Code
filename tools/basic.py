import datetime
import ast
import operator
from typing import Union
from tools.registry import ToolRegistry

# Allowed operators mapping for safe evaluation
ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def _eval_node(node) -> Union[int, float]:
    """
    Recursively evaluate an AST node safely.
    """
    if isinstance(node, ast.Constant):  # Python 3.8+
        if isinstance(node.value, (int, float)):
            return node.value
        raise TypeError("Constant must be a numeric value")
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in ALLOWED_OPERATORS:
            raise TypeError(f"Unsupported operator: {op_type.__name__}")
        return ALLOWED_OPERATORS[op_type](_eval_node(node.left), _eval_node(node.right))
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in ALLOWED_OPERATORS:
            raise TypeError(f"Unsupported unary operator: {op_type.__name__}")
        return ALLOWED_OPERATORS[op_type](_eval_node(node.operand))
    else:
        raise TypeError(f"Unsupported AST element: {type(node).__name__}")

def calculator(expression: str) -> str:
    """
    Safely evaluates a basic mathematical expression.
    Supports operations: +, -, *, /, **, and parenthesis.
    """
    try:
        # Strip all whitespaces
        expr = expression.replace(" ", "")
        if not expr:
            return "Error: Empty expression"
            
        tree = ast.parse(expr, mode="eval")
        result = _eval_node(tree.body)
        return str(result)
    except Exception as e:
        return f"Error: Invalid mathematical expression ({e})"

def get_time() -> str:
    """
    Returns the current date and time.
    """
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

def finish_task(summary: str = "Task assessment finished.") -> str:
    """
    Signals that the security audit or assessment task is complete and provides a final summary.
    """
    return f"TASK_COMPLETED: {summary}"

def complete(summary: str = "Task assessment completed.") -> str:
    """
    Alias for finish_task. Signals task completion.
    """
    return f"TASK_COMPLETED: {summary}"

def lab_echo(message: str = "hello") -> str:
    """
    Diagnostic tool that echoes back a received message to verify tool calling.
    """
    return f"ECHO_OK: {message}"

def lab_probe() -> str:
    """
    Diagnostic tool that executes a harmless environment check inside the sandbox.
    """
    from sandbox.container import get_sandbox
    sandbox = get_sandbox()
    res = sandbox.execute("hostname")
    host = res["stdout"].strip() or "container"
    return f"PROBE_OK: hostname={host} sandboxed={res['sandboxed']}"

def register_basic_tools(registry: ToolRegistry):
    """
    Helper function to register all Phase 2 basic tools.
    """
    registry.register(
        name="get_time",
        description="Returns the current date and time on the local host.",
        func=get_time,
        sandbox_required=False
    )
    registry.register(
        name="lab_echo",
        description="Diagnostic test tool that echoes back a message. Arguments: message (str).",
        func=lab_echo,
        sandbox_required=False
    )
    registry.register(
        name="lab_probe",
        description="Diagnostic test tool that verifies Docker sandbox execution.",
        func=lab_probe,
        sandbox_required=True
    )
    registry.register(
        name="calculator",
        description="Safely computes basic mathematical expressions. Arguments: expression (str).",
        func=calculator,
        sandbox_required=False
    )
    registry.register(
        name="finish_task",
        description="Signals that the security audit or task has concluded. Arguments: summary (str).",
        func=finish_task,
        sandbox_required=False
    )
    registry.register(
        name="complete",
        description="Signals completion of the task. Arguments: summary (str).",
        func=complete,
        sandbox_required=False
    )

