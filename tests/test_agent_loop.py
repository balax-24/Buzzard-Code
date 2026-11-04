import pytest
from typing import List, Dict, Any, Optional
from security_agent.agent.loop import AgentLoop
from security_agent.model.provider import ModelProvider
from security_agent.tools.registry import ToolRegistry
from security_agent.storage.db import StorageManager
from security_agent.model.schemas import TaskStatus

class MockModelProvider(ModelProvider):
    """
    Mocked provider returning pre-determined decisions.
    """
    def __init__(self, responses: List[str]):
        self.responses = responses
        self.call_count = 0

    def chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
        else:
            resp = '{"type": "complete", "summary": "Finished", "reason": "No more mock responses"}'
        
        return {
            "message": {
                "role": "assistant",
                "content": resp
            }
        }

    def generate(self, prompt: str, system_prompt: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> str:
        return ""

    def stream_chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ):
        yield {}

    def is_available(self) -> bool:
        return True

    def get_available_models(self) -> List[str]:
        return ["mock-model"]


def test_agent_loop_execution_with_storage(temp_db):
    """
    Verifies that the AgentLoop executes properly, calls tools, and updates storage.
    """
    # Mock assistant responses:
    # 1. Ask to run calculator tool
    # 2. Ask to run complete
    mock_responses = [
        '{"type": "tool_call", "summary": "Run calc", "reason": "need to sum numbers", "tool": "calculator", "arguments": {"expression": "2 + 2"}, "expected_observation": "4"}',
        '{"type": "complete", "summary": "Done calculating", "reason": "Calculation completed successfully"}'
    ]
    
    provider = MockModelProvider(mock_responses)
    storage = StorageManager(db_path=temp_db)
    
    loop = AgentLoop(provider=provider, storage_manager=storage, max_iterations=5)
    
    session_id = "mock-session-123"
    result = loop.run(
        task_goal="Perform math audit",
        target="localhost",
        scope=["localhost"],
        session_id=session_id
    )
    
    # Assert loop results
    assert result["status"] == TaskStatus.COMPLETED.value
    assert result["session_id"] == session_id
    assert result["iterations"] == 2
    assert len(result["observations"]) == 1
    assert "Executed calculator" in result["observations"][0]
    
    # Assert session is saved in DB
    session = storage.get_session(session_id)
    assert session is not None
    assert session["status"] == TaskStatus.COMPLETED.value
    assert session["target"] == "localhost"
    assert session["goal"] == "Perform math audit"
    
    # Assert plan is saved and updated in DB
    plan = storage.get_plan(session_id)
    assert len(plan) == 5
    # The agent completed successfully, marking all plan steps as completed
    assert plan[0]["status"] == "completed"
    assert plan[1]["status"] == "completed"
    assert plan[2]["status"] == "completed"
    assert plan[3]["status"] == "completed"
    assert plan[4]["status"] == "completed"

def test_agent_loop_with_policy_engine(temp_db):
    """
    Verifies that the AgentLoop blocks out-of-scope tool calls using the PolicyEngine.
    """
    # Mock assistant responses:
    # 1. Ask to run scan_ports on google.com (out-of-scope)
    # 2. Complete the run
    mock_responses = [
        '{"type": "tool_call", "summary": "Scan google", "reason": "want to check target ports", "tool": "scan_ports", "arguments": {"host": "google.com", "ports": "80"}, "expected_observation": "OPEN"}',
        '{"type": "complete", "summary": "Stopped after block", "reason": "Blocked by policy"}'
    ]
    
    provider = MockModelProvider(mock_responses)
    storage = StorageManager(db_path=temp_db)
    
    loop = AgentLoop(provider=provider, storage_manager=storage, max_iterations=5)
    
    session_id = "mock-session-scope"
    result = loop.run(
        task_goal="Scan localhost ports",
        target="localhost",
        scope=["localhost"],
        session_id=session_id
    )
    
    # Assert loop status
    assert result["status"] == TaskStatus.COMPLETED.value
    assert len(result["observations"]) == 1
    # Check that it contains the POLICY DENIED string
    assert "POLICY DENIED" in result["observations"][0]
    assert "google.com" in result["observations"][0]


def test_parse_xml_tool_call_helper():
    """
    Directly tests the XML regex-based parser in AgentLoop.
    """
    loop = AgentLoop(provider=MockModelProvider([]), native_tools=False)
    
    # 1. Standard tags
    content_std = """
    <thinking>
    Let's read a file to see its contents.
    </thinking>
    <tool_call name="filesystem.read_file">
      <path>/workspace/main.py</path>
    </tool_call>
    """
    name, args, thinking = loop._parse_xml_tool_call(content_std)
    assert name == "filesystem.read_file"
    assert args == {"path": "/workspace/main.py"}
    assert "Let's read a file" in thinking

    # 2. Self closing tags
    content_self = """
    <thinking>Task is finished</thinking>
    <tool_call name="complete" />
    """
    name, args, thinking = loop._parse_xml_tool_call(content_self)
    assert name == "complete"
    assert args == {}
    assert thinking == "Task is finished"

    # 3. Arguments wrapper & multiple types of parameters (JSON decoding)
    content_complex = """
    <tool_call name="test_tool">
      <arguments>
        <string_param>hello</string_param>
        <int_param>123</int_param>
        <bool_param>true</bool_param>
        <dict_param>{"key": "value"}</dict_param>
      </arguments>
    </tool_call>
    """
    name, args, thinking = loop._parse_xml_tool_call(content_complex)
    assert name == "test_tool"
    assert args["string_param"] == "hello"
    assert args["int_param"] == 123
    assert args["bool_param"] is True
    assert args["dict_param"] == {"key": "value"}
    assert thinking == ""


def test_agent_loop_with_xml_tool_calling(temp_db):
    """
    Tests AgentLoop.run with native_tools=False using XML-based tool call and response injection.
    """
    mock_responses = [
        '<thinking>Checking system files</thinking>\n<tool_call name="file.read"><path>config.json</path></tool_call>',
        '<thinking>Finished analysis</thinking>\n<tool_call name="complete" />'
    ]
    
    provider = MockModelProvider(mock_responses)
    storage = StorageManager(db_path=temp_db)
    
    loop = AgentLoop(provider=provider, storage_manager=storage, max_iterations=5, native_tools=False)
    
    session_id = "mock-session-xml"
    result = loop.run(
        task_goal="Perform filesystem check",
        target="localhost",
        scope=["localhost"],
        session_id=session_id
    )
    
    # Assert execution metrics and state
    assert result["status"] == TaskStatus.COMPLETED.value
    assert result["iterations"] == 2
    assert len(result["observations"]) == 1
    assert "Executed file.read" in result["observations"][0]
    
    # Verify the message history structure.
    # Since native_tools=False:
    # 1. The tool result must be added as a role='user' message
    # 2. No tool_calls object should exist in the assistant history message
    history = result.get("messages", [])
    
    # We should have system, first user task, assistant XML 1, tool response user message, assistant XML 2
    # Verify that the message containing tool result has role='user'
    tool_msgs = [m for m in loop.provider.responses if False]  # we can check loop's local message list if accessible, or we inspect from DB / result
    
    # Let's inspect the messages in loop database/session
    session = storage.get_session(session_id)
    # The return dictionary contains the actual message history
    messages = result.get("messages", [])
    
    # Message indices:
    # 0: System Prompt
    # 1: User task prompt
    # 2: Assistant XML response 1
    # 3: User tool result response
    # 4: Assistant XML response 2 (complete)
    assert len(messages) >= 5
    assert messages[2]["role"] == "assistant"
    assert "tool_calls" not in messages[2]  # Should not be populated in assistant history
    
    assert messages[3]["role"] == "user"
    assert "execution result" in messages[3]["content"]
    assert "file.read" in messages[3]["content"]
    
    assert messages[4]["role"] == "assistant"
    assert "complete" in messages[4]["content"]


def test_evidence_fidelity_and_multistep_continuation(temp_db, monkeypatch):
    """
    Verifies that when nmap_scan discovers ports on an audit task, the agent loop
    prevents premature 1-step completion, feeds discovered services to the prompt,
    and requires multi-step investigation before concluding with a grounded report.
    """
    nmap_output = """
PORT      STATE SERVICE VERSION
8384/tcp  open  http    Syncthing administrative web GUI
11434/tcp open  http    Ollama LLM API
"""
    # 1. Model runs nmap_scan
    # 2. Model tries to terminate prematurely without probing
    # 3. Loop prompts for continuation -> Model runs whatweb_scan on port 8384
    # 4. Model outputs grounded final report citing ports 8384 and 11434
    mock_responses = [
        '<tool_call name="nmap_scan"><host>127.0.0.1</host></tool_call>',
        '{"type": "complete", "summary": "Audit finished prematurely"}',
        '<tool_call name="whatweb_scan"><url>http://127.0.0.1:8384</url></tool_call>',
        '# Security Assessment Report\nDiscovered open services on port 8384 (Syncthing) and port 11434 (Ollama API).'
    ]

    provider = MockModelProvider(mock_responses)
    storage = StorageManager(db_path=temp_db)
    
    # Mock nmap_scan and whatweb_scan execution
    registry = ToolRegistry()
    registry.register("nmap_scan", "Nmap network scan", lambda host, **kw: nmap_output)
    registry.register("whatweb_scan", "WhatWeb technology scanner", lambda url, **kw: "Syncthing Web UI [200 OK]")

    loop = AgentLoop(
        provider=provider,
        registry=registry,
        storage_manager=storage,
        max_iterations=6,
        native_tools=False,
        approval_callback=lambda tool, args, metadata: True,
    )

    session_id = "test-fidelity-123"
    result = loop.run(
        task_goal="Assess the services exposed by my local Docker laboratory and produce a report.",
        target="127.0.0.1",
        scope=["127.0.0.1"],
        session_id=session_id
    )

    assert result["status"] == TaskStatus.COMPLETED.value
    # Discovered attack surface should have 2 services
    assert len(loop.attack_surface.services) == 2
    ports = [s.port for s in loop.attack_surface.services]
    assert 8384 in ports
    assert 11434 in ports

    # Multi-step continuation occurred (more than 1 tool call executed)
    assert len(result["observations"]) >= 2
    assert "nmap_scan" in result["observations"][0]
    assert "whatweb_scan" in result["observations"][1]

    # Verify that continuation prompt informed the model about discovered services
    messages = result.get("messages", [])
    continuation_msgs = [m for m in messages if "ASSESSMENT CONTINUATION REQUIRED" in m.get("content", "")]
    assert len(continuation_msgs) >= 1
    assert "Port 8384/tcp" in continuation_msgs[0]["content"]
    assert "Port 11434/tcp" in continuation_msgs[0]["content"]



