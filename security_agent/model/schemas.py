from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from enum import Enum

class AgentDecision(BaseModel):
    """
    Schema for decisions returned by the Buzzard Code model.
    """
    type: str = Field(description="Type of decision (e.g. 'tool_call', 'complete', 'pause')")
    summary: str = Field(description="A brief description of what the agent is doing")
    reason: str = Field(description="Explanation of why this action is appropriate")
    tool: Optional[str] = Field(None, description="The name of the tool to execute")
    arguments: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arguments for the tool")
    expected_observation: Optional[str] = Field(None, description="What the agent expects to observe or learn")

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(str, Enum):
    HYPOTHESIS = "hypothesis"
    LOW = "low"
    MEDIUM = "medium"
    CONFIRMED = "confirmed"

class Finding(BaseModel):
    """
    Schema for security findings discovered by the agent.
    """
    id: str = Field(description="Unique finding identifier (e.g., FIND-001)")
    title: str = Field(description="Concise description of the finding")
    severity: Severity = Field(description="Severity classification")
    confidence: Confidence = Field(description="Verification confidence level")
    affected_asset: str = Field(description="The component or asset affected")
    description: str = Field(description="Detailed explanation of the issue")
    evidence: List[str] = Field(default_factory=list, description="IDs of supporting evidence")
    impact: str = Field(description="Potential impact of the vulnerability")
    verification: str = Field(description="Steps taken to verify the issue")
    remediation: str = Field(description="How to resolve the issue")
    status: str = Field(default="active", description="Finding state (e.g., active, resolved, ignored)")

class EvidenceType(str, Enum):
    HTTP = "http"
    SCREENSHOT = "screenshot"
    TERMINAL = "terminal"
    FILESYSTEM = "filesystem"
    CONFIG = "config"
    OTHER = "other"

class Evidence(BaseModel):
    """
    Schema for collected evidence.
    """
    id: str = Field(description="Evidence unique ID")
    type: EvidenceType = Field(description="Type of evidence collected")
    target: str = Field(description="Target resource or asset")
    description: str = Field(description="Description of what this evidence shows")
    data: Any = Field(description="Raw data content (e.g., HTTP raw request/response, file content, base64 image)")
    timestamp: str = Field(description="ISO timestamp of collection")
