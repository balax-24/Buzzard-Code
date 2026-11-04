"""
Persistent Assessment Logger and Tool Output Summarizer.
Creates structured assessment logs under assessments/session-<timestamp>/
"""

import os
import json
import time
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from security_agent.events.agent_event import AgentEvent


def summarize_tool_output(tool_name: str, raw_output: str, exit_code: int = 0) -> str:
    """
    Summarizes raw tool output into a concise 1-3 line summary for live UI presentation.
    """
    if not raw_output or not raw_output.strip():
        return "Command completed (no output)"

    output = raw_output.strip()
    
    # Error cases
    if exit_code != 0 and ("error" in output.lower() or "failed" in output.lower()):
        first_line = output.split("\n")[0][:120]
        return f"Operation failed (exit {exit_code}): {first_line}"

    # Port scanning / nmap
    if "nmap" in tool_name or "port" in tool_name or "scan" in tool_name:
        open_ports = re.findall(r"(\d+/(?:tcp|udp))\s+open\s+([\w\-]+)", output)
        if open_ports:
            ports_summary = ", ".join(f"{p[0]} ({p[1]})" for p in open_ports[:5])
            extra = f" +{len(open_ports)-5} more" if len(open_ports) > 5 else ""
            return f"{len(open_ports)} open services discovered: {ports_summary}{extra}"
        
    # HTTP requests / enumeration
    if "http" in tool_name or "curl" in tool_name or "web" in tool_name:
        status_match = re.search(r"HTTP/\S+\s+(\d{3})", output) or re.search(r"status[:\s]+(\d{3})", output, re.IGNORECASE)
        status_code = status_match.group(1) if status_match else None
        
        links = re.findall(r"href=[\"']([^\"']+)[\"']", output, re.IGNORECASE)
        if status_code:
            summary = f"HTTP {status_code} response"
            if links:
                summary += f", {len(links)} endpoints/links referenced"
            return summary
            
    # DNS / subdomain enumeration
    if "dns" in tool_name or "subdomain" in tool_name:
        lines = [l.strip() for l in output.split("\n") if l.strip() and not l.startswith("#")]
        return f"{len(lines)} DNS records/hosts identified"

    # Directory / file search
    if "dir" in tool_name or "file" in tool_name or "list" in tool_name:
        lines = [l.strip() for l in output.split("\n") if l.strip()]
        return f"{len(lines)} items discovered"

    # Default concise fallback
    lines = [l.strip() for l in output.split("\n") if l.strip()]
    if len(lines) == 1:
        return lines[0][:150]
    elif len(lines) > 1:
        return f"{len(lines)} lines returned. First line: {lines[0][:100]}"
    return "Operation completed"


class AssessmentLogger:
    """
    Manages persistent logging of a security assessment session.
    """
    def __init__(self, session_id: Optional[str] = None, base_dir: str = "assessments"):
        self.timestamp_str = time.strftime("%Y-%m-%d-%H%M%S")
        self.session_id = session_id or f"session-{self.timestamp_str}"
        self.session_dir = Path(base_dir) / self.session_id
        self.raw_dir = self.session_dir / "raw"
        
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeline_file = self.session_dir / "timeline.jsonl"
        self.tool_calls_file = self.session_dir / "tool_calls.jsonl"
        self.metadata_file = self.session_dir / "metadata.json"
        self.findings_file = self.session_dir / "findings.json"
        self.report_file = self.session_dir / "final_report.md"
        
        self.tool_call_count = 0
        self.start_time = time.time()
        
    def write_metadata(self, metadata: Dict[str, Any]) -> None:
        """Writes or updates session metadata."""
        meta = {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time)),
            **metadata
        }
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def log_event(self, event: AgentEvent) -> None:
        """Appends an event to timeline.jsonl."""
        with open(self.timeline_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def log_tool_call(
        self,
        tool: str,
        arguments: Dict[str, Any],
        raw_output: str,
        duration_s: float,
        exit_code: int = 0,
        summary: Optional[str] = None
    ) -> str:
        """
        Logs a full tool execution, saves raw output to file, and appends to tool_calls.jsonl.
        """
        self.tool_call_count += 1
        call_id = f"tool_{self.tool_call_count:03d}_{tool.replace('.', '_')}"
        
        raw_file_name = f"{call_id}.txt"
        raw_path = self.raw_dir / raw_file_name
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(raw_output or "")
            
        short_summary = summary or summarize_tool_output(tool, raw_output, exit_code)
        
        entry = {
            "id": call_id,
            "timestamp": time.time(),
            "tool": tool,
            "arguments": arguments,
            "duration_s": duration_s,
            "exit_code": exit_code,
            "summary": short_summary,
            "raw_output_file": f"raw/{raw_file_name}"
        }
        
        with open(self.tool_calls_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            
        return short_summary

    def write_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Writes the list of findings to findings.json."""
        with open(self.findings_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

    def write_final_report(self, report_markdown: str) -> str:
        """Writes the final markdown report."""
        with open(self.report_file, "w", encoding="utf-8") as f:
            f.write(report_markdown)
        return str(self.report_file)
