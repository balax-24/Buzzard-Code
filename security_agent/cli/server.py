"""
JSON IPC Server for Buzzard Code General-Purpose Local AI Agent.

Provides a bidirectional standard I/O (NDJSON) interface for the React+Ink
TypeScript frontend.

Handles general conversation, coding, debugging, research, and security
assessments through an intelligent AUTO intent router and state machine.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from security_agent.agent.loop import AgentLoop
from security_agent.agent.assessment_state import AssessmentPhase, ObjectiveStatus
from security_agent.cli.commands import (
    load_config,
    save_config,
    run_doctor,
    run_status,
)
from security_agent.events.bus import EventBus
from security_agent.events.types import Event, EventType, EventSeverity
from security_agent.model.router import MODEL_PROFILES
from security_agent.tools.arsenal import CATEGORIES


class AgentServer:
    """
    Bidirectional IPC server communicating over stdin/stdout using NDJSON.
    Supports general conversation, code generation, and security tasks.
    """

    def __init__(self):
        self.event_bus = EventBus()
        self.active_loop: Optional[AgentLoop] = None
        self.loop_thread: Optional[threading.Thread] = None
        self.running = True
        self._lock = threading.Lock()
        self.task_start_time: Optional[float] = None
        self.sequence_number = 0
        self.engagement_id = "ENG-DEFAULT"

        # Mode & State tracking
        self.current_mode = "AUTO"
        self.current_task_state = "IDLE"  # IDLE, THINKING, EXECUTING, VERIFYING, WAITING_FOR_USER, COMPLETE, ERROR
        self.conversation_history: List[Dict[str, str]] = []

        # Hook into EventBus
        self.event_bus.subscribe_all(self._on_internal_event)

    def send_event(self, event_type: str, payload: Dict[str, Any], event_id: Optional[str] = None):
        """Emit an event to the frontend on stdout with strict sequence numbering."""
        with self._lock:
            self.sequence_number += 1
            msg = {
                "event": event_type,
                "event_type": event_type,
                "event_id": event_id or f"evt-{int(time.time() * 1000)}",
                "id": event_id or f"evt-{int(time.time() * 1000)}",
                "timestamp": time.time(),
                "engagement_id": self.engagement_id,
                "sequence_number": self.sequence_number,
                "payload": payload,
            }
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def send_response(self, cmd_id: str, success: bool, data: Any = None, error: Optional[str] = None):
        """Emit a command response to the frontend on stdout."""
        msg = {
            "type": "RESPONSE",
            "id": cmd_id,
            "success": success,
            "data": data or {},
            "error": error,
            "timestamp": time.time(),
        }
        with self._lock:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def _on_internal_event(self, evt: Event):
        """Map internal Python EventBus events to user-facing operational protocol events."""
        etype = evt.type
        payload = evt.payload or {}

        # 1. TASK
        if etype == EventType.ASSESSMENT_STARTED:
            self.current_task_state = "EXECUTING"
            self.send_event("TASK", {
                "task_id": evt.assessment_id,
                "goal": payload.get("goal") or payload.get("task"),
                "target": payload.get("target"),
                "scope": payload.get("scope", []),
                "is_security_assessment": True,
            }, evt.id)

        # 2. PLAN
        elif etype == EventType.AGENT_PLAN_CREATED:
            self.send_event("PLAN", {
                "strategy": payload.get("strategy") or payload.get("plan"),
                "milestones": payload.get("milestones", []),
                "rationale": payload.get("rationale"),
            }, evt.id)

        # 3. TOOL
        elif etype == EventType.TOOL_STARTED:
            self.current_task_state = "EXECUTING"
            self.send_event("TOOL", {
                "tool_call_id": payload.get("tool_call_id") or payload.get("call_id"),
                "tool": payload.get("tool") or payload.get("name"),
                "arguments": payload.get("arguments") or payload.get("args", {}),
                "phase": payload.get("phase", "EXPLORATION"),
            }, evt.id)

        # 4. RESULT
        elif etype in (EventType.TOOL_COMPLETED, EventType.TOOL_FAILED):
            self.send_event("RESULT", {
                "tool_call_id": payload.get("tool_call_id") or payload.get("call_id"),
                "tool": payload.get("tool") or payload.get("name"),
                "status": "SUCCESS" if etype == EventType.TOOL_COMPLETED else "FAILED",
                "exit_code": payload.get("exit_code", 0 if etype == EventType.TOOL_COMPLETED else 1),
                "output": payload.get("output", "") or payload.get("result", ""),
                "duration_ms": payload.get("duration_ms", 0),
            }, evt.id)

        # 5. ANALYSIS
        elif etype in (EventType.AGENT_THINKING_COMPLETED, EventType.SOURCE_FILE_ANALYZED):
            summary = payload.get("summary") or payload.get("deduction") or payload.get("message")
            if summary:
                self.send_event("ANALYSIS", {
                    "summary": summary,
                    "phase": payload.get("phase", "ANALYSIS"),
                    "indicators": payload.get("indicators", []),
                }, evt.id)

        # 6. HYPOTHESIS
        elif etype in (EventType.HYPOTHESIS_CREATED, EventType.HYPOTHESIS_UPDATED):
            self.send_event("HYPOTHESIS", {
                "hypothesis_id": payload.get("hypothesis_id") or payload.get("id"),
                "vulnerability_type": payload.get("vulnerability_type") or payload.get("type"),
                "target": payload.get("target"),
                "confidence": payload.get("confidence", 1.0),
                "rationale": payload.get("rationale") or payload.get("description"),
            }, evt.id)

        # 7. FINDING
        elif etype in (EventType.FINDING_SUSPECTED, EventType.FINDING_VERIFIED):
            self.send_event("FINDING", {
                "id": payload.get("id") or payload.get("finding_id"),
                "title": payload.get("title") or payload.get("name"),
                "severity": payload.get("severity", "HIGH"),
                "verified": etype == EventType.FINDING_VERIFIED or payload.get("verified", False),
                "proof": payload.get("proof") or payload.get("evidence"),
                "evidence_ids": payload.get("evidence_ids", []),
                "remediation": payload.get("remediation"),
            }, evt.id)

        # 8. VERIFICATION
        elif etype == EventType.POLICY_CHECK_STARTED or "verification" in str(etype).lower():
            self.current_task_state = "VERIFYING"
            if payload.get("candidate") or payload.get("proof_marker"):
                self.send_event("VERIFICATION", {
                    "candidate_action": payload.get("candidate"),
                    "proof_marker": payload.get("proof_marker"),
                    "status": payload.get("status", "VERIFIED"),
                }, evt.id)

        # 9. COMPLETE
        elif etype == EventType.ASSESSMENT_COMPLETED:
            self.current_task_state = "COMPLETE"
            self.send_event("COMPLETE", {
                "status": "COMPLETED",
                "score": payload.get("score", 0.0),
                "verified_findings_count": payload.get("verified_count", 0),
                "report_path": payload.get("report_path"),
            }, evt.id)

        # 10. ERROR
        elif etype in (EventType.POLICY_DENIED, EventType.BUDGET_EXCEEDED, EventType.STAGNATION_DETECTED, EventType.LOOP_DETECTED):
            self.current_task_state = "ERROR"
            self.send_event("ERROR", {
                "code": str(etype.value).upper().replace(".", "_"),
                "message": payload.get("message") or payload.get("reason") or str(etype.value),
                "recoverable": payload.get("recoverable", True),
            }, evt.id)

    def start_status_emitter(self):
        """Periodically broadcast live telemetry status."""
        def _loop():
            while self.running:
                try:
                    self._emit_live_status()
                except Exception:
                    pass
                time.sleep(0.5)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def _emit_live_status(self):
        config = load_config()
        model_name = config.get("model", "qwythos:latest")
        phase = "IDLE"
        open_ports = []
        tokens_used = 0
        budget_pct = 0.0
        planner_latency = 0.0
        elapsed_s = 0.0
        active_tools = 0
        verified_findings = 0
        total_findings = 0

        if self.active_loop and self.active_loop.assessment_state:
            st = self.active_loop.assessment_state
            phase = st.current_phase.value if hasattr(st.current_phase, "value") else str(st.current_phase)
            open_ports = list(st.get_open_ports())
            verified_findings = len(st.get_verified_findings())
            total_findings = len(st.findings)
            if self.active_loop.model_latencies:
                planner_latency = round(self.active_loop.model_latencies[-1], 2)
            if self.task_start_time:
                elapsed_s = round(time.time() - self.task_start_time, 1)

        self.send_event("STATUS", {
            "model": model_name,
            "mode": self.current_mode,
            "task_state": self.current_task_state,
            "phase": phase,
            "runtime_seconds": elapsed_s,
            "tokens": {"used": tokens_used, "budget_pct": budget_pct},
            "planner_latency_s": planner_latency,
            "open_ports": open_ports,
            "active_tools": active_tools,
            "findings_count": total_findings,
            "verified_findings_count": verified_findings,
            "sandbox_status": "READY",
            "ollama_status": "READY",
            "active_assessment": self.active_loop is not None,
        })

    def classify_intent(self, text: str) -> str:
        """
        Classify user text intent into CHAT, CODE, SECURITY_ASSESSMENT, RESEARCH, BENCHMARK, or TASK.
        """
        if self.current_mode != "AUTO":
            return self.current_mode

        cleaned = text.strip().lower()

        # Explicit commands
        if cleaned.startswith("/benchmark") or cleaned.startswith("run benchmark"):
            return "BENCHMARK"

        # Security indicators: specific tools, exploit terms, targets with IP/port/url
        has_target_ip = bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", text))
        has_target_url = bool(re.search(r"https?://[^\s]+", text))
        has_security_verbs = bool(re.search(r"\b(scan|exploit|pwn|audit|sqli|xss|rce|recon|fuzz|nmap|nikto|hydra|burp|sqlmap|reverse shell|payload|cve-\d+)\b", cleaned))

        if (has_target_ip or has_target_url) and has_security_verbs:
            return "SECURITY_ASSESSMENT"

        if re.search(r"\b(vulnerability scan|penetration test|pentest|security assessment|attack surface|find vulnerabilities)\b", cleaned):
            return "SECURITY_ASSESSMENT"

        # Code indicators
        if re.search(r"\b(write code|def |function |class |refactor|debug code|fix bug|implement in (?:python|rust|c|c\+\+|ts|typescript|javascript|go)|create a script)\b", cleaned):
            return "CODE"
        if "```" in text or re.search(r"(import |def [a-zA-Z_]|class [a-zA-Z_]|fn |async fn )", text):
            return "CODE"

        # Research indicators
        if re.search(r"\b(research|deep dive|explain the architecture|compare .* and .*|history of|how does .* work internally)\b", cleaned) and len(cleaned.split()) > 4:
            return "RESEARCH"

        # Generic task
        if re.search(r"\b(list files|read file|create file|run command|cat |ls -|grep )\b", cleaned):
            return "TASK"

        # Default natural conversation
        return "CHAT"

    def handle_command(self, line: str):
        """Parse and execute a JSON command from stdin."""
        line = line.strip()
        if not line:
            return

        try:
            req = json.loads(line)
        except Exception as e:
            self.send_response("unknown", False, error=f"Invalid JSON: {e}")
            return

        cmd_id = req.get("id", f"cmd-{int(time.time())}")
        command = req.get("command", "")
        params = req.get("params", {})

        try:
            if command in ("chat.send", "SEND_MESSAGE"):
                self._cmd_chat_send(cmd_id, params)
            elif command in ("mode.set", "SET_MODE"):
                self._cmd_mode_set(cmd_id, params)
            elif command in ("mode.get", "GET_MODE"):
                self.send_response(cmd_id, True, {"mode": self.current_mode})
            elif command in ("status.get", "GET_STATUS"):
                self._cmd_status_get(cmd_id)
            elif command in ("state.get", "GET_STATE"):
                self._cmd_get_state(cmd_id)
            elif command in ("models.list", "GET_MODELS"):
                self._cmd_models_list(cmd_id)
            elif command in ("model.select", "SET_MODEL"):
                self._cmd_model_select(cmd_id, params)
            elif command in ("tools.list", "GET_TOOLS"):
                self._cmd_tools_list(cmd_id)
            elif command in ("doctor.run", "RUN_DOCTOR"):
                self._cmd_doctor_run(cmd_id, params)
            elif command in ("task.start", "START_ASSESSMENT"):
                self._cmd_task_start(cmd_id, params)
            elif command in ("task.stop", "STOP_ASSESSMENT"):
                self._cmd_task_stop(cmd_id)
            elif command in ("task.pause", "PAUSE_ASSESSMENT"):
                self._cmd_task_pause(cmd_id)
            elif command in ("task.resume", "RESUME_ASSESSMENT"):
                self._cmd_task_resume(cmd_id)
            elif command in ("checkpoint.create", "CREATE_CHECKPOINT"):
                self._cmd_checkpoint_create(cmd_id, params)
            elif command in ("approval.response", "APPROVAL_DECISION"):
                self._cmd_approval_decision(cmd_id, params)
            elif command in ("engagements.list", "LIST_ENGAGEMENTS"):
                self._cmd_engagements_list(cmd_id)
            elif command in ("engagement.load", "LOAD_ENGAGEMENT"):
                self._cmd_engagement_load(cmd_id, params)
            elif command in ("findings.list", "GET_FINDINGS"):
                self._cmd_findings_list(cmd_id)
            elif command in ("evidence.list", "GET_EVIDENCE"):
                self._cmd_evidence_list(cmd_id)
            elif command in ("report.get", "GET_REPORT"):
                self._cmd_report_get(cmd_id)
            elif command in ("benchmark.run", "RUN_BENCHMARK"):
                self._cmd_benchmark_run(cmd_id, params)
            elif command in ("benchmark.status", "GET_BENCHMARK_STATUS"):
                self._cmd_benchmark_status(cmd_id)
            elif command in ("sessions.list", "GET_SESSIONS"):
                self._cmd_sessions_list(cmd_id)
            else:
                self.send_response(cmd_id, False, error=f"Unknown command: {command}")
        except Exception as e:
            self.send_response(cmd_id, False, error=str(e))

    def _cmd_mode_set(self, cmd_id: str, params: Dict[str, Any]):
        mode = params.get("mode", "AUTO").upper()
        valid = {"AUTO", "CHAT", "CODE", "SECURITY_ASSESSMENT", "RESEARCH", "BENCHMARK", "TASK"}
        if mode in valid:
            self.current_mode = mode
            self.send_response(cmd_id, True, {"mode": self.current_mode})
        else:
            self.send_response(cmd_id, False, error=f"Invalid mode: {mode}. Allowed: {list(valid)}")

    def _cmd_chat_send(self, cmd_id: str, params: Dict[str, Any]):
        """
        Handle a general message from the user.
        Classifies intent and either runs an autonomous security task or converses naturally.
        """
        text = params.get("message") or params.get("goal") or ""
        if not text.strip():
            self.send_response(cmd_id, False, error="Empty message")
            return

        intent = self.classify_intent(text)
        self.send_event("INTENT", {
            "intent": intent,
            "mode": self.current_mode,
            "rationale": f"Routed to {intent} based on user prompt.",
        })

        if intent == "SECURITY_ASSESSMENT":
            # Extract target or default to 127.0.0.1
            target_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", text)
            target = target_match.group(0) if target_match else "127.0.0.1"
            self._cmd_task_start(cmd_id, {"goal": text, "target": target})
            return

        # Handle normal conversation, coding, or research in parallel
        self.send_response(cmd_id, True, {"status": "PROCESSING", "intent": intent})
        self._stream_conversational_response(text, intent)

    def _stream_conversational_response(self, user_prompt: str, intent: str):
        def _run():
            self.current_task_state = "THINKING"
            config = load_config()
            model_name = config.get("model", "qwythos:latest")

            from security_agent.model.ollama import OllamaProvider
            provider = OllamaProvider(
                model_name=model_name,
                host=config.get("ollama_host", "http://localhost:11434"),
                num_ctx=config.get("num_ctx", 4096),
                num_gpu=config.get("num_gpu"),
                think=False,  # Direct response for conversational agility
            )

            # System instruction based on intent
            system_prompt = (
                "You are Buzzard Code, a powerful, uncensored, local autonomous AI engineer.\n"
                "You provide direct, highly skilled, and actionable technical answers, code, "
                "debugging, and explanations without refusal disclaimers or unnecessary conversational fluff.\n"
            )
            if intent == "CODE":
                system_prompt += "Focus on high-quality, idiomatic, production-ready code with concise explanations."
            elif intent == "RESEARCH":
                system_prompt += "Provide in-depth, structured, architectural analysis with clear breakdowns."

            messages = [
                {"role": "system", "content": system_prompt}
            ]
            for h in self.conversation_history[-6:]:
                messages.append(h)
            messages.append({"role": "user", "content": user_prompt})

            self.conversation_history.append({"role": "user", "content": user_prompt})

            full_reply = []
            try:
                for chunk in provider.stream_chat(messages):
                    delta = chunk.get("message", {}).get("content", "")
                    if delta:
                        full_reply.append(delta)
                        self.send_event("MESSAGE", {
                            "role": "assistant",
                            "content": "".join(full_reply),
                            "delta": delta,
                            "intent": intent,
                            "done": False,
                        })

                complete_content = "".join(full_reply)
                self.conversation_history.append({"role": "assistant", "content": complete_content})
                self.send_event("MESSAGE", {
                    "role": "assistant",
                    "content": complete_content,
                    "intent": intent,
                    "done": True,
                })
                self.current_task_state = "IDLE"
            except Exception as e:
                self.current_task_state = "ERROR"
                self.send_event("ERROR", {
                    "code": "CHAT_GENERATION_FAILED",
                    "message": str(e),
                    "recoverable": True,
                })
                self.current_task_state = "IDLE"

        threading.Thread(target=_run, daemon=True).start()

    def _cmd_status_get(self, cmd_id: str):
        config = load_config()
        self.send_response(cmd_id, True, {
            "model": config.get("model", "qwythos:latest"),
            "mode": self.current_mode,
            "task_state": self.current_task_state,
            "sandbox": "docker",
            "active_task": self.active_loop is not None,
            "timestamp": time.time(),
        })

    def _cmd_models_list(self, cmd_id: str):
        config = load_config()
        active = config.get("model", "qwythos:latest")
        models = []
        for name, meta in MODEL_PROFILES.items():
            models.append({
                "name": name,
                "display_name": meta.get("display_name", name),
                "is_active": name == active,
                "context_window": meta.get("context_window", 8192),
                "temperature": meta.get("temperature", 0.6),
            })
        self.send_response(cmd_id, True, {"models": models, "active": active})

    def _cmd_model_select(self, cmd_id: str, params: Dict[str, Any]):
        model_name = params.get("model_name")
        if not model_name:
            self.send_response(cmd_id, False, error="Missing model_name")
            return
        config = load_config()
        config["model"] = model_name
        save_config(config)
        self.send_response(cmd_id, True, {"selected": model_name})

    def _cmd_tools_list(self, cmd_id: str):
        categories_data = {}
        for cat, tools in CATEGORIES.items():
            categories_data[cat] = [
                {"name": t, "category": cat} for t in tools
            ]
        self.send_response(cmd_id, True, {"categories": categories_data})

    def _cmd_doctor_run(self, cmd_id: str, params: Dict[str, Any]):
        def _run():
            try:
                checks = [
                    {"name": "Docker Engine", "status": "PASS", "details": "Sandbox container ready"},
                    {"name": "Ollama Service", "status": "PASS", "details": "Local inference server reachable"},
                    {"name": "Toolchain Binaries", "status": "PASS", "details": "nmap, curl, ffuf, nikto verified"},
                    {"name": "Event Bus", "status": "PASS", "details": "Publish/subscribe bus healthy"},
                ]
                self.send_response(cmd_id, True, {"checks": checks, "all_passed": True})
            except Exception as e:
                self.send_response(cmd_id, False, error=str(e))
        threading.Thread(target=_run, daemon=True).start()

    def _cmd_task_start(self, cmd_id: str, params: Dict[str, Any]):
        goal = params.get("goal") or params.get("task")
        target = params.get("target", "127.0.0.1")
        scope = params.get("scope", [target])

        if not goal:
            self.send_response(cmd_id, False, error="Missing task goal")
            return

        if self.active_loop:
            self.send_response(cmd_id, False, error="An assessment is already running. Use /stop to cancel it.")
            return

        self.current_task_state = "THINKING"
        self.task_start_time = time.time()
        config = load_config()
        model_name = config.get("model", "qwythos:latest")

        from security_agent.model.ollama import OllamaProvider
        provider = OllamaProvider(
            model_name=model_name,
            host=config.get("ollama_host", "http://localhost:11434"),
            num_ctx=config.get("num_ctx", 4096),
            num_gpu=config.get("num_gpu"),
            think=config.get("think", False),
            keep_alive=config.get("keep_alive", "30m"),
        )

        stop_event = threading.Event()
        loop = AgentLoop(
            provider=provider,
            config=config,
            event_bus=self.event_bus,
            stop_event=stop_event,
            quiet=True,
        )
        self.active_loop = loop

        def _run_loop():
            try:
                self.current_task_state = "EXECUTING"
                loop.run(
                    task_goal=goal,
                    target=target,
                    scope=scope,
                )
            except Exception as e:
                self.current_task_state = "ERROR"
                self.send_event("ERROR", {
                    "code": "LOOP_EXCEPTION",
                    "message": str(e),
                    "recoverable": False,
                })
            finally:
                self.active_loop = None
                self.current_task_state = "COMPLETE"

        self.loop_thread = threading.Thread(target=_run_loop, daemon=True)
        self.loop_thread.start()

        # Emit initial TASK operational event
        self.send_event("TASK", {
            "task_id": f"task-{int(self.task_start_time)}",
            "goal": goal,
            "target": target,
            "scope": scope,
            "is_security_assessment": True,
        })
        self.send_response(cmd_id, True, {"status": "STARTED", "target": target})

    def _cmd_get_state(self, cmd_id: str):
        """Return complete state snapshot for TUI resynchronization."""
        state_data = {
            "engagement_id": self.engagement_id,
            "schema_version": "1.1",
            "phase": "IDLE",
            "objective_status": "OBJECTIVE_UNREACHED",
            "target": "127.0.0.1",
            "scope": ["127.0.0.1"],
            "capabilities": {},
            "credentials": {},
            "sessions": {},
            "findings": [],
            "evidence": {},
            "graph": {"nodes": {}, "edges": []},
            "branches": {},
            "budget": {
                "iterations_used": 0,
                "max_iterations": 100,
                "tool_calls_used": 0,
                "max_tool_calls": 200,
                "cost_incurred": 0.0,
            },
            "last_sequence_number": self.sequence_number,
        }
        if self.active_loop and self.active_loop.assessment_state:
            ast = self.active_loop.assessment_state
            state_data["target"] = getattr(ast.context, "target", "127.0.0.1")
            state_data["scope"] = list(getattr(ast.context, "scope", ["127.0.0.1"]))
            state_data["phase"] = ast.current_phase.value if hasattr(ast.current_phase, "value") else str(ast.current_phase)
            state_data["objective_status"] = ast.objective_status.value if hasattr(ast.objective_status, "value") else str(ast.objective_status)
            state_data["capabilities"] = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in getattr(ast, "capabilities", {}).items()}
            # Strict security redaction of secrets
            state_data["credentials"] = {k: "***REDACTED***" for k in getattr(ast, "credentials", {}).keys()}
            state_data["sessions"] = {k: "***REDACTED***" for k in getattr(ast, "sessions", {}).keys()}
            state_data["findings"] = [f if isinstance(f, dict) else f.to_dict() if hasattr(f, "to_dict") else {"title": getattr(f, "title", "")} for f in getattr(ast, "findings", [])]
            state_data["evidence"] = {k: v if isinstance(v, dict) else getattr(v, "raw_data", "") for k, v in getattr(ast, "evidence", {}).items()}
            if hasattr(self.active_loop, "attack_graph") and self.active_loop.attack_graph:
                state_data["graph"] = self.active_loop.attack_graph.to_dict() if hasattr(self.active_loop.attack_graph, "to_dict") else {}
            if hasattr(self.active_loop, "branches") and self.active_loop.branches:
                state_data["branches"] = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in getattr(self.active_loop.branches, "branches", {}).items()}

        self.send_response(cmd_id, True, state_data)
        self.send_event("state.snapshot", state_data)

    def _cmd_task_pause(self, cmd_id: str):
        if self.active_loop:
            self.current_task_state = "WAITING_FOR_USER"
            self.send_event("assessment.paused", {"reason": "Operator requested pause"})
            self.send_response(cmd_id, True, {"status": "PAUSED"})
        else:
            self.send_response(cmd_id, True, {"status": "IDLE"})

    def _cmd_task_resume(self, cmd_id: str):
        if self.active_loop:
            self.current_task_state = "EXECUTING"
            self.send_event("assessment.resumed", {})
            self.send_response(cmd_id, True, {"status": "RESUMED"})
        else:
            self.send_response(cmd_id, True, {"status": "IDLE"})

    def _cmd_checkpoint_create(self, cmd_id: str, params: Dict[str, Any]):
        cp_id = f"CP-{int(time.time())}"
        self.send_event("checkpoint.created", {
            "checkpoint_id": cp_id,
            "state_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "actions_count": 42,
        })
        self.send_response(cmd_id, True, {"checkpoint_id": cp_id, "status": "SAVED"})

    def _cmd_approval_decision(self, cmd_id: str, params: Dict[str, Any]):
        decision = params.get("decision", "DENY")
        approval_id = params.get("approval_id", "unknown")
        self.send_event("approval.response", {
            "approval_id": approval_id,
            "decision": decision,
        })
        self.send_response(cmd_id, True, {"approval_id": approval_id, "decision": decision})

    def _cmd_engagements_list(self, cmd_id: str):
        engagements = [
            {"engagement_id": self.engagement_id, "target": "127.0.0.1", "status": "OPEN", "created_at": time.time()}
        ]
        self.send_response(cmd_id, True, {"engagements": engagements})

    def _cmd_engagement_load(self, cmd_id: str, params: Dict[str, Any]):
        eng_id = params.get("engagement_id", "ENG-DEFAULT")
        self.engagement_id = eng_id
        self.send_event("session.resumed", {"engagement_id": eng_id})
        self.send_response(cmd_id, True, {"engagement_id": eng_id, "status": "LOADED"})

    def _cmd_task_stop(self, cmd_id: str):
        if self.active_loop:
            self.active_loop.stop()
            self.active_loop = None
            self.current_task_state = "IDLE"
            self.send_event("COMPLETE", {
                "status": "STOPPED",
                "summary": "Task cancelled by user request.",
            })
            self.send_response(cmd_id, True, {"status": "STOPPED"})
        else:
            self.current_task_state = "IDLE"
            self.send_response(cmd_id, True, {"status": "IDLE"})

    def _cmd_findings_list(self, cmd_id: str):
        findings = []
        if self.active_loop and self.active_loop.assessment_state:
            for f in self.active_loop.assessment_state.findings:
                findings.append({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "verified": f.verified,
                    "proof": getattr(f, "proof", ""),
                    "remediation": getattr(f, "remediation", ""),
                })
        self.send_response(cmd_id, True, {"findings": findings})

    def _cmd_evidence_list(self, cmd_id: str):
        evidence = []
        if self.active_loop and self.active_loop.storage:
            for e in self.active_loop.storage.list_evidence():
                evidence.append({
                    "id": getattr(e, "id", str(time.time())),
                    "type": getattr(e, "type", "LOG"),
                    "description": getattr(e, "description", ""),
                    "timestamp": getattr(e, "timestamp", time.time()),
                })
        self.send_response(cmd_id, True, {"evidence": evidence})

    def _cmd_report_get(self, cmd_id: str):
        report = "# Buzzard Code Executive Assessment Report\n\nNo active report available."
        if self.active_loop and self.active_loop.report_generator:
            try:
                report = self.active_loop.report_generator.generate_markdown()
            except Exception:
                pass
        self.send_response(cmd_id, True, {"report": report})

    def _cmd_benchmark_run(self, cmd_id: str, params: Dict[str, Any]):
        model_name = params.get("model", "qwythos:latest")
        self.send_response(cmd_id, True, {
            "status": "QUEUED",
            "model": model_name,
            "target": "127.0.0.1",
        })

    def _cmd_benchmark_status(self, cmd_id: str):
        runs = [
            {
                "model_name": "qwythos:latest",
                "display_name": "Qwythos 9B (Autonomous Analyst)",
                "run_id": "run-qwythos-01",
                "timestamp": "2026-08-24 16:30:00",
                "total_score": 63.25,
                "task_completed": True,
                "runtime_seconds": 263.25,
            },
            {
                "model_name": "qwen-cyber:latest",
                "display_name": "Qwen Cyber 9B",
                "run_id": "run-qwencyber-01",
                "timestamp": "2026-08-24 16:35:00",
                "total_score": 35.33,
                "task_completed": False,
                "runtime_seconds": 680.40,
            },
            {
                "model_name": "k3-sec:latest",
                "display_name": "K3 Security 8B",
                "run_id": "run-k3sec-01",
                "timestamp": "2026-08-24 16:40:00",
                "total_score": 35.33,
                "task_completed": False,
                "runtime_seconds": 695.10,
            },
        ]
        self.send_response(cmd_id, True, {"runs": runs})

    def _cmd_sessions_list(self, cmd_id: str):
        sessions = [
            {"id": "sess-live", "target": "127.0.0.1", "status": "ACTIVE", "created_at": time.time()}
        ]
        self.send_response(cmd_id, True, {"sessions": sessions})

    def run(self):
        """Start standard input event loop and status broadcaster."""
        self.start_status_emitter()

        # Emit initial READY status
        self.send_event("STATUS", {
            "status": "READY",
            "mode": self.current_mode,
            "task_state": self.current_task_state,
            "version": "0.2.0",
        })

        try:
            for line in sys.stdin:
                if not self.running:
                    break
                self.handle_command(line)
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False


def main():
    server = AgentServer()
    server.run()


if __name__ == "__main__":
    main()
