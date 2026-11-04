"""
Intent Classification Engine for Buzzard Code.

Routes user inputs between:
- CODING: Autonomous software engineering, repository navigation, bug fixing, test running, file editing.
- SECURITY: Penetration testing, vulnerability scanning, network probing, exploit execution.
- CONVERSATIONAL: Natural language chat, greetings, general questions without tool execution.
"""

from __future__ import annotations

import re
from typing import List, Set

CODE_FILE_EXTENSIONS: Set[str] = {
    "py", "js", "ts", "tsx", "jsx", "rs", "go", "java", "kt", "rb", "php",
    "cs", "swift", "m", "sh", "bash", "zsh", "ps1", "bat", "cmd", "json", "toml", "yaml", "yml",
    "xml", "html", "htm", "css", "scss", "sass", "md", "markdown", "rst", "txt", "log", "sql",
    "lock", "env", "cfg", "ini", "conf"
}

GREETINGS: Set[str] = {
    "hi", "hello", "hey", "sup", "yo", "good morning", "good evening", "good afternoon",
    "howdy", "who are you", "what can you do", "help", "thanks", "thank you",
    "bye", "goodbye", "ok", "okay", "cool", "great", "nice"
}

CODING_PATTERNS: List[re.Pattern] = [
    # Bug fixing & debugging
    re.compile(r"\b(fix|bug|issue|error|traceback|exception|failing|fail|broken|debug|crash|type\s*error)\b", re.IGNORECASE),
    # Implementation & features
    re.compile(r"\b(add|feature|implement|create|build|scaffold|write\s+code|codebase)\b", re.IGNORECASE),
    # Refactoring & editing
    re.compile(r"\b(refactor|edit|modify|update|rewrite|clean\s*up|optimize|format|patch)\b", re.IGNORECASE),
    # Testing & verification
    re.compile(r"\b(test|tests|pytest|unittest|vitest|npm\s+test|cargo\s+test|go\s+test|run\s+test|verify)\b", re.IGNORECASE),
    # Repository & files
    re.compile(r"\b(repo|repository|project|workspace|directory|files?|diff|git|commit|pull\s*request|pr)\b", re.IGNORECASE),
    re.compile(r"\b(explain\s+(?:this|the)\s+(?:repo|repository|codebase|project))\b", re.IGNORECASE),
    # Code structures & programming
    re.compile(r"\b(function|class|method|module|dependency|import|def\s+|async\s+def\s+|var\s+|const\s+|let\s+)\b", re.IGNORECASE),
    # File with code extension (e.g. auth.py, app.ts)
    re.compile(r"\b[a-zA-Z0-9_\-\.\/]+\.(?:" + "|".join(CODE_FILE_EXTENSIONS) + r")\b", re.IGNORECASE),
]

SECURITY_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(pentest|penetration\s+test|vulnerability|vuln\s+scan|nmap|sqlmap|nikto|ffuf|hydra|exploit|brute\s*force|cve-\d+|attack\s+surface|reconnaissance|subdomain\s+enum|port\s+scan|pwn|reverse\s+shell|privilege\s+escalation)\b", re.IGNORECASE),
    re.compile(r"\b(xss|sqli|rce|ssrf|csrf|lfi|rfi|idor)\b", re.IGNORECASE),
]


def is_coding_task(text: str) -> bool:
    """
    Returns True if the text requests software engineering, file editing,
    debugging, testing, or repository-aware development tasks.
    """
    clean = text.strip()
    if not clean:
        return False

    clean_lower = clean.lower()
    if clean_lower in GREETINGS:
        return False

    # Check for explicit coding task indicators
    for pat in CODING_PATTERNS:
        if pat.search(clean):
            return True

    return False


def is_security_task(text: str) -> bool:
    """
    Returns True if the text requests offensive security, vulnerability assessment,
    or targeted network exploitation.
    """
    clean = text.strip()
    if not clean:
        return False

    for pat in SECURITY_PATTERNS:
        if pat.search(clean):
            return True

    # Has target IP or URL with an active action verb
    has_target = bool(
        re.search(r"https?://[^\s]+", clean) or
        re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean)
    )
    if has_target and re.search(r"\b(scan|audit|probe|test|inspect|attack)\b", clean, re.IGNORECASE):
        return True

    return False


def is_actionable_task(text: str) -> bool:
    """
    Returns True if the text is an actionable autonomous agent task
    (either coding or security), as opposed to casual conversation.
    """
    clean = text.strip().lower()
    if not clean or clean in GREETINGS:
        return False

    return is_coding_task(text) or is_security_task(text)


def classify_intent(text: str) -> str:
    """
    Authoritative classifier returning 'CODING', 'SECURITY', or 'CONVERSATIONAL'.
    """
    clean = text.strip().lower()
    if not clean or clean in GREETINGS:
        return "CONVERSATIONAL"

    # Security takes precedence if explicit exploit/scan keywords present
    if is_security_task(text):
        return "SECURITY"

    if is_coding_task(text):
        return "CODING"

    return "CONVERSATIONAL"

