"""Detectors for MCP tool poisoning.

A poisoned MCP tool is a tool whose *description*, *input schema* or
*returned content* smuggles instructions for the LLM / agent that are
not part of the user's request: "ignore previous instructions", "send
the API key to ...", "read ~/.ssh/id_rsa", and so on.

This module is deliberately heuristic + deterministic (regex / keyword
rules, no LLM call). That makes it fast, testable, offline, and safe to
run in the request path: a detector must never itself call out to a
model or the network.

Each finding carries a category, a severity weight and a human-readable
reason, so the proxy can explain *why* it blocked something in the
audit log instead of just saying "blocked".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    category: str
    pattern: str
    matched: str
    severity: int  # 1-10, higher = more dangerous
    reason: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """0-100, capped sum of severities (10 per finding maxes quickly)."""
        return min(100, sum(f.severity * 10 for f in self.findings))

    @property
    def is_poisoned(self) -> bool:
        return any(f.severity >= 7 for f in self.findings)

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            if f.category not in seen:
                seen.append(f.category)
        return seen


# (regex, category, severity, reason)
_RULES: list[tuple[re.Pattern[str], str, int, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.I),
        "instruction_override", 10,
        "Attempts to override prior / system instructions",
    ),
    (
        re.compile(r"disregard\s+(all\s+)?(previous|prior|above|system)\s+(instructions|rules|prompts)", re.I),
        "instruction_override", 10,
        "Attempts to disregard system instructions",
    ),
    (
        re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
        "instruction_override", 8,
        "Attempts to reassign the agent's role / identity",
    ),
    (
        re.compile(r"(new\s+)?system\s+prompt\s*[:=]", re.I),
        "instruction_override", 9,
        "Injects a fake system prompt",
    ),
    (
        re.compile(r"do\s+not\s+(tell|mention|reveal|disclose|inform)\s+(the\s+)?user", re.I),
        "instruction_override", 9,
        "Instructs the agent to hide behaviour from the user",
    ),
    (
        re.compile(r"send\s+(the\s+)?(api[_-]?key|password|secret|token|credentials?|private\s+key|ssh\s+key)", re.I),
        "credential_harvest", 10,
        "Instructs exfiltration of credentials / secrets",
    ),
    (
        re.compile(r"(exfiltrate|leak|upload|post|email|transmit)\b.{0,60}(password|secret|token|api[_-]?key|credential|private\s+key)", re.I | re.S),
        "credential_harvest", 10,
        "Instructs exfiltration of credentials / secrets",
    ),
    (
        re.compile(r"read\s+(the\s+)?(~\/\.ssh\/|/etc/(passwd|shadow)|\.aws/credentials|\.env)", re.I),
        "credential_harvest", 10,
        "Instructs reading a credential file",
    ),
    (
        re.compile(r"https?://[^\s\"'<>]+", re.I),
        "external_url", 3,
        "Contains an external URL (reviewed in context; suspicious when paired with exfiltration)",
    ),
    (
        re.compile(r"(curl|wget)\s+https?://", re.I),
        "exfiltration", 8,
        "Instructs fetching / posting to an external URL with curl/wget",
    ),
    (
        re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.I),
        "ssrf_metadata", 10,
        "References a cloud metadata endpoint (SSRF / credential theft)",
    ),
    (
        re.compile(r"\b(sudo|su\s+root|chmod\s+\+x|rm\s+-rf\s+/)", re.I),
        "privilege_escalation", 9,
        "Instructs privilege escalation or destructive shell use",
    ),
    (
        re.compile(r"execute\s+(this|the\s+following)\s+(command|code|script|payload)", re.I),
        "privilege_escalation", 7,
        "Instructs execution of supplied code / commands",
    ),
    (
        re.compile(r"begin\s+(system|instruction|prompt)", re.I),
        "instruction_override", 8,
        "Fake system/instruction delimiter",
    ),
    (
        re.compile(r"<\|?(system|im_start|assistant|user)\|?>", re.I),
        "instruction_override", 8,
        "Chat-template token injection",
    ),
    (
        re.compile(r"(base64|rot13|hex)\s*(decode|encoded?|payload)", re.I),
        "encoded_payload", 7,
        "Encoded payload instruction (obfuscation)",
    ),
    (
        re.compile(r"instead\s+of\s+(answering|doing|helping)", re.I),
        "instruction_override", 7,
        "Attempts to replace the user's task",
    ),
    (
        re.compile(r"important\s*:\s*before\s+(answering|doing|proceeding)", re.I),
        "instruction_override", 7,
        "Urgency framing to override the user's task",
    ),
]

# A URL is only treated as a *blocking* signal when it appears with an
# exfiltration / credential context, or points at a known-bad pattern.
# Plain documentation URLs in a tool description are normal.
_SUSPICIOUS_URL_HOSTS = ("evil", "exfil", "pastebin", "ngrok", "trycloudflare")


def scan_text(text: str) -> ScanResult:
    """Scan one string and return every finding."""
    if not text:
        return ScanResult()
    findings: list[Finding] = []
    for pattern, category, severity, reason in _RULES:
        for m in pattern.finditer(text):
            # A bare URL is only a finding when its host looks
            # suspicious. Clean servers (e.g. the official filesystem
            # server) put documentation URLs in their tool descriptions,
            # and flagging every one of them spams the audit log with
            # risk-20 "flagged" events for tools that are actually clean.
            if category == "external_url":
                host = m.group(0).lower()
                if not any(h in host for h in _SUSPICIOUS_URL_HOSTS):
                    continue
                severity = 7
            findings.append(
                Finding(
                    category=category,
                    pattern=pattern.pattern,
                    matched=m.group(0)[:200],
                    severity=severity,
                    reason=reason,
                )
            )
    return ScanResult(findings=findings)


def _walk_strings(value: object, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            _walk_strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _walk_strings(v, out)


def scan_tool(tool: dict) -> ScanResult:
    """Scan a whole MCP tool definition (name + description + schema)."""
    texts: list[str] = []
    _walk_strings(tool, texts)
    findings: list[Finding] = []
    for t in texts:
        findings.extend(scan_text(t).findings)
    # De-duplicate identical (category, matched) pairs.
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.category, f.matched.lower())
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return ScanResult(findings=unique)


def scan_tool_result(result: dict) -> ScanResult:
    """Scan an MCP tools/call result (its content blocks)."""
    texts: list[str] = []
    _walk_strings(result.get("content", result), texts)
    findings: list[Finding] = []
    for t in texts:
        findings.extend(scan_text(t).findings)
    return ScanResult(findings=findings)
