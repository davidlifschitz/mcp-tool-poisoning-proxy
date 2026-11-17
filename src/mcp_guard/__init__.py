"""mcp-guard: a defensive MCP Tool Poisoning Proxy.

Intercepts JSON-RPC between an MCP client and an (untrusted) MCP
server, scans tool definitions and results for prompt-injection /
tool poisoning, enforces a Pydantic policy (allow/blocklists, paths,
hosts, size, rate limits), and writes a structured JSONL audit log.
"""
from .audit import AuditLogger, redact
from .detectors import ScanResult, scan_text, scan_tool
from .policies import Decision, Policy, validate_call
from .proxy import Guard, StdioProxy

__all__ = [
    "AuditLogger", "Decision", "Guard", "Policy", "ScanResult",
    "StdioProxy", "redact", "scan_text", "scan_tool", "validate_call",
]
__version__ = "0.1.0"
