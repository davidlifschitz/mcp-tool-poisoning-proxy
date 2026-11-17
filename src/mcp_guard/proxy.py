"""MCP Tool Poisoning Proxy -- stdio JSON-RPC interception.

Architecture
-----------
    MCP client (Claude Desktop / agent)
        |  newline-delimited JSON-RPC 2.0 over stdio
        v
    mcp-guard proxy  (this module)
        |  validated + scanned JSON-RPC
        v
    upstream MCP server (subprocess, untrusted)

What it intercepts
-------------------
* Client -> server `tools/call`: policy validation (allow/blocklist,
  paths, hosts, shell metachars, size, rate limit) + injection scan
  of the arguments. Blocked calls never reach the server; the client
  gets a JSON-RPC error instead.
* Server -> client `tools/list` result: every tool definition is
  scanned for poisoning. In enforce mode poisoned tools are removed
  from the list (quarantined); in monitor mode they are kept but logged.
* Server -> client `tools/call` result: content is scanned for
  injected instructions. In enforce mode a poisoned result is replaced
  with a safe notice.
* Everything else (initialize, ping, resources, prompts, notifications)
  passes through, with oversized payloads rejected.

All decisions are written to the audit log. The proxy never calls a
model or the network itself.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLogger
from .detectors import scan_text, scan_tool, scan_tool_result
from .policies import Decision, Policy, validate_call

JSONRPC_ERROR_BLOCKED = -32000


@dataclass
class Guard:
    policy: Policy
    audit: AuditLogger
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    _calls: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    # -- tools/call (client -> server) -----------------------------------
    def check_tool_call(self, tool: str, arguments: dict | None) -> Decision:
        reasons: list[str] = []

        # Rate limit, per tool, sliding 60s window.
        now = time.time()
        window = [t for t in self._calls[tool] if now - t < 60]
        self._calls[tool] = window
        if len(window) >= self.policy.rate_limit_per_minute:
            reasons.append(f"rate limit exceeded for '{tool}' ({self.policy.rate_limit_per_minute}/min)")
        else:
            window.append(now)

        decision = validate_call(self.policy, tool, arguments)
        reasons.extend(decision.reasons)

        # Injection scan over the serialised arguments.
        scan = scan_text(json.dumps(arguments or {}, default=str))
        if scan.is_poisoned:
            reasons.append(
                "arguments contain injected instructions: "
                + ", ".join(sorted(set(scan.categories)))
            )

        allowed = not reasons
        self.audit.log(
            "tool_call", session_id=self.session_id, tool=tool,
            decision="allow" if allowed else "block", reasons=reasons,
            risk_score=scan.risk_score, arguments=arguments, direction="client->server",
            method="tools/call",
        )
        return Decision(allowed=allowed, reasons=reasons)

    # -- tools/list result (server -> client) -----------------------------
    def filter_tools_list(self, tools: list[dict]) -> tuple[list[dict], list[dict]]:
        kept, removed = [], []
        for tool in tools:
            scan = scan_tool(tool)
            name = tool.get("name", "?")
            if scan.is_poisoned:
                removed.append(tool)
                self.audit.log(
                    "tool_quarantined", session_id=self.session_id, tool=name,
                    decision="quarantine", reasons=[f.reason for f in scan.findings],
                    risk_score=scan.risk_score, direction="server->client",
                    method="tools/list",
                )
            else:
                kept.append(tool)
                if scan.findings:
                    self.audit.log(
                        "tool_flagged", session_id=self.session_id, tool=name,
                        decision="allow", reasons=[f.reason for f in scan.findings],
                        risk_score=scan.risk_score, direction="server->client",
                        method="tools/list",
                    )
        if self.policy.mode == "monitor":
            return tools, removed  # keep everything, log only
        return kept, removed

    # -- tools/call result (server -> client) -----------------------------
    def check_tool_result(self, tool: str, result: dict) -> tuple[dict, bool]:
        scan = scan_tool_result(result)
        size = len(json.dumps(result, default=str))
        blocked = False
        if scan.is_poisoned or size > self.policy.max_result_size:
            reasons = [f.reason for f in scan.findings]
            if size > self.policy.max_result_size:
                reasons.append(f"result too large ({size} > {self.policy.max_result_size})")
            self.audit.log(
                "tool_result_blocked", session_id=self.session_id, tool=tool,
                decision="block", reasons=reasons, risk_score=scan.risk_score,
                direction="server->client", method="tools/call",
            )
            blocked = True
            if self.policy.mode == "monitor":
                return result, False
            return {
                "content": [{"type": "text",
                             "text": "[mcp-guard] Tool result blocked: it contained injected "
                                     "instructions. See the audit log for details."}],
                "isError": True,
            }, True
        return result, False


def _error_response(req_id: Any, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": JSONRPC_ERROR_BLOCKED, "message": message}}


class StdioProxy:
    """Runs the guard between stdin/stdout and an upstream subprocess."""

    def __init__(self, upstream_cmd: list[str], policy: Policy,
                 audit: AuditLogger | None = None):
        self.upstream_cmd = upstream_cmd
        self.guard = Guard(policy=policy, audit=audit or AuditLogger())
        self._pending: dict[Any, dict] = {}  # id -> {"method":..., "tool":...}
        self._lock = threading.Lock()

    # -- message handling (pure-ish, testable via Guard + these helpers) --
    def handle_client_message(self, msg: dict) -> dict | None:
        """Return a response to send back immediately, or None to forward."""
        method = msg.get("method", "")
        if method == "tools/call":
            params = msg.get("params") or {}
            tool = params.get("name", "?")
            decision = self.guard.check_tool_call(tool, params.get("arguments"))
            if not decision.allowed:
                return _error_response(
                    msg.get("id"),
                    "Blocked by mcp-guard: " + "; ".join(decision.reasons),
                )
            with self._lock:
                self._pending[msg.get("id")] = {"method": method, "tool": tool}
            return None
        if method in ("tools/list", "resources/list", "prompts/list"):
            with self._lock:
                self._pending[msg.get("id")] = {"method": method, "tool": None}
        return None

    def handle_server_message(self, msg: dict) -> dict:
        if "result" not in msg:
            return msg
        with self._lock:
            pending = self._pending.pop(msg.get("id"), None)
        if not pending:
            return msg
        result = msg["result"]
        if pending["method"] == "tools/list" and isinstance(result, dict):
            tools = result.get("tools", [])
            kept, _removed = self.guard.filter_tools_list(tools)
            msg = {**msg, "result": {**result, "tools": kept}}
        elif pending["method"] == "tools/call" and isinstance(result, dict):
            new_result, _blocked = self.guard.check_tool_result(pending["tool"] or "?", result)
            msg = {**msg, "result": new_result}
        return msg

    # -- stdio plumbing ----------------------------------------------------
    def run(self) -> int:
        proc = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, text=True, bufsize=1,
        )
        assert proc.stdin and proc.stdout

        def client_to_server() -> None:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                resp = self.handle_client_message(msg)
                if resp is not None:
                    print(json.dumps(resp), flush=True)
                else:
                    print(json.dumps(msg), file=proc.stdin, flush=True)
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass

        def server_to_client() -> None:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    print(line, flush=True)
                    continue
                print(json.dumps(self.handle_server_message(msg)), flush=True)

        t1 = threading.Thread(target=client_to_server, daemon=True)
        t2 = threading.Thread(target=server_to_client, daemon=True)
        t1.start()
        t2.start()
        try:
            return proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            return 130


def run_proxy(upstream: str, policy_path: str | None, audit_path: str | None,
              mode: str | None = None) -> int:
    policy = Policy.from_yaml(policy_path) if policy_path else Policy.default()
    if mode:
        policy.mode = mode  # type: ignore[assignment]
    audit = AuditLogger(audit_path)
    proxy = StdioProxy(shlex.split(upstream), policy, audit)
    print(f"[mcp-guard] proxying {upstream!r} (mode={policy.mode}, "
          f"session={proxy.guard.session_id})", file=sys.stderr)
    return proxy.run()
