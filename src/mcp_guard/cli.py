"""CLI for mcp-guard.

Usage:
  # Proxy an MCP server (stdio) through the guard:
  python -m mcp_guard proxy --upstream "python examples/poisoned_server.py" \
      --policy config/default-policy.yaml --audit audit.jsonl

  # Scan a tool definition file offline (no server needed):
  python -m mcp_guard scan examples/poisoned-tools.json

  # Check one tools/call against the policy:
  python -m mcp_guard check --tool read_file --args '{"path": "/etc/passwd"}'
"""
from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditLogger
from .detectors import scan_tool
from .policies import Policy, validate_call
from .proxy import run_proxy

__version__ = "0.1.0"


def _load_policy(path: str | None) -> Policy:
    return Policy.from_yaml(path) if path else Policy.default()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-guard", description="MCP Tool Poisoning Proxy")
    parser.add_argument("--version", action="version", version=f"mcp-guard {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("proxy", help="Proxy an upstream MCP server over stdio")
    p.add_argument("--upstream", required=True, help='Command to run, e.g. "python examples/poisoned_server.py"')
    p.add_argument("--policy", default=None)
    p.add_argument("--audit", default=None, help="JSONL audit log path")
    p.add_argument("--mode", choices=["enforce", "monitor"], default=None)

    s = sub.add_parser("scan", help="Scan tool definitions in a JSON file for poisoning")
    s.add_argument("file", help="JSON file: a tool object, or a list of tools, or {\"tools\": [...]}")

    c = sub.add_parser("check", help="Validate one tools/call against the policy")
    c.add_argument("--tool", required=True)
    c.add_argument("--args", default="{}", help='JSON arguments, e.g. \'{"path": "/tmp/x"}\'')
    c.add_argument("--policy", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "proxy":
        return run_proxy(args.upstream, args.policy, args.audit, args.mode)

    if args.cmd == "scan":
        with open(args.file, encoding="utf-8") as f:
            data = json.load(f)
        tools = data["tools"] if isinstance(data, dict) and "tools" in data else (
            data if isinstance(data, list) else [data])
        poisoned = 0
        for tool in tools:
            scan = scan_tool(tool)
            status = "POISONED" if scan.is_poisoned else ("flagged" if scan.findings else "clean")
            if scan.is_poisoned:
                poisoned += 1
            print(f"{tool.get('name', '?')}: {status} (risk={scan.risk_score})")
            for f in scan.findings:
                print(f"  - [{f.category}] {f.reason}: {f.matched!r}")
        print(f"{poisoned} poisoned / {len(tools)} tools")
        return 1 if poisoned else 0

    if args.cmd == "check":
        policy = _load_policy(args.policy)
        decision = validate_call(policy, args.tool, json.loads(args.args))
        print("ALLOW" if decision.allowed else "BLOCK")
        for r in decision.reasons:
            print(f"  - {r}")
        return 0 if decision.allowed else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
