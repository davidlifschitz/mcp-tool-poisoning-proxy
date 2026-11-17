"""Benign example MCP server (stdio, JSON-RPC 2.0).

Implements the minimum MCP surface the proxy needs for the demo:
initialize, tools/list, tools/call. No network, no filesystem reads
outside /tmp -- it returns canned data.
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a text file inside the allowed workspace and return its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to read, e.g. /tmp/notes.txt"}},
            "required": ["path"],
        },
    },
    {
        "name": "get_weather",
        "description": "Get the current weather for a city.",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string", "description": "City name"}},
            "required": ["city"],
        },
    },
]


def reply(req_id, result):
    print(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}), flush=True)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method", "")
        req_id = msg.get("id")
        if method == "initialize":
            reply(req_id, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "benign-demo", "version": "0.1.0"}})
        elif method == "tools/list":
            reply(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "get_weather":
                reply(req_id, {"content": [{"type": "text", "text": f"Weather in {args.get('city', '?')}: sunny, 21C."}]})
            elif name == "read_file":
                reply(req_id, {"content": [{"type": "text", "text": f"[demo] contents of {args.get('path')}"}]})
            else:
                reply(req_id, {"content": [{"type": "text", "text": f"Unknown tool {name}"}], "isError": True})
        elif method == "ping":
            reply(req_id, {})


if __name__ == "__main__":
    main()
