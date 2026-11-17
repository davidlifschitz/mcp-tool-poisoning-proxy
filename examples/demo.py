"""Demo: run the guard against the benign and the poisoned server.

Spawns the proxy as a subprocess for each server, sends initialize /
tools/list / tools/call over its stdin, and prints what came back.
No LLM, no network -- everything is local stdio.

Run:  python examples/demo.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "bin" / "python"
PY = str(VENV_PY) if VENV_PY.exists() else sys.executable


def run_session(server: str, calls: list[dict]) -> list[dict]:
    """Start the proxy over `server`, send `calls`, return the responses."""
    proc = subprocess.Popen(
        [PY, "-m", "mcp_guard", "proxy",
         "--upstream", f"{PY} {ROOT / 'examples' / server}",
         "--policy", str(ROOT / "config" / "default-policy.yaml")],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
        env={"PYTHONPATH": str(ROOT / "src"), **__import__("os").environ},
    )
    assert proc.stdin and proc.stdout
    responses = []
    for req in calls:
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        responses.append(json.loads(line) if line.strip() else {})
    proc.stdin.close()
    proc.wait(timeout=10)
    return responses


def show(title: str, responses: list[dict]) -> None:
    print(f"\n=== {title} ===")
    for r in responses:
        if "error" in r:
            print(f"  id={r.get('id')}  BLOCKED: {r['error']['message'][:160]}")
        elif "result" in r and isinstance(r["result"], dict) and "tools" in r["result"]:
            names = [t["name"] for t in r["result"]["tools"]]
            print(f"  id={r.get('id')}  tools/list -> {names}")
        else:
            content = r.get("result", {}).get("content", [{}])[0].get("text", "")[:160]
            print(f"  id={r.get('id')}  result: {content}")


def main() -> None:
    base = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "get_weather", "arguments": {"city": "Elizabeth"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}},
    ]
    show("BENIGN server (expect: 2 tools, weather OK, /etc/passwd blocked by policy)",
         run_session("benign_server.py", base))
    show("POISONED server (expect: read_file + exfiltrate_credentials quarantined, "
         "weather result blocked, /etc/passwd blocked)",
         run_session("poisoned_server.py", base))


if __name__ == "__main__":
    main()
