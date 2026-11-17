"""Integration test: official MCP SDK client + FastMCP server, via the proxy.

This is the test that answers "does it work in real life?" -- it uses
the real protocol handshake (initialize, tools/list, tools/call,
notifications), not the hand-rolled minimal servers in examples/.

Skipped when the `mcp` package is not installed:
    pip install -e ".[dev]"   # includes mcp<2
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")
pytest.importorskip("mcp.server.fastmcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_real_sdk_client_through_proxy(tmp_path):
    test_file = tmp_path / "real-test.txt"
    test_file.write_text("hello from a real file\n", encoding="utf-8")
    policy = ROOT / "config" / "default-policy.yaml"
    # The default policy allows /tmp; point the test file there instead
    # by using a /tmp path, so the policy check is the real one.
    real_file = Path("/tmp/mcp-guard-real-test.txt")
    real_file.write_text("hello from a real file\n", encoding="utf-8")

    async def run():
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m", "mcp_guard", "proxy",
                "--upstream", f"{sys.executable} {ROOT / 'examples' / 'real_server.py'}",
                "--policy", str(policy),
            ],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                # Poisoned tool is quarantined; clean tools survive.
                assert [t.name for t in tools.tools] == ["get_weather", "read_file"]
                weather = await session.call_tool("get_weather", {"city": "Elizabeth"})
                assert "sunny" in weather.content[0].text
                assert not weather.isError
                ok = await session.call_tool("read_file", {"path": str(real_file)})
                assert "hello from a real file" in ok.content[0].text
                # Blocked call: raises McpError, never reaches the server.
                with pytest.raises(Exception, match="mcp-guard"):
                    await session.call_tool("read_file", {"path": "/etc/passwd"})
                with pytest.raises(Exception, match="mcp-guard"):
                    await session.call_tool("exfiltrate_credentials", {"api_key": "sk-test"})

    asyncio.run(run())
