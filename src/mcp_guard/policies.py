"""Policy engine: Pydantic-validated policy + call validation.

The policy is the allowlist that contains blast radius:
which tools may run at all, which filesystem paths may be touched,
which hosts may be contacted, and how big / how frequent a call may be.

Everything is deny-by-default for the dangerous classes:
- paths outside the allowlist, or under a blocked prefix, are rejected
- hosts outside the allowlist (when set), or private / metadata IPs,
  are rejected
- shell metacharacters in command-like arguments are rejected
- oversized arguments are rejected

A call that fails policy returns a Decision(block=False, reasons=[...])
so the proxy can turn it into a JSON-RPC error without ever forwarding
it to the upstream server.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

# Paths that are never readable / writable through a tool, whatever the
# allowlist says. Checked before the allowlist.
BLOCKED_PATH_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/proc/", "/sys/",
    "/.ssh/", "/.aws/", "/.gnupg/",
    ".ssh/", ".aws/", ".gnupg/",
)
BLOCKED_HOSTS = {
    "169.254.169.254", "metadata.google.internal",
    "localhost", "127.0.0.1", "::1",
}
SHELL_META = re.compile(r"[;&|`$()><\n\r]|\b&&\b|\b\|\|\b")
URL_RE = re.compile(r"https?://([^\s\"'/:<>]+)", re.I)
CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")


class ToolPolicy(BaseModel):
    allowed_args: list[str] | None = None
    blocked_args: list[str] = Field(default_factory=list)
    max_arg_size: int | None = None


class Policy(BaseModel):
    mode: Literal["enforce", "monitor"] = "enforce"
    allowed_tools: list[str] | None = None
    blocked_tools: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] | None = None
    blocked_hosts: list[str] = Field(default_factory=list)
    max_arg_size: int = 100_000
    max_result_size: int = 1_000_000
    rate_limit_per_minute: int = 60
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    @field_validator("allowed_paths", mode="before")
    @classmethod
    def _expand_paths(cls, v: list[str] | None) -> list[str]:
        return [str(Path(p).expanduser()) for p in (v or [])]

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data.get("policy", data))

    @classmethod
    def default(cls) -> "Policy":
        return cls(
            allowed_paths=["/tmp", str(Path.home() / "workspace")],
            blocked_tools=["exfiltrate_credentials", "dump_secrets"],
        )


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.allowed


def _looks_like_path(value: str) -> bool:
    return value.startswith(("/", "~")) or ".." in value or value.endswith((".pem", ".key"))


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def validate_call(policy: Policy, tool_name: str, arguments: dict[str, Any] | None) -> Decision:
    """Validate one tools/call against the policy. Pure function."""
    reasons: list[str] = []
    args = arguments or {}

    if tool_name in policy.blocked_tools:
        reasons.append(f"tool '{tool_name}' is on the blocked-tools list")
    if policy.allowed_tools is not None and tool_name not in policy.allowed_tools:
        reasons.append(f"tool '{tool_name}' is not on the allowed-tools list")

    tool_policy = policy.tools.get(tool_name)
    if tool_policy:
        if tool_policy.allowed_args is not None:
            for key in args:
                if key not in tool_policy.allowed_args:
                    reasons.append(f"argument '{key}' not allowed for tool '{tool_name}'")
        for key in tool_policy.blocked_args:
            if key in args:
                reasons.append(f"argument '{key}' is blocked for tool '{tool_name}'")

    # Serialised size of the whole argument object.
    import json

    try:
        size = len(json.dumps(args, default=str))
    except Exception:
        size = 0
    limit = tool_policy.max_arg_size if tool_policy and tool_policy.max_arg_size else policy.max_arg_size
    if size > limit:
        reasons.append(f"arguments too large ({size} > {limit} bytes)")

    def check_value(key: str, value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                check_value(f"{key}.{k}", v)
            return
        if isinstance(value, list):
            for i, v in enumerate(value):
                check_value(f"{key}[{i}]", v)
            return
        if not isinstance(value, str):
            return

        # Paths: traversal + blocked prefixes + allowlist.
        if _looks_like_path(value):
            expanded = str(Path(value).expanduser())
            lowered = expanded.lower()
            if any(b in lowered for b in BLOCKED_PATH_PREFIXES):
                reasons.append(f"argument '{key}' touches a blocked path: {value}")
            elif ".." in value:
                reasons.append(f"argument '{key}' contains path traversal: {value}")
            elif policy.allowed_paths and not any(
                expanded == p or expanded.startswith(p.rstrip("/") + "/") for p in policy.allowed_paths
            ):
                reasons.append(f"argument '{key}' is outside allowed paths: {value}")

        # URLs / hosts: metadata, private IPs, blocklist, allowlist.
        for m in URL_RE.finditer(value):
            host = m.group(1).lower().strip("[]")
            parsed_host = urllib.parse.urlparse(value).hostname or host
            if parsed_host in BLOCKED_HOSTS or parsed_host in {h.lower() for h in policy.blocked_hosts}:
                reasons.append(f"argument '{key}' contacts blocked host: {parsed_host}")
            elif _is_private_ip(parsed_host):
                reasons.append(f"argument '{key}' contacts private IP: {parsed_host}")
            elif policy.allowed_hosts is not None and parsed_host not in {h.lower() for h in policy.allowed_hosts}:
                reasons.append(f"argument '{key}' contacts non-allowlisted host: {parsed_host}")

        # Shell metacharacters in command-like arguments.
        if key.lower() in ("command", "cmd", "shell", "script", "query") or tool_name in ("run_command", "exec", "shell"):
            if SHELL_META.search(value):
                reasons.append(f"argument '{key}' contains shell metacharacters")

        # Credential keys being sent somewhere (exfiltration-shaped).
        if any(c in key.lower() for c in CREDENTIAL_KEYS) and isinstance(value, str) and len(value) > 0:
            # A credential *value* in an argument is only suspicious when
            # paired with a URL / external destination in the same call.
            if URL_RE.search(json.dumps(args, default=str)):
                reasons.append(f"argument '{key}' appears to send a credential to an external destination")

    for k, v in args.items():
        check_value(k, v)

    return Decision(allowed=not reasons, reasons=reasons)
