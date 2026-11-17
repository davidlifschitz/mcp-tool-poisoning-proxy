"""Structured audit logging (JSONL, one event per line).

Every decision the proxy makes -- allow, block, quarantine, rate-limit
-- is written here with a timestamp, session id, tool, risk score and
reasons. Argument values are redacted (secret-looking keys) and
truncated, so the audit log itself never becomes a credential leak.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REDACT_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "authorization", "auth")


def redact(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if any(r in str(k).lower() for r in REDACT_KEYS):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v, depth + 1)
        return out
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + f"...[truncated {len(value) - 500} chars]"
    return value


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.events: list[dict[str, Any]] = []

    def log(self, event: str, *, session_id: str, tool: str | None = None,
            decision: str | None = None, reasons: list[str] | None = None,
            risk_score: int | None = None, arguments: dict | None = None,
            direction: str | None = None, method: str | None = None) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "session_id": session_id,
            "tool": tool,
            "method": method,
            "direction": direction,
            "decision": decision,
            "reasons": reasons or [],
            "risk_score": risk_score,
            "arguments": redact(arguments) if arguments is not None else None,
        }
        self.events.append(record)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        return record

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.events:
            key = e.get("decision") or e.get("event") or "unknown"
            counts[key] = counts.get(key, 0) + 1
        return counts
