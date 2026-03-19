"""Async audit logger that appends JSON-lines to a file."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiofiles

from promptshield.config import settings

_TRUNCATE_LENGTH = 200


async def log_request(
    *,
    request_id: str,
    prompt: str,
    safe: bool,
    score: float,
    threats: list[dict[str, Any]],
    latency_ms: float,
    client_ip: str | None = None,
) -> None:
    """Append a single audit entry as a JSON line.

    The prompt text is truncated to avoid storing excessively large payloads.
    """
    entry: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "request_id": request_id,
        "prompt": prompt[:_TRUNCATE_LENGTH]
        + ("..." if len(prompt) > _TRUNCATE_LENGTH else ""),
        "safe": safe,
        "score": score,
        "threats": threats,
        "latency_ms": latency_ms,
        "client_ip": client_ip,
    }

    path = Path(settings.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(path, mode="a", encoding="utf-8") as fh:
        await fh.write(json.dumps(entry, default=str) + "\n")
