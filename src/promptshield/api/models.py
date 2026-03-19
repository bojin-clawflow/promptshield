"""Pydantic v2 request and response models for the PromptShield API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

# ── Request models ───────────────────────────────────────────────────────────


class ShieldRequest(BaseModel):
    """Incoming prompt to be analysed."""

    prompt: str = Field(..., min_length=1, description="The prompt text to analyse.")
    context: str | None = Field(
        default=None,
        description="Optional surrounding context for the prompt.",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Arbitrary metadata attached by the caller.",
    )


# ── Response models ──────────────────────────────────────────────────────────


class ThreatDetail(BaseModel):
    """A single threat detected inside a prompt."""

    pattern_name: str
    matched_text: str
    severity: float = Field(..., ge=0.0, le=1.0)
    category: str


class ShieldResponse(BaseModel):
    """Result returned from the detection endpoint."""

    safe: bool
    score: float = Field(..., ge=0.0, le=1.0)
    threats: list[ThreatDetail] = Field(default_factory=list)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    latency_ms: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HealthResponse(BaseModel):
    """Health-check payload."""

    status: str = "ok"
    version: str
    uptime_seconds: float


class StatsResponse(BaseModel):
    """Basic in-memory usage statistics."""

    total_requests: int
    blocked_requests: int
    avg_latency_ms: float
    top_threats: list[dict[str, Any]] = Field(default_factory=list)
