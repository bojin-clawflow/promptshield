"""FastAPI router with PromptShield API endpoints."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from promptshield.api.models import (
    HealthResponse,
    ShieldRequest,
    ShieldResponse,
    StatsResponse,
    ThreatDetail,
)
from promptshield.audit import log_request
from promptshield.config import settings
from promptshield.engine.detector import ShieldDetector

router = APIRouter(prefix="/v1", tags=["shield"])

# ── In-memory statistics (MVP) ──────────────────────────────────────────────

_stats: dict[str, Any] = {
    "total_requests": 0,
    "blocked_requests": 0,
    "latencies": [],
    "threat_counter": Counter(),
}

_detector: ShieldDetector | None = None
_start_time: float = time.monotonic()


def get_detector() -> ShieldDetector:
    """Return the initialised detector instance."""
    if _detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialised.")
    return _detector


def init_detector() -> None:
    """Create the global detector instance (called at startup)."""
    global _detector, _start_time  # noqa: PLW0603
    _detector = ShieldDetector(threshold=settings.detection_threshold)
    _start_time = time.monotonic()


# ── Auth dependency ──────────────────────────────────────────────────────────


async def verify_api_key(
    x_api_key: str | None = Header(default=None),
) -> None:
    """Validate the ``X-API-Key`` header when an API key is configured."""
    if settings.api_key is None:
        return  # auth not enabled
    if x_api_key is None or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/shield", response_model=ShieldResponse, dependencies=[Depends(verify_api_key)])
async def shield(body: ShieldRequest, request: Request) -> ShieldResponse:
    """Analyse a prompt for threats and return a safety verdict."""
    detector = get_detector()

    result = detector.analyze(body.prompt)

    threats: list[ThreatDetail] = [
        ThreatDetail(
            pattern_name=t.name,
            matched_text=t.matched_text,
            severity=t.severity,
            category=t.category,
        )
        for t in result.threats
    ]

    response = ShieldResponse(
        safe=result.safe,
        score=result.score,
        threats=threats,
        latency_ms=result.latency_ms,
    )

    # Update in-memory stats
    _stats["total_requests"] += 1
    if not result.safe:
        _stats["blocked_requests"] += 1
    _stats["latencies"].append(result.latency_ms)
    for threat in threats:
        _stats["threat_counter"][threat.pattern_name] += 1

    # Fire-and-forget audit log
    client_ip = request.client.host if request.client else None
    await log_request(
        request_id=response.request_id,
        prompt=body.prompt,
        safe=result.safe,
        score=result.score,
        threats=[t.model_dump() for t in threats],
        latency_ms=result.latency_ms,
        client_ip=client_ip,
    )

    return response


@router.get("/health", response_model=HealthResponse, dependencies=[Depends(verify_api_key)])
async def health() -> HealthResponse:
    """Return service health information."""
    return HealthResponse(
        status="ok",
        version=settings.version,
        uptime_seconds=round(time.monotonic() - _start_time, 2),
    )


@router.get("/stats", response_model=StatsResponse, dependencies=[Depends(verify_api_key)])
async def stats() -> StatsResponse:
    """Return in-memory request statistics."""
    latencies: list[float] = _stats["latencies"]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    threat_counter: Counter[str] = _stats["threat_counter"]
    top_threats = [
        {"pattern_name": name, "count": count}
        for name, count in threat_counter.most_common(10)
    ]

    return StatsResponse(
        total_requests=_stats["total_requests"],
        blocked_requests=_stats["blocked_requests"],
        avg_latency_ms=avg_latency,
        top_threats=top_threats,
    )
