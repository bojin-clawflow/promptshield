"""FastAPI application entry-point for PromptShield."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from promptshield import __version__
from promptshield.api.routes import init_detector, router
from promptshield.config import settings

logger = logging.getLogger("promptshield")

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"


# ── Lifespan ─────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle hook."""
    logging.basicConfig(level=settings.log_level.upper())
    logger.info(
        "\n"
        "========================================\n"
        "  PromptShield v%s\n"
        "  Host: %s  Port: %s\n"
        "  Debug: %s\n"
        "========================================",
        settings.version,
        settings.host,
        settings.port,
        settings.debug,
    )
    init_detector()
    logger.info("ShieldDetector initialised.")
    yield
    logger.info("PromptShield shutting down.")


# ── App factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    description="AI prompt injection and jailbreak detection API.",
    version=__version__,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(router)

# Dashboard static files (served only if the directory exists)
if DASHBOARD_DIR.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")

# ── CLI runner ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "promptshield.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=settings.debug,
    )
