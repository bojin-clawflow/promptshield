"""Configuration management for PromptShield."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All variables are prefixed with ``PROMPTSHIELD_`` (e.g.
    ``PROMPTSHIELD_DEBUG=true``).
    """

    model_config = {"env_prefix": "PROMPTSHIELD_"}

    # ── Application ──────────────────────────────────────────────
    app_name: str = "PromptShield"
    version: str = "0.1.0"
    debug: bool = False

    # ── Server ───────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # ── Detection ────────────────────────────────────────────────
    detection_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum score to flag a prompt as unsafe.",
    )

    # ── Auth ─────────────────────────────────────────────────────
    api_key: str | None = Field(
        default=None,
        description="Optional API key for SaaS authentication.",
    )

    # ── CORS ─────────────────────────────────────────────────────
    cors_origins: list[str] = Field(default=["*"])

    # ── Audit ────────────────────────────────────────────────────
    audit_log_path: str = "audit.jsonl"


settings = Settings()
