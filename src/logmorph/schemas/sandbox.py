"""Schemas for the interactive sandbox parser demo."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from logmorph.schemas.events import EventItem


class SandboxParseRequest(BaseModel):
    """Payload to test raw log parsing interactively."""

    model_config = ConfigDict(frozen=True)

    raw_log: str = Field(
        min_length=1,
        max_length=8192,
        description="Raw log string to parse. Maximum 8192 characters.",
    )
    format_hint: str | None = Field(
        default=None,
        max_length=64,
        description="Optional format hint (e.g. SYSLOG, JSON, CEF).",
    )


class SandboxParseResponse(BaseModel):
    """Response containing detected format, parsing tier, normalized ULS structure, and server latency."""

    model_config = ConfigDict(frozen=True)

    detected_format: str
    parsed_by: str
    event: EventItem
    processing_ms: float = Field(
        ...,
        description="Server-side parsing cascade and normalization latency in milliseconds",
    )
