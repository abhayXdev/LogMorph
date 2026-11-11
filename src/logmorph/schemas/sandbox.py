"""Schemas for the interactive sandbox parser demo."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from logmorph.schemas.events import EventItem


class SandboxParseRequest(BaseModel):
    """Payload to test raw log parsing interactively."""

    model_config = ConfigDict(frozen=True)

    raw_log: str = Field(min_length=1, description="Raw log line to parse")


class SandboxParseResponse(BaseModel):
    """Response containing detected format, parsing tier, and normalized ULS structure."""

    model_config = ConfigDict(frozen=True)

    detected_format: str
    parsed_by: str
    event: EventItem
