"""Schemas for Log Source Collector registration, management, and health telemetry."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LogSourceCreateRequest(BaseModel):
    """Payload to register a new log collector source."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=100)
    type: str = Field(
        default="SYSLOG",
        description="Source type e.g. SYSLOG, JSON, CEF, CLF, FIREWALL, KUBERNETES",
    )
    description: str | None = Field(default=None, max_length=255)


class LogSourceResponse(BaseModel):
    """Public representation of a configured log source."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    type: str
    description: str | None = None
    status: str
    events_count: int = Field(ge=0)
    last_seen_at: datetime | None = None
    created_at: datetime


class LogSourcesListResponse(BaseModel):
    """List response envelope for log sources."""

    model_config = ConfigDict(frozen=True)

    sources: list[LogSourceResponse]
    total: int = Field(ge=0)


class LogSourceDeleteResponse(BaseModel):
    """Acknowledgement of source deletion."""

    model_config = ConfigDict(frozen=True)

    message: str = "Source deleted successfully"
    source_id: str
