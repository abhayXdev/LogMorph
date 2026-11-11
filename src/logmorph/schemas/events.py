"""Schemas and data contracts for tenant-isolated log events querying, detail, search, and lifecycle."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventSourceInfo(BaseModel):
    """Source network endpoint metadata."""

    model_config = ConfigDict(frozen=True)

    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    mac: str | None = None


class EventDestinationInfo(BaseModel):
    """Destination network endpoint metadata."""

    model_config = ConfigDict(frozen=True)

    ip: str | None = None
    port: int | None = None


class EventSecurityInfo(BaseModel):
    """Security context, credentials, and identifiers."""

    model_config = ConfigDict(frozen=True)

    user: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    threat_id: str | None = None
    mitre_technique: str | None = None


class EventEnrichmentInfo(BaseModel):
    """Contextual enrichment payloads (GeoIP, Threat Intel, MITRE ATT&CK)."""

    model_config = ConfigDict(frozen=True)

    geoip: dict[str, Any] | None = None
    threat_match: bool = False
    mitre_technique: str | None = None
    mitre_tactic: str | None = None


class EventItem(BaseModel):
    """Canonical log event representation for listings and search results."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    timestamp: datetime
    raw_log: str
    detected_format: str
    severity: str
    source: EventSourceInfo | None = None
    destination: EventDestinationInfo | None = None
    security: EventSecurityInfo | None = None
    action: str | None = None
    parsed_by: str = "RULE"
    enrichment: EventEnrichmentInfo | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class EventsPagination(BaseModel):
    """Pagination metadata conforming to frontend API contract."""

    model_config = ConfigDict(frozen=True)

    page: int = Field(ge=1, description="Current page number.")
    limit: int = Field(ge=1, le=100, description="Events returned per page.")
    total: int = Field(ge=0, description="Total matching events.")
    total_pages: int = Field(ge=0, description="Total pages available.")


class PaginatedEventsResponse(BaseModel):
    """Paginated response envelope for event listing endpoints."""

    model_config = ConfigDict(frozen=True)

    events: list[EventItem]
    pagination: EventsPagination


class EventDetailResponse(EventItem):
    """Detailed event view including full contextual fields."""

    pass


class EventSearchResultItem(BaseModel):
    """Individual search match with calculated relevance score."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    timestamp: datetime
    severity: str
    raw_log: str
    detected_format: str
    score: float = Field(ge=0.0, le=1.0, description="Relevance score between 0.0 and 1.0.")


class EventSearchResponse(BaseModel):
    """Response contract for full-text search endpoint."""

    model_config = ConfigDict(frozen=True)

    query: str
    results: list[EventSearchResultItem]
    total: int = Field(ge=0)


class EventDeleteResponse(BaseModel):
    """Acknowledgement of event deletion."""

    model_config = ConfigDict(frozen=True)

    message: str = "Event deleted successfully"
    event_id: str
