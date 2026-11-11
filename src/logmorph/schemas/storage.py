"""Schemas and data contracts for log storage querying, pagination, and tenant analytics."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import LogFormatEnum, SeverityEnum


class LogQueryFilter(BaseModel):
    """Multi-vector search filter for querying stored tenant logs."""

    model_config = ConfigDict(frozen=True)

    start_time: datetime | None = Field(
        default=None,
        description="Filter events occurring at or after this UTC timestamp.",
    )
    end_time: datetime | None = Field(
        default=None,
        description="Filter events occurring at or before this UTC timestamp.",
    )
    severity: SeverityEnum | None = Field(
        default=None,
        description="Filter by standardized severity.",
    )
    detected_format: LogFormatEnum | None = Field(
        default=None,
        description="Filter by source log format.",
    )
    threat_matched: bool | None = Field(
        default=None,
        description="Filter by presence of threat match.",
    )
    mitre_technique: str | None = Field(
        default=None,
        description="Filter by specific MITRE ATT&CK technique ID.",
    )
    source_ip: str | None = Field(
        default=None,
        description="Filter by source IP address.",
    )
    destination_ip: str | None = Field(
        default=None,
        description="Filter by destination IP address.",
    )
    search_term: str | None = Field(
        default=None,
        description="Substring search across raw log, action, and user fields.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of log records to return.",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Number of records to skip for pagination.",
    )


class LogRecordRead(BaseModel):
    """Pydantic projection model representing a stored log record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_id: str
    timestamp: datetime
    ingested_at: datetime
    raw_log: str
    detected_format: str
    severity: str
    action: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    user: str | None = None
    process_name: str | None = None
    parsed_by: str
    is_duplicate: bool
    threat_matched: bool
    threat_id: str | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    geoip_country: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class LogQueryResponse(BaseModel):
    """Paginated response contract for log query searches."""

    model_config = ConfigDict(frozen=True)

    items: list[LogRecordRead]
    total_count: int = Field(ge=0, description="Total matching logs across all pages.")
    limit: int = Field(ge=1, description="Requested page limit.")
    offset: int = Field(ge=0, description="Requested page offset.")
    has_more: bool = Field(description="Whether more records exist beyond this page.")


class TenantLogStats(BaseModel):
    """Aggregated security and analytics metrics for a tenant."""

    model_config = ConfigDict(frozen=True)

    tenant_id: uuid.UUID
    total_logs: int = Field(ge=0)
    threat_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    format_breakdown: dict[str, int] = Field(default_factory=dict)
    top_mitre_techniques: dict[str, int] = Field(default_factory=dict)
    top_countries: dict[str, int] = Field(default_factory=dict)
