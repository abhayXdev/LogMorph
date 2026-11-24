"""Schemas for Tenant Analytics, Time-series Charts, and Security Telemetry."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class StatsOverviewResponse(BaseModel):
    """Overall pipeline and security metrics for dashboard cards."""

    model_config = ConfigDict(frozen=True)

    total_events: int = Field(ge=0)
    events_today: int = Field(ge=0)
    duplicates_dropped: int = Field(ge=0)
    errors: int = Field(ge=0)
    active_sources: int = Field(ge=0)
    avg_processing_ms: float = Field(ge=0.0)


class TimelineDataPoint(BaseModel):
    """Individual bucket count for time-series charts."""

    model_config = ConfigDict(frozen=True)

    time: datetime
    count: int = Field(ge=0)


class StatsTimelineResponse(BaseModel):
    """Event volume history grouped by time intervals."""

    model_config = ConfigDict(frozen=True)

    period: str = Field(description="Requested time period e.g. 1h, 24h, 7d, 30d")
    bucket: str = Field(description="Bucket size e.g. minute, hour, day")
    data: list[TimelineDataPoint]


class FormatBreakdownItem(BaseModel):
    """Format slice for donut/pie charts."""

    model_config = ConfigDict(frozen=True)

    format: str
    count: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)


class StatsFormatsResponse(BaseModel):
    """Breakdown of logs by detected source format."""

    model_config = ConfigDict(frozen=True)

    formats: list[FormatBreakdownItem]


class SeverityBreakdownItem(BaseModel):
    """Severity level item with standard UI color."""

    model_config = ConfigDict(frozen=True)

    level: str
    count: int = Field(ge=0)
    color: str


class StatsSeverityResponse(BaseModel):
    """Breakdown of logs by severity rating."""

    model_config = ConfigDict(frozen=True)

    severity: list[SeverityBreakdownItem]


class TopTechniqueItem(BaseModel):
    """Top MITRE ATT&CK technique item."""

    model_config = ConfigDict(frozen=True)

    technique: str
    count: int = Field(ge=0)


class RecentIOCItem(BaseModel):
    """Indicator of compromise recently matched."""

    model_config = ConfigDict(frozen=True)

    type: str
    value: str
    seen_at: datetime


class StatsThreatsResponse(BaseModel):
    """Threat intelligence match summary."""

    model_config = ConfigDict(frozen=True)

    total_threats_detected: int = Field(ge=0)
    threats_today: int = Field(ge=0)
    top_techniques: list[TopTechniqueItem]
    recent_iocs: list[RecentIOCItem]


class TierUsageItem(BaseModel):
    """Tier usage count and percentage."""

    model_config = ConfigDict(frozen=True)

    tier: str
    label: str
    count: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)


class StatsCascadeResponse(BaseModel):
    """Breakdown of logs processed across the 3 parsing tiers."""

    model_config = ConfigDict(frozen=True)

    tiers: list[TierUsageItem]
