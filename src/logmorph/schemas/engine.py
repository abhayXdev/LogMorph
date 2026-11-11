"""Configuration, processing result, and metrics schemas for the unified LogMorph engine.

Provides data contracts for end-to-end log processing, execution telemetry,
and pipeline stage toggles.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, UniversalLogEvent


class EngineConfig(BaseModel):
    """Configuration controls for the unified LogMorph engine."""

    model_config = ConfigDict(frozen=True)

    detection_enabled: bool = Field(default=True, description="Enable automatic format detection.")
    cascade_enabled: bool = Field(default=True, description="Enable adaptive parsing cascade.")
    quality_pipeline_enabled: bool = Field(
        default=True,
        description="Enable timestamp and PII quality pipeline.",
    )
    deduplication_enabled: bool = Field(
        default=True,
        description="Enable tenant-aware deduplication.",
    )
    drop_duplicates: bool = Field(
        default=False,
        description="Drop duplicate logs or tag them with is_duplicate attribute.",
    )
    geoip_enabled: bool = Field(default=True, description="Enable GeoIP contextual enrichment.")
    threat_intel_enabled: bool = Field(
        default=True,
        description="Enable threat intelligence correlation.",
    )
    mitre_tagger_enabled: bool = Field(
        default=True,
        description="Enable MITRE ATT&CK adversary tagging.",
    )
    max_batch_workers: int = Field(
        default=16,
        ge=1,
        le=64,
        description="Concurrency level for batch operations.",
    )


class EngineProcessingResult(BaseModel):
    """Outcome of processing an individual log through the unified engine."""

    model_config = ConfigDict(frozen=True)

    success: bool = Field(description="Whether processing completed without fatal error.")
    event: UniversalLogEvent | None = Field(
        default=None,
        description="Enriched UniversalLogEvent on success.",
    )
    error_message: str | None = Field(default=None, description="Error diagnostics if failed.")
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="End-to-end processing latency in milliseconds.",
    )
    format_detected: LogFormatEnum | None = Field(
        default=None,
        description="Detected source log format.",
    )
    parsed_by: ParsingTierEnum | None = Field(
        default=None,
        description="Cascade tier that parsed the event.",
    )
    is_duplicate: bool = Field(
        default=False,
        description="Whether the event was identified as a duplicate.",
    )
    threat_matched: bool = Field(
        default=False,
        description="Whether a threat IOC match occurred.",
    )
    mitre_technique: str | None = Field(
        default=None,
        description="Primary MITRE ATT&CK technique ID.",
    )
    geoip_country: str | None = Field(
        default=None,
        description="Resolved GeoIP country name.",
    )


class EngineMetricsSnapshot(BaseModel):
    """Unified telemetry snapshot summarizing entire engine activity."""

    model_config = ConfigDict(frozen=True)

    total_processed: int = Field(ge=0, description="Total log messages processed.")
    successful: int = Field(ge=0, description="Total logs successfully transformed.")
    failed: int = Field(ge=0, description="Total logs that failed processing.")
    duplicates_detected: int = Field(
        ge=0,
        description="Total duplicates caught by deduplication.",
    )
    threats_detected: int = Field(
        ge=0,
        description="Total events with positive threat matches.",
    )
    mitre_tagged: int = Field(
        ge=0,
        description="Total events tagged with MITRE ATT&CK.",
    )
    avg_latency_ms: float = Field(ge=0.0, description="Average processing latency in ms.")
    p95_latency_ms: float = Field(ge=0.0, description="95th percentile latency in ms.")
    p99_latency_ms: float = Field(ge=0.0, description="99th percentile latency in ms.")
    format_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by detected format.",
    )
    tier_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by cascade parsing tier.",
    )
