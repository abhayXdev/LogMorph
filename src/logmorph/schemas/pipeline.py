"""Pydantic schemas for the composite Quality Normalization Pipeline."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.deduplication import DeduplicationConfig, DeduplicationResult
from logmorph.schemas.normalization import TimestampNormalizationResult
from logmorph.schemas.sanitization import FieldCleaningConfig, SanitizationReport


class QualityPipelineConfig(BaseModel):
    """Configuration options governing the composite Quality Pipeline."""

    model_config = ConfigDict(frozen=True)

    target_timezone: str = Field(
        default="UTC",
        description="Target timezone for universal timestamp normalization (default: UTC).",
    )
    field_cleaning: FieldCleaningConfig = Field(
        default_factory=FieldCleaningConfig,
        description="Field cleaning and PII redaction configuration.",
    )
    deduplication: DeduplicationConfig = Field(
        default_factory=DeduplicationConfig,
        description="Tenant-aware sliding-window deduplication configuration.",
    )
    enabled: bool = Field(
        default=True,
        description="Global toggle for the quality pipeline.",
    )


class QualityPipelineResult(BaseModel):
    """Comprehensive outcome of the composite quality normalization pipeline."""

    model_config = ConfigDict(frozen=True)

    parsed_result: ParsedResult = Field(
        description="Final enriched, sanitized, and deduplicated ParsedResult.",
    )
    timestamp_result: TimestampNormalizationResult | None = Field(
        default=None,
        description="Outcome of universal timestamp normalization stage.",
    )
    sanitization_report: SanitizationReport | None = Field(
        default=None,
        description="Outcome of field cleaning and PII redaction stage.",
    )
    deduplication_result: DeduplicationResult | None = Field(
        default=None,
        description="Outcome of sliding-window deduplication evaluation.",
    )
    pipeline_duration_ms: float = Field(
        ge=0.0,
        description="Total execution time of the quality pipeline in milliseconds.",
    )
    success: bool = Field(
        default=True,
        description="Whether the entire quality pipeline completed without fatal errors.",
    )
    tenant_id: str = Field(
        description="Owning tenant identifier.",
    )
