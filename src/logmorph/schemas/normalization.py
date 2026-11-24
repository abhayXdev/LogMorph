"""Pydantic schemas and enums for data normalization results."""

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TimestampFormatEnum(enum.StrEnum):
    """Recognized source timestamp pattern categories."""

    ISO_8601 = "ISO_8601"
    UNIX_EPOCH_S = "UNIX_EPOCH_S"
    UNIX_EPOCH_MS = "UNIX_EPOCH_MS"
    UNIX_EPOCH_US = "UNIX_EPOCH_US"
    UNIX_EPOCH_NS = "UNIX_EPOCH_NS"
    UNIX_EPOCH_FLOAT = "UNIX_EPOCH_FLOAT"
    SYSLOG_RFC3164 = "SYSLOG_RFC3164"
    APACHE_CLF = "APACHE_CLF"
    ENTERPRISE_CUSTOM = "ENTERPRISE_CUSTOM"
    RFC_2822 = "RFC_2822"
    FUZZY_DATEUTIL = "FUZZY_DATEUTIL"
    FALLBACK_INGESTION_TIME = "FALLBACK_INGESTION_TIME"


class TimestampNormalizationResult(BaseModel):
    """Result of normalizing a candidate raw timestamp to UTC ISO 8601."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(
        description="Canonical UTC timezone-aware datetime object.",
    )
    iso_8601: str = Field(
        description="Standardized ISO 8601 UTC string representation with trailing Z.",
    )
    original_raw: str | int | float | None = Field(
        default=None,
        description="Original raw timestamp candidate passed into the normalizer.",
    )
    matched_format: TimestampFormatEnum = Field(
        description="Classification of the format pattern recognized.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score (1.0 = explicit tz, 0.9 = inferred year/tz, 0.0 = fallback).",
    )
    was_fallback: bool = Field(
        default=False,
        description="Flag indicating if parsing failed and defaulted to reference time.",
    )
    timezone_offset_seconds: int = Field(
        default=0,
        description="Timezone offset from UTC in seconds extracted or applied.",
    )
