"""Pydantic schemas and enums for tenant-aware log deduplication."""

import enum

from pydantic import BaseModel, ConfigDict, Field


class DeduplicationBackendEnum(enum.StrEnum):
    """Storage backends utilized for sliding-window deduplication."""

    REDIS = "REDIS"
    MEMORY_FALLBACK = "MEMORY_FALLBACK"


class DeduplicationResult(BaseModel):
    """Result of a deduplication evaluation for a single log event."""

    model_config = ConfigDict(frozen=True)

    is_duplicate: bool = Field(
        description="True if this event was already observed within the sliding window.",
    )
    duplicate_count: int = Field(
        ge=1,
        description="Total occurrences of this event fingerprint within the active window (1 for first seen).",
    )
    fingerprint: str = Field(
        description="Deterministic 64-character SHA-256 fingerprint hash.",
    )
    tenant_id: str = Field(
        description="Owning tenant identifier.",
    )
    ttl_seconds: int = Field(
        ge=1,
        description="Active sliding window duration in seconds.",
    )
    storage_backend: DeduplicationBackendEnum = Field(
        description="Storage engine that evaluated the deduplication state.",
    )


class DeduplicationConfig(BaseModel):
    """Configuration options governing sliding-window deduplication behavior."""

    model_config = ConfigDict(frozen=True)

    ttl_seconds: int = Field(
        default=60,
        ge=1,
        le=86400,
        description="Deduplication sliding window duration in seconds (default: 60s).",
    )
    refresh_ttl_on_duplicate: bool = Field(
        default=False,
        description="Whether observing a duplicate extends the sliding window expiration.",
    )
    max_memory_entries: int = Field(
        default=50000,
        ge=100,
        description="Maximum entries retained by the in-memory fallback cache.",
    )
    enabled: bool = Field(
        default=True,
        description="Global toggle for deduplication.",
    )


class DeduplicationMetricsSnapshot(BaseModel):
    """Point-in-time metrics snapshot for deduplication service telemetry."""

    model_config = ConfigDict(frozen=True)

    total_evaluated: int = Field(
        default=0,
        ge=0,
        description="Total log records evaluated for deduplication.",
    )
    unique_events: int = Field(
        default=0,
        ge=0,
        description="Total distinct log records admitted (first seen).",
    )
    duplicates_suppressed: int = Field(
        default=0,
        ge=0,
        description="Total duplicate records detected and suppressed.",
    )
    suppression_rate_pct: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Percentage of evaluated records that were duplicates.",
    )
    redis_hits: int = Field(
        default=0,
        ge=0,
        description="Deduplication evaluations processed by primary Redis backend.",
    )
    memory_fallback_hits: int = Field(
        default=0,
        ge=0,
        description="Deduplication evaluations processed by autonomous in-memory fallback.",
    )
