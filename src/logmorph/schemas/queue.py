"""Pydantic schema for raw log messages published to Apache Kafka."""

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class RawLogMessage(BaseModel):
    """Message envelope published to the Kafka raw-logs streaming topic."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(..., description="Unique event identifier (evt_<uuid>)")
    tenant_id: uuid.UUID = Field(
        ...,
        description="Tenant identifier for partitioned stream isolation",
    )
    raw_log: str = Field(..., min_length=1, description="Raw unparsed log line")
    source: str | None = Field(default=None, description="Optional log collector/source name")
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the log was accepted by the ingestion webhook",
    )
