"""Pydantic schemas for single and batch log ingestion endpoints."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IngestRequest(BaseModel):
    """Payload for single log ingestion (POST /api/v1/ingest)."""

    model_config = ConfigDict(extra="forbid")

    raw_log: str = Field(
        ...,
        min_length=1,
        description="Raw, unparsed log string line",
        examples=["<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"],
    )
    source: str | None = Field(
        default=None,
        max_length=255,
        description="Optional identifier of the log source/collector",
        examples=["production-firewall"],
    )

    @field_validator("raw_log")
    @classmethod
    def validate_raw_log_not_whitespace(cls, v: str) -> str:
        """Ensure raw log is not purely whitespace."""
        if not v.strip():
            raise ValueError("raw_log must contain non-whitespace characters")
        return v


class IngestResponse(BaseModel):
    """Response payload for single log ingestion."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(
        default="accepted",
        description="Ingestion processing status",
        examples=["accepted"],
    )
    event_id: str = Field(
        ...,
        description="Unique event tracking identifier (evt_<uuid>)",
        examples=["evt_f1e2d3c4-b5a6-7890-abcd-ef1234567890"],
    )


class BatchIngestRequest(BaseModel):
    """Payload for batch log ingestion (POST /api/v1/ingest/batch)."""

    model_config = ConfigDict(extra="forbid")

    logs: list[str] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of raw log strings to ingest (1 to 1000 items)",
        examples=[
            [
                "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
                '{"timestamp": "2026-09-23T10:00:00Z", "level": "ERROR", "msg": "Timeout"}',
            ]
        ],
    )
    source: str | None = Field(
        default=None,
        max_length=255,
        description="Optional identifier of the log source/collector",
        examples=["mixed-collector"],
    )

    @field_validator("logs")
    @classmethod
    def validate_logs_non_empty(cls, v: list[str]) -> list[str]:
        """Validate that batch is not empty and each log entry has non-whitespace content."""
        if not v:
            raise ValueError("logs batch must contain at least one log entry")
        for idx, item in enumerate(v):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Log at index {idx} must be a non-empty string")
        return v


class BatchIngestResponse(BaseModel):
    """Response payload for batch log ingestion."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(
        default="accepted",
        description="Ingestion processing status",
        examples=["accepted"],
    )
    count: int = Field(
        ...,
        ge=1,
        description="Number of logs accepted in this batch",
        examples=[3],
    )
    event_ids: list[str] = Field(
        ...,
        description="Generated event IDs corresponding to each log in the batch",
        examples=[
            "evt_aaa11111-b5a6-7890-abcd-ef1234567890",
            "evt_bbb22222-b5a6-7890-abcd-ef1234567890",
        ],
    )
