"""Pydantic schema for format detection results."""

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import LogFormatEnum


class DetectionResult(BaseModel):
    """Result of the format detection engine's classification of a raw log string."""

    model_config = ConfigDict(frozen=True)

    detected_format: LogFormatEnum = Field(
        description="The log format identified by the detection engine.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Detection confidence score (0.0 = no match, 1.0 = certain).",
    )
    sub_format: str | None = Field(
        default=None,
        description="Optional sub-format hint (e.g., 'RFC_5424', 'RFC_3164', 'COMBINED').",
    )
