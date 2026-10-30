"""Base parser abstractions and normalized parsed result contract."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)


class ParsedResult(BaseModel):
    """Normalized intermediate result produced by any cascade parsing tier.

    Captures extracted fields prior to final UTC timestamp normalization,
    field cleaning, and enrichment.
    """

    model_config = ConfigDict(frozen=True)

    success: bool = Field(
        ...,
        description="Whether parsing succeeded cleanly without syntax failure",
    )
    format: LogFormatEnum = Field(
        ...,
        description="Source log format processed by this parser",
    )
    parsed_by: ParsingTierEnum = Field(
        default=ParsingTierEnum.RULE,
        description="Parsing tier that parsed this record (default: RULE for Tier 1)",
    )
    raw_timestamp: str | None = Field(
        default=None,
        description="Extracted candidate raw timestamp string for Day 4 normalization",
    )
    severity: SeverityEnum = Field(
        default=SeverityEnum.INFORMATIONAL,
        description="Standardized severity level extracted or inferred from the log",
    )
    action: str | None = Field(
        default=None,
        description="Extracted action descriptor (e.g. HTTP verb, firewall action, event type)",
    )
    source: SourceInfo | None = Field(
        default=None,
        description="Origin network and endpoint telemetry",
    )
    destination: DestinationInfo | None = Field(
        default=None,
        description="Target network and endpoint telemetry",
    )
    security: SecurityContext | None = Field(
        default=None,
        description="Subject user, credentials, process name, or process ID",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Format-specific key-value pairs preserved during parsing",
    )
    error_message: str | None = Field(
        default=None,
        description="Error description if parsing failed (for cascade fall-through)",
    )


class BaseParser(ABC):
    """Abstract base class for all deterministic Tier 1 log parsers."""

    @abstractmethod
    def parse(self, raw_log: str) -> ParsedResult:
        """Parse raw log line into structured ParsedResult.

        Must return ParsedResult(success=False, error_message=...) on syntax failure
        rather than raising unhandled exceptions, enabling clean cascading to Tier 2.
        """
        pass
