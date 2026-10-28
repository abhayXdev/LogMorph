"""Universal Log Schema (ULS) domain models and enumerations."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SeverityEnum(StrEnum):
    """Standardized log severity levels based on RFC 5424."""

    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


class LogFormatEnum(StrEnum):
    """Supported source log formats identified by the detection engine."""

    SYSLOG = "SYSLOG"
    JSON = "JSON"
    CEF = "CEF"
    LEEF = "LEEF"
    CLF = "CLF"
    XML = "XML"
    UNSTRUCTURED = "UNSTRUCTURED"


class ParsingTierEnum(StrEnum):
    """Execution tiers of the 3-Tier Adaptive Parsing Cascade."""

    RULE = "RULE"
    TEMPLATE = "TEMPLATE"
    LLM = "LLM"
    FALLBACK = "FALLBACK"


class SourceInfo(BaseModel):
    """Network and endpoint telemetry for the event origin."""

    model_config = ConfigDict(validate_assignment=True)

    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    mac: str | None = None


class DestinationInfo(BaseModel):
    """Network and endpoint telemetry for the event target."""

    model_config = ConfigDict(validate_assignment=True)

    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    mac: str | None = None


class SecurityContext(BaseModel):
    """Identity, process, and attack surface context."""

    model_config = ConfigDict(validate_assignment=True)

    user: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    threat_id: str | None = None
    mitre_technique: str | None = None


class GeoIPContext(BaseModel):
    """Geographical location details resolved from IP addresses."""

    model_config = ConfigDict(validate_assignment=True)

    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class EnrichmentContext(BaseModel):
    """Enrichment metadata injected during post-processing."""

    model_config = ConfigDict(validate_assignment=True)

    geoip: GeoIPContext | None = None
    threat_match: bool = False
    mitre_technique: str | None = None
    mitre_tactic: str | None = None


class UniversalLogEvent(BaseModel):
    """Universal Log Schema (ULS) canonical model for all normalized events.

    Provides multi-tenant tagging via `tenant_id` to strictly guarantee isolation
    in multi-tenant SaaS environments.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
    )

    event_id: str = Field(
        default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}",
        description="Unique identifier for the log event.",
    )
    tenant_id: UUID = Field(
        description="Unique identifier of the tenant/workspace owning this event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Normalized UTC ISO-8601 event timestamp.",
    )
    raw_log: str = Field(
        description="Original unparsed log string as received by the ingestion layer.",
    )
    detected_format: LogFormatEnum = Field(
        description="Source format detected by the detection heuristics.",
    )
    severity: SeverityEnum = Field(
        default=SeverityEnum.INFORMATIONAL,
        description="Standardized severity level.",
    )
    source: SourceInfo | None = Field(
        default=None,
        description="Origin network and host details.",
    )
    destination: DestinationInfo | None = Field(
        default=None,
        description="Target network and host details.",
    )
    security: SecurityContext | None = Field(
        default=None,
        description="Subject credentials, user, process, or security markers.",
    )
    action: str | None = Field(
        default=None,
        description="Normalized action descriptor (e.g. LOGIN_FAILED, ALLOW, BLOCK).",
    )
    parsed_by: ParsingTierEnum = Field(
        default=ParsingTierEnum.RULE,
        description="Cascade tier that parsed this event.",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Format-specific key-value pairs preserved during parsing.",
    )
    enrichment: EnrichmentContext | None = Field(
        default=None,
        description="Security enrichment details (GeoIP, threat feeds, MITRE ATT&CK).",
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when event was accepted into the ingestion pipeline.",
    )
