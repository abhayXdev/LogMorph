"""Pydantic schemas and models for Threat Intelligence IOC matching."""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import SeverityEnum


class IOCTypeEnum(enum.StrEnum):
    """Supported Indicator of Compromise (IOC) classifications."""

    IP = "IP"
    DOMAIN = "DOMAIN"
    SHA256 = "SHA256"
    MD5 = "MD5"
    URL = "URL"
    CIDR = "CIDR"


class ThreatCategoryEnum(enum.StrEnum):
    """High-level categorization of cyber threats."""

    C2_SERVER = "C2_SERVER"
    BOTNET = "BOTNET"
    TOR_EXIT_NODE = "TOR_EXIT_NODE"
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    SCANNER = "SCANNER"
    UNKNOWN = "UNKNOWN"


class ThreatIndicator(BaseModel):
    """Discrete threat intelligence indicator definition."""

    model_config = ConfigDict(frozen=True)

    ioc_value: str = Field(
        description="Normalized IOC string (IP, domain, hash, CIDR).",
    )
    ioc_type: IOCTypeEnum = Field(
        description="Classification of the indicator.",
    )
    threat_name: str = Field(
        description="Malware family or threat identifier (e.g. Cobalt Strike, Mirai, WannaCry).",
    )
    category: ThreatCategoryEnum = Field(
        default=ThreatCategoryEnum.UNKNOWN,
        description="High-level threat category.",
    )
    severity: SeverityEnum = Field(
        default=SeverityEnum.ERROR,
        description="Standardized severity rating.",
    )
    confidence: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Intelligence confidence score.",
    )
    source_feed: str = Field(
        default="EMBEDDED_LOCAL",
        description="Name of the threat intelligence feed or provider.",
    )
    description: str | None = Field(
        default=None,
        description="Detailed threat summary or context.",
    )


class ThreatIntelResult(BaseModel):
    """Outcome of a threat intelligence match evaluation."""

    model_config = ConfigDict(frozen=True)

    is_match: bool = Field(
        description="True if IOC matches a known threat indicator with confidence >= threshold.",
    )
    matched_ioc: str | None = Field(
        default=None,
        description="The specific IOC value that triggered the match.",
    )
    ioc_type: IOCTypeEnum | None = Field(
        default=None,
        description="Classification of the matched indicator.",
    )
    threat_name: str | None = Field(
        default=None,
        description="Threat or malware family name.",
    )
    category: ThreatCategoryEnum = Field(
        default=ThreatCategoryEnum.UNKNOWN,
        description="Threat classification.",
    )
    severity: SeverityEnum = Field(
        default=SeverityEnum.INFORMATIONAL,
        description="Assigned severity level.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score of the match.",
    )
    source_feed: str | None = Field(
        default=None,
        description="Feed providing the intelligence.",
    )
    description: str | None = Field(
        default=None,
        description="Detailed threat summary or context.",
    )


class ThreatIntelConfig(BaseModel):
    """Configuration options governing threat intelligence matching."""

    model_config = ConfigDict(frozen=True)

    feed_path: str | None = Field(
        default=None,
        description="Optional file path to custom JSON/CSV threat intelligence feed.",
    )
    cache_size: int = Field(
        default=10000,
        ge=100,
        description="Maximum entries maintained by the in-memory LRU cache.",
    )
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required to classify as positive threat match.",
    )
    enabled: bool = Field(
        default=True,
        description="Global toggle for threat intelligence matching.",
    )


class ThreatIntelMetricsSnapshot(BaseModel):
    """Point-in-time metrics snapshot for Threat Intel telemetry."""

    model_config = ConfigDict(frozen=True)

    total_scans: int = Field(default=0, ge=0)
    threats_detected: int = Field(default=0, ge=0)
    benign_scans: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    cache_misses: int = Field(default=0, ge=0)
    detection_rate_pct: float = Field(default=0.0, ge=0.0, le=100.0)
