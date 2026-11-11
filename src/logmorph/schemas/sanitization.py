"""Pydantic schemas and enums for field cleaning and data sanitization."""

import enum

from pydantic import BaseModel, ConfigDict, Field


class SanitizationMaskType(enum.StrEnum):
    """Supported classifications of sensitive PII and secrets to redact."""

    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"
    API_KEY = "API_KEY"
    JWT = "JWT"
    PASSWORD = "PASSWORD"
    EMAIL = "EMAIL"


class CleanedIP(BaseModel):
    """Canonicalized network endpoint details and RFC classification metadata."""

    model_config = ConfigDict(frozen=True)

    ip: str = Field(
        description="Standardized IPv4 or IPv6 address string without port or leading zeroes.",
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Validated network port number (1 to 65535).",
    )
    is_ipv6: bool = Field(
        default=False,
        description="True if the address is IPv6, False if IPv4.",
    )
    is_private: bool = Field(
        default=False,
        description="True if the IP falls within RFC 1918 / RFC 4193 private ranges.",
    )
    is_loopback: bool = Field(
        default=False,
        description="True if the IP is loopback (127.0.0.0/8 or ::1).",
    )
    is_multicast: bool = Field(
        default=False,
        description="True if the IP is multicast.",
    )
    is_public: bool = Field(
        default=False,
        description="True if the IP is globally routable on the public internet.",
    )


class SanitizationReport(BaseModel):
    """Telemetry report recording the redaction actions performed on an event."""

    model_config = ConfigDict(frozen=True)

    redacted_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Mapping of secret category to count of redactions applied.",
    )
    total_redactions: int = Field(
        default=0,
        description="Total number of sensitive tokens redacted.",
    )
    cleaned_fields_count: int = Field(
        default=0,
        description="Number of fields that had whitespace or control characters cleansed.",
    )


class FieldCleaningConfig(BaseModel):
    """Runtime configuration toggles for field cleaning and PII redaction."""

    model_config = ConfigDict(frozen=True)

    strip_ansi: bool = Field(
        default=True,
        description="Whether to strip ANSI color and terminal escape sequences.",
    )
    strip_control_chars: bool = Field(
        default=True,
        description="Whether to purge non-printable control characters and null bytes.",
    )
    normalize_ips: bool = Field(
        default=True,
        description="Whether to parse and canonicalize IP addresses and ports.",
    )
    normalize_macs: bool = Field(
        default=True,
        description="Whether to format MAC addresses to colon-separated lowercase.",
    )
    normalize_hostnames: bool = Field(
        default=True,
        description="Whether to lowercase and clean hostnames.",
    )
    mask_pii: bool = Field(
        default=True,
        description="Whether to scan and redact sensitive compliance data.",
    )
    mask_types: set[SanitizationMaskType] = Field(
        default_factory=lambda: {
            SanitizationMaskType.CREDIT_CARD,
            SanitizationMaskType.SSN,
            SanitizationMaskType.API_KEY,
            SanitizationMaskType.JWT,
            SanitizationMaskType.PASSWORD,
        },
        description="Active set of sensitive secret categories to mask.",
    )
