"""Pydantic schemas and models for contextual GeoIP enrichment."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from logmorph.domain.uls import GeoIPContext


class GeoIPLookupResult(BaseModel):
    """Normalized geographical telemetry resolved for an IP address."""

    model_config = ConfigDict(frozen=True)

    ip: str = Field(
        description="Canonical IP address string.",
    )
    country: str | None = Field(
        default=None,
        description="Full English country name (e.g. United States, Germany, India).",
    )
    country_code: str | None = Field(
        default=None,
        description="ISO 3166-1 alpha-2 two-letter country code (e.g. US, DE, IN).",
    )
    city: str | None = Field(
        default=None,
        description="City or metropolitan area name (e.g. Mountain View, Frankfurt).",
    )
    latitude: float | None = Field(
        default=None,
        ge=-90.0,
        le=90.0,
        description="Geographic latitude coordinate.",
    )
    longitude: float | None = Field(
        default=None,
        ge=-180.0,
        le=180.0,
        description="Geographic longitude coordinate.",
    )
    asn: int | None = Field(
        default=None,
        description="Autonomous System Number (e.g. 15169 for Google).",
    )
    as_org: str | None = Field(
        default=None,
        description="Autonomous System organization name.",
    )
    is_private: bool = Field(
        default=False,
        description="True if the IP falls within RFC 1918 or RFC 4193 private ranges.",
    )
    is_bogon: bool = Field(
        default=False,
        description="True if the IP is unallocated, loopback, or reserved.",
    )
    resolved_by: str = Field(
        default="EMBEDDED_OFFLINE",
        description="Resolution engine utilized (CACHE, EMBEDDED_OFFLINE, MAXMIND_MMDB).",
    )

    def to_geoip_context(self) -> GeoIPContext:
        """Convert lookup outcome to standard ULS GeoIPContext representation."""
        return GeoIPContext(
            country=self.country,
            country_code=self.country_code,
            city=self.city,
            latitude=self.latitude,
            longitude=self.longitude,
        )


class GeoIPConfig(BaseModel):
    """Configuration options governing GeoIP resolution."""

    model_config = ConfigDict(frozen=True)

    db_path: str | None = Field(
        default=None,
        description="Path to optional MaxMind GeoLite2 .mmdb database file.",
    )
    cache_size: int = Field(
        default=10000,
        ge=100,
        description="Maximum entries maintained by the in-memory LRU cache.",
    )
    enabled: bool = Field(
        default=True,
        description="Global toggle for GeoIP resolution.",
    )


class GeoIPMetricsSnapshot(BaseModel):
    """Point-in-time metrics snapshot for GeoIP lookup telemetry."""

    model_config = ConfigDict(frozen=True)

    total_lookups: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    cache_misses: int = Field(default=0, ge=0)
    private_ips_skipped: int = Field(default=0, ge=0)
    embedded_lookups: int = Field(default=0, ge=0)
    mmdb_lookups: int = Field(default=0, ge=0)
    hit_rate_pct: float = Field(default=0.0, ge=0.0, le=100.0)
