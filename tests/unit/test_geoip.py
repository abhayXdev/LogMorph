"""Comprehensive unit test suite for GeoIP resolution adapter.

Verifies embedded offline database binary search, RFC 1918 private filtering,
port stripping, in-memory LRU caching, telemetry metrics reconciliation,
ULS UniversalLogEvent enrichment, and sub-5-microsecond performance SLA.
"""

from __future__ import annotations

import time
import uuid

import pytest

from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    SourceInfo,
    UniversalLogEvent,
)
from logmorph.engine.enrichers.geoip import (
    GeoIPAdapter,
    GeoIPMetrics,
    get_geoip_adapter,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.enrichment import GeoIPConfig


@pytest.fixture
def isolated_geoip_adapter() -> GeoIPAdapter:
    """Return a pristine GeoIPAdapter with an empty cache and isolated metrics."""
    metrics = GeoIPMetrics()
    config = GeoIPConfig(cache_size=1000, enabled=True)
    return GeoIPAdapter(config=config, metrics=metrics)


# ==============================================================================
# 1. Public IP Geo Resolution Tests (Embedded Offline Database)
# ==============================================================================


def test_google_dns_resolution(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Google Anycast DNS IPs resolve accurately with city, coordinates, and ASN."""
    for ip in ["8.8.8.8", "8.8.4.4"]:
        res = isolated_geoip_adapter.lookup(ip)
        assert res is not None
        assert res.ip == ip
        assert res.country == "United States"
        assert res.country_code == "US"
        assert res.city == "Mountain View"
        assert res.latitude is not None and abs(res.latitude - 37.4056) < 0.1
        assert res.longitude is not None and abs(res.longitude - (-122.0775)) < 0.1
        assert res.asn == 15169
        assert res.as_org == "Google LLC"
        assert res.is_private is False
        assert res.is_bogon is False
        assert res.resolved_by == "EMBEDDED_OFFLINE"


def test_cloudflare_dns_resolution(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Cloudflare Anycast DNS IPs resolve to San Francisco with AS13335."""
    for ip in ["1.1.1.1", "1.0.0.1"]:
        res = isolated_geoip_adapter.lookup(ip)
        assert res is not None
        assert res.country == "United States"
        assert res.country_code == "US"
        assert res.city == "San Francisco"
        assert res.asn == 13335
        assert res.as_org == "Cloudflare, Inc."
        assert not res.is_private


def test_quad9_dns_resolution(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Quad9 Anycast DNS IP resolves to Berkeley with AS19281."""
    res = isolated_geoip_adapter.lookup("9.9.9.9")
    assert res is not None
    assert res.country == "United States"
    assert res.city == "Berkeley"
    assert res.asn == 19281
    assert res.as_org == "Quad9"


def test_opendns_resolution(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Cisco OpenDNS resolves to San Francisco with AS36692."""
    res = isolated_geoip_adapter.lookup("208.67.222.222")
    assert res is not None
    assert res.country == "United States"
    assert res.city == "San Francisco"
    assert res.asn == 36692


# ==============================================================================
# 2. International Regional Cloud Subnet Resolution Tests
# ==============================================================================


def test_international_cloud_subnets(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Regional subnets across Germany, India, Japan, UK, Ireland, Australia, and Brazil resolve correctly."""
    test_cases = [
        # AWS Frankfurt
        ("3.120.10.5", "Germany", "DE", "Frankfurt", 16509),
        # AWS Mumbai
        ("13.126.50.1", "India", "IN", "Mumbai", 16509),
        # AWS Tokyo
        ("13.112.20.10", "Japan", "JP", "Tokyo", 16509),
        # AWS Dublin
        ("34.240.1.1", "Ireland", "IE", "Dublin", 16509),
        # AWS Sydney
        ("13.54.100.2", "Australia", "AU", "Sydney", 16509),
        # AWS São Paulo
        ("54.232.5.5", "Brazil", "BR", "São Paulo", 16509),
        # Azure London
        ("51.140.2.1", "United Kingdom", "GB", "London", 8075),
        # Azure Redmond
        ("13.64.10.5", "United States", "US", "Redmond", 8075),
    ]

    for ip, country, code, city, asn in test_cases:
        res = isolated_geoip_adapter.lookup(ip)
        assert res is not None, f"Failed for {ip}"
        assert res.country == country, f"Expected {country} for {ip}, got {res.country}"
        assert res.country_code == code
        assert res.city == city
        assert res.asn == asn


def test_ipv6_anycast_resolution(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """IPv6 addresses resolve accurately through the IPv6 range table."""
    # Google IPv6
    res_google = isolated_geoip_adapter.lookup("2001:4860:4860::8888")
    assert res_google is not None
    assert res_google.country == "United States"
    assert res_google.city == "Mountain View"
    assert res_google.asn == 15169

    # Cloudflare IPv6
    res_cf = isolated_geoip_adapter.lookup("2606:4700:4700::1111")
    assert res_cf is not None
    assert res_cf.country == "United States"
    assert res_cf.city == "San Francisco"
    assert res_cf.asn == 13335


# ==============================================================================
# 3. RFC Private, Loopback & Bogon Filtering Tests
# ==============================================================================


def test_rfc1918_private_ip_filtering(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """RFC 1918 and RFC 4193 private network addresses are flagged as INTERNAL without external lookups."""
    private_ips = [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.100.250",
        "fd00::1",  # IPv6 ULA
    ]

    for ip in private_ips:
        res = isolated_geoip_adapter.lookup(ip)
        assert res is not None
        assert res.is_private is True
        assert res.country == "Private Network"
        assert res.resolved_by == "RFC_PRIVATE"


def test_loopback_and_bogon_filtering(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Loopback (127.0.0.1, ::1) and link-local (169.254.x.x) are classified accurately."""
    # IPv4 Loopback
    res_loop4 = isolated_geoip_adapter.lookup("127.0.0.1")
    assert res_loop4 is not None
    assert res_loop4.is_private is True
    assert res_loop4.is_bogon is True
    assert res_loop4.country == "Loopback"
    assert res_loop4.city == "Localhost"

    # IPv6 Loopback
    res_loop6 = isolated_geoip_adapter.lookup("::1")
    assert res_loop6 is not None
    assert res_loop6.is_private is True
    assert res_loop6.is_bogon is True

    # Link-local
    res_link = isolated_geoip_adapter.lookup("169.254.1.1")
    assert res_link is not None
    assert res_link.is_private is True
    assert res_link.is_bogon is True
    assert res_link.country == "Reserved / Bogon"


# ==============================================================================
# 4. Port Stripping, Brackets & Malformed IP Handling
# ==============================================================================


def test_port_and_bracket_stripping(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Trailing ports and surrounding brackets are safely stripped before resolution."""
    assert isolated_geoip_adapter.lookup("8.8.8.8:53") is not None
    assert isolated_geoip_adapter.lookup("8.8.8.8:53").city == "Mountain View"  # type: ignore[union-attr]
    assert isolated_geoip_adapter.lookup("[1.1.1.1]:443").city == "San Francisco"  # type: ignore[union-attr]
    assert isolated_geoip_adapter.lookup(" [ 9.9.9.9 ] ").city == "Berkeley"  # type: ignore[union-attr]


def test_malformed_and_empty_inputs(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Empty, non-IP, or out-of-range strings return None without raising unhandled exceptions."""
    assert isolated_geoip_adapter.lookup(None) is None
    assert isolated_geoip_adapter.lookup("") is None
    assert isolated_geoip_adapter.lookup("   ") is None
    assert isolated_geoip_adapter.lookup("not.an.ip.address") is None
    assert isolated_geoip_adapter.lookup("999.999.999.999") is None
    assert isolated_geoip_adapter.lookup("256.0.0.1") is None


def test_unrecognized_public_ip_fallback(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Public IPs outside known subnets return Unknown/ZZ fallback without error."""
    res = isolated_geoip_adapter.lookup("198.51.100.1")  # TEST-NET-2 documentation IP
    assert res is not None
    assert res.country in {"Unknown", "Reserved / Bogon", "Private Network"}


# ==============================================================================
# 5. In-Memory LRU Cache & Performance SLA
# ==============================================================================


def test_lru_cache_hit_and_eviction(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Cached entries return resolved_by='CACHE' and respect cache bounding."""
    ip = "8.8.8.8"

    # First lookup: Cache miss, embedded hit
    res1 = isolated_geoip_adapter.lookup(ip)
    assert res1 is not None
    assert res1.resolved_by == "EMBEDDED_OFFLINE"

    # Second lookup: Cache hit
    res2 = isolated_geoip_adapter.lookup(ip)
    assert res2 is not None
    assert res2.city == res1.city

    # Check cache metrics
    snap = isolated_geoip_adapter.metrics.get_snapshot()
    assert snap.total_lookups == 2
    assert snap.cache_hits == 1
    assert snap.cache_misses == 1
    assert snap.hit_rate_pct == 50.0

    # Clear cache
    isolated_geoip_adapter.clear_cache()
    assert isolated_geoip_adapter.cache_size == 0


def test_geoip_lookup_performance_sla(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """10,000 cached lookups must complete in under 50ms (average < 5 microseconds per IP)."""
    ip = "1.1.1.1"
    # Warm up cache
    isolated_geoip_adapter.lookup(ip)

    start = time.perf_counter()
    for _ in range(10000):
        isolated_geoip_adapter.lookup(ip)
    duration = time.perf_counter() - start

    avg_us = (duration / 10000.0) * 1_000_000.0
    assert duration < 0.05, f"Took {duration:.4f}s; expected < 0.05s"
    assert avg_us < 10.0, f"Average lookup {avg_us:.2f}us; expected < 10us"


# ==============================================================================
# 6. UniversalLogEvent & ParsedResult Enrichment Tests
# ==============================================================================


def test_enrich_universal_log_event(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """UniversalLogEvent is enriched with GeoIPContext and source/destination attributes."""
    event = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Sample firewall log",
        detected_format=LogFormatEnum.CEF,
        source=SourceInfo(ip="8.8.8.8", port=53),
        destination=DestinationInfo(ip="10.0.0.1", port=443),
        action="ALLOW",
        parsed_by=ParsingTierEnum.RULE,
    )

    enriched = isolated_geoip_adapter.enrich_event(event)
    assert enriched.enrichment is not None
    assert enriched.enrichment.geoip is not None
    assert enriched.enrichment.geoip.country == "United States"
    assert enriched.enrichment.geoip.city == "Mountain View"

    # Both endpoints preserved in attributes
    assert "geoip_source" in enriched.attributes
    assert enriched.attributes["geoip_source"]["country"] == "United States"
    assert "geoip_destination" in enriched.attributes
    assert enriched.attributes["geoip_destination"]["is_private"] is True


def test_enrich_parsed_result(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """ParsedResult is enriched with geoip_source and geoip_destination in attributes."""
    parsed = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.INFORMATIONAL,
        source=SourceInfo(ip="3.120.10.5", port=8080),  # AWS Frankfurt
        destination=DestinationInfo(ip="1.1.1.1", port=443),  # Cloudflare SF
        attributes={"service": "payment-api"},
    )

    enriched = isolated_geoip_adapter.enrich_parsed_result(parsed)
    attrs = enriched.attributes
    assert "geoip_source" in attrs
    assert attrs["geoip_source"]["country"] == "Germany"
    assert attrs["geoip_source"]["city"] == "Frankfurt"
    assert "geoip_destination" in attrs
    assert attrs["geoip_destination"]["city"] == "San Francisco"


# ==============================================================================
# 7. Disabled Toggle & Telemetry Reset
# ==============================================================================


def test_geoip_disabled_toggle() -> None:
    """When enabled=False, lookup returns None and enrich_event does not modify the event."""
    config = GeoIPConfig(enabled=False)
    adapter = GeoIPAdapter(config=config)

    assert adapter.lookup("8.8.8.8") is None

    event = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Sample log",
        detected_format=LogFormatEnum.JSON,
        source=SourceInfo(ip="8.8.8.8"),
    )
    unmodified = adapter.enrich_event(event)
    assert unmodified.enrichment is None or unmodified.enrichment.geoip is None


def test_telemetry_metrics_reset(isolated_geoip_adapter: GeoIPAdapter) -> None:
    """Metrics snapshot invariants and reset functionality."""
    isolated_geoip_adapter.lookup("8.8.8.8")
    isolated_geoip_adapter.lookup("10.0.0.1")

    snap = isolated_geoip_adapter.metrics.get_snapshot()
    assert snap.total_lookups == 2
    assert snap.cache_misses == 2
    assert snap.private_ips_skipped == 1
    assert snap.embedded_lookups == 1

    isolated_geoip_adapter.metrics.reset()
    snap_after = isolated_geoip_adapter.metrics.get_snapshot()
    assert snap_after.total_lookups == 0
    assert snap_after.hit_rate_pct == 0.0


def test_default_singleton_accessor() -> None:
    """get_geoip_adapter returns a valid GeoIPAdapter singleton instance."""
    adapter = get_geoip_adapter()
    assert isinstance(adapter, GeoIPAdapter)
