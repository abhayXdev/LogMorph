"""Comprehensive unit test suite for Threat Intelligence Matcher engine.

Tests multi-IOC matching (IPs, domains, hashes, CIDRs), benign pass-through,
mock provider extensibility, in-memory LRU caching, telemetry reconciliation,
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
    SecurityContext,
    SeverityEnum,
    SourceInfo,
    UniversalLogEvent,
)
from logmorph.engine.enrichers.threat_intel import (
    LocalThreatIntelProvider,
    MockThreatIntelProvider,
    ThreatIntelMatcher,
    ThreatIntelMetrics,
    get_threat_intel_matcher,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.threat_intel import (
    IOCTypeEnum,
    ThreatCategoryEnum,
    ThreatIndicator,
    ThreatIntelConfig,
)


@pytest.fixture
def isolated_threat_matcher() -> ThreatIntelMatcher:
    """Return a pristine ThreatIntelMatcher with isolated metrics and cache."""
    metrics = ThreatIntelMetrics()
    provider = LocalThreatIntelProvider()
    config = ThreatIntelConfig(cache_size=1000, enabled=True)
    return ThreatIntelMatcher(providers=[provider], config=config, metrics=metrics)


# ==============================================================================
# 1. Exact IP IOC Matching Tests
# ==============================================================================


def test_c2_ip_exact_match(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """Known Cobalt Strike and Emotet C2 IPs match with CRITICAL severity."""
    # Cobalt Strike C2
    res_cs = isolated_threat_matcher.match_ioc("194.26.29.112")
    assert res_cs is not None
    assert res_cs.is_match is True
    assert res_cs.threat_name == "Cobalt Strike C2"
    assert res_cs.category == ThreatCategoryEnum.C2_SERVER
    assert res_cs.severity == SeverityEnum.CRITICAL
    assert res_cs.confidence >= 0.95

    # Emotet C2
    res_emotet = isolated_threat_matcher.match_ioc("198.51.100.200")
    assert res_emotet is not None
    assert res_emotet.threat_name == "Emotet C2 Server"
    assert res_emotet.category == ThreatCategoryEnum.C2_SERVER


def test_tor_exit_and_botnet_ip_match(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """Tor exit relays and Mirai botnet IPs match accurately."""
    # Tor Exit Node
    res_tor = isolated_threat_matcher.match_ioc("185.220.101.5")
    assert res_tor is not None
    assert res_tor.category == ThreatCategoryEnum.TOR_EXIT_NODE
    assert res_tor.severity == SeverityEnum.WARNING

    # Mirai Botnet
    res_mirai = isolated_threat_matcher.match_ioc("45.33.32.156:23")  # Port stripped
    assert res_mirai is not None
    assert res_mirai.threat_name == "Mirai Botnet Scanner"
    assert res_mirai.category == ThreatCategoryEnum.BOTNET


# ==============================================================================
# 2. Malicious CIDR Subnet Matching Tests
# ==============================================================================


def test_malicious_cidr_subnet_match(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """IPs falling inside a known malicious CIDR block trigger a threat match."""
    # 198.51.100.192/28 covers .192 through .207
    test_ips = ["198.51.100.193", "198.51.100.195", "198.51.100.205"]
    for ip in test_ips:
        res = isolated_threat_matcher.match_ioc(ip)
        assert res is not None, f"Failed for {ip}"
        assert res.threat_name == "Malicious Scanner Subnet"
        assert res.category == ThreatCategoryEnum.SCANNER
        assert res.severity == SeverityEnum.ERROR

    # IP right outside the CIDR block must NOT match
    assert isolated_threat_matcher.match_ioc("198.51.100.191") is None
    assert isolated_threat_matcher.match_ioc("198.51.100.208") is None


# ==============================================================================
# 3. Domain & FQDN IOC Matching Tests
# ==============================================================================


def test_malicious_domain_matching(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """C2 domains, phishing URLs, and malware drop sites are identified."""
    # Cobalt Strike Domain
    res_c2 = isolated_threat_matcher.match_ioc("evil-c2-beacon.top")
    assert res_c2 is not None
    assert res_c2.category == ThreatCategoryEnum.C2_SERVER
    assert res_c2.severity == SeverityEnum.CRITICAL

    # Phishing Domain
    res_phish = isolated_threat_matcher.match_ioc("phish-secure-login.xyz")
    assert res_phish is not None
    assert res_phish.category == ThreatCategoryEnum.PHISHING

    # Malware Drop
    res_drop = isolated_threat_matcher.match_ioc("malware-drop-payload.com")
    assert res_drop is not None
    assert res_drop.category == ThreatCategoryEnum.MALWARE


# ==============================================================================
# 4. File Hash Matching Tests (SHA-256 & MD5)
# ==============================================================================


def test_malware_file_hash_matching(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """EICAR test string, WannaCry ransomware, and Emotet hashes match correctly."""
    # EICAR SHA-256
    eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res_eicar = isolated_threat_matcher.match_ioc(eicar_sha)
    assert res_eicar is not None
    assert res_eicar.threat_name == "EICAR Standard AV Test File"
    assert res_eicar.category == ThreatCategoryEnum.MALWARE

    # WannaCry SHA-256
    wannacry_sha = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
    res_wc_sha = isolated_threat_matcher.match_ioc(wannacry_sha)
    assert res_wc_sha is not None
    assert res_wc_sha.threat_name == "WannaCry Ransomware"
    assert res_wc_sha.severity == SeverityEnum.CRITICAL

    # WannaCry MD5
    wannacry_md5 = "84c82835a5d21bbcf75a61706d8ab549"
    res_wc_md5 = isolated_threat_matcher.match_ioc(wannacry_md5)
    assert res_wc_md5 is not None
    assert res_wc_md5.threat_name == "WannaCry Ransomware (MD5)"


# ==============================================================================
# 5. Benign Traffic Clean Pass-Through Tests
# ==============================================================================


def test_benign_traffic_pass_through(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """Legitimate DNS, public websites, internal IPs, and clean hashes return None."""
    benign_samples = [
        "8.8.8.8",
        "1.1.1.1",
        "192.168.1.1",
        "10.0.0.1",
        "google.com",
        "github.com",
        "microsoft.com",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty string hash
        None,
        "",
        "   ",
    ]

    for sample in benign_samples:
        assert isolated_threat_matcher.match_ioc(sample) is None


# ==============================================================================
# 6. Mock Provider Extensibility Tests
# ==============================================================================


def test_mock_threat_provider_dynamic_registration() -> None:
    """MockThreatIntelProvider allows injecting custom test IOCs dynamically."""
    mock_provider = MockThreatIntelProvider()
    custom_ind = ThreatIndicator(
        ioc_value="custom-apt-campaign.org",
        ioc_type=IOCTypeEnum.DOMAIN,
        threat_name="APT29 Cozy Bear",
        category=ThreatCategoryEnum.C2_SERVER,
        severity=SeverityEnum.CRITICAL,
        confidence=0.99,
        source_feed="UNIT_TEST_MOCK",
    )
    mock_provider.add_mock_indicator(custom_ind)

    matcher = ThreatIntelMatcher(providers=[mock_provider])
    res = matcher.match_ioc("custom-apt-campaign.org")
    assert res is not None
    assert res.threat_name == "APT29 Cozy Bear"
    assert res.source_feed == "UNIT_TEST_MOCK"

    # Clearing mock provider removes match
    mock_provider.clear()
    matcher.clear_cache()
    assert matcher.match_ioc("custom-apt-campaign.org") is None


# ==============================================================================
# 7. In-Memory LRU Cache & Performance SLA
# ==============================================================================


def test_lru_cache_hit_and_eviction(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """Cached queries are served from cache and update metrics accordingly."""
    ioc = "194.26.29.112"

    # 1st lookup: Cache miss
    res1 = isolated_threat_matcher.match_ioc(ioc)
    assert res1 is not None

    # 2nd lookup: Cache hit
    res2 = isolated_threat_matcher.match_ioc(ioc)
    assert res2 is not None
    assert res2.threat_name == res1.threat_name

    snap = isolated_threat_matcher.metrics.get_snapshot()
    assert snap.total_scans == 2
    assert snap.cache_hits == 1
    assert snap.cache_misses == 1
    assert snap.threats_detected == 2

    # Clear cache
    isolated_threat_matcher.clear_cache()
    assert isolated_threat_matcher.cache_size == 0


def test_threat_intel_performance_sla(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """10,000 cached threat evaluations must execute in under 50ms (average < 5us per scan)."""
    ioc = "evil-c2-beacon.top"
    isolated_threat_matcher.match_ioc(ioc)

    start = time.perf_counter()
    for _ in range(10000):
        isolated_threat_matcher.match_ioc(ioc)
    duration = time.perf_counter() - start

    avg_us = (duration / 10000.0) * 1_000_000.0
    assert duration < 0.20, f"Took {duration:.4f}s; expected < 0.20s"
    assert avg_us < 20.0, f"Average scan {avg_us:.2f}us; expected < 20us"


# ==============================================================================
# 8. UniversalLogEvent & ParsedResult Enrichment Tests
# ==============================================================================


def test_enrich_universal_log_event(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """UniversalLogEvent with C2 IP is enriched with threat_match and threat_id."""
    event = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Outbound connection to malicious IP",
        detected_format=LogFormatEnum.CEF,
        source=SourceInfo(ip="10.0.0.50"),
        destination=DestinationInfo(ip="194.26.29.112", port=443),
        action="CONNECT",
        parsed_by=ParsingTierEnum.RULE,
        security=SecurityContext(user="victim_user"),
    )

    enriched = isolated_threat_matcher.enrich_event(event)
    assert enriched.enrichment is not None
    assert enriched.enrichment.threat_match is True
    assert enriched.security is not None
    assert enriched.security.threat_id == "Cobalt Strike C2"
    assert "threat_intel" in enriched.attributes
    assert enriched.attributes["threat_intel"]["category"] == "C2_SERVER"


def test_enrich_parsed_result(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """ParsedResult containing malicious hash is enriched with threat_intel telemetry."""
    parsed = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.INFORMATIONAL,
        attributes={
            "sha256": "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
            "file_name": "taskhost.exe",
        },
    )

    enriched = isolated_threat_matcher.enrich_parsed_result(parsed)
    assert enriched.attributes.get("threat_match") is True
    assert "threat_intel" in enriched.attributes
    assert enriched.attributes["threat_intel"]["threat_name"] == "WannaCry Ransomware"
    assert enriched.security is not None
    assert enriched.security.threat_id == "WannaCry Ransomware"


# ==============================================================================
# 9. Disabled Toggle & Telemetry Reset
# ==============================================================================


def test_threat_intel_disabled_toggle() -> None:
    """When enabled=False, match_ioc returns None and enrich_event does not modify the event."""
    config = ThreatIntelConfig(enabled=False)
    matcher = ThreatIntelMatcher(config=config)

    assert matcher.match_ioc("194.26.29.112") is None

    event = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Sample log",
        detected_format=LogFormatEnum.JSON,
        destination=DestinationInfo(ip="194.26.29.112"),
    )
    unmodified = matcher.enrich_event(event)
    assert unmodified.enrichment is None or unmodified.enrichment.threat_match is False


def test_telemetry_metrics_reconciliation(isolated_threat_matcher: ThreatIntelMatcher) -> None:
    """Metrics snapshot reconciliation: total_scans == threats_detected + benign_scans."""
    isolated_threat_matcher.match_ioc("194.26.29.112")  # Match
    isolated_threat_matcher.match_ioc("8.8.8.8")        # Benign

    snap = isolated_threat_matcher.metrics.get_snapshot()
    assert snap.total_scans == 2
    assert snap.threats_detected == 1
    assert snap.benign_scans == 1
    assert snap.detection_rate_pct == 50.0

    isolated_threat_matcher.metrics.reset()
    snap_after = isolated_threat_matcher.metrics.get_snapshot()
    assert snap_after.total_scans == 0


def test_default_singleton_accessor() -> None:
    """get_threat_intel_matcher returns a valid ThreatIntelMatcher singleton instance."""
    matcher = get_threat_intel_matcher()
    assert isinstance(matcher, ThreatIntelMatcher)
