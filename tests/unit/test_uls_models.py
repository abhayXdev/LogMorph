"""Unit tests for Universal Log Schema (ULS) data models and serialization."""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from logmorph.domain.uls import (
    DestinationInfo,
    EnrichmentContext,
    GeoIPContext,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
    UniversalLogEvent,
)


def test_universal_log_event_creation_minimal():
    """Verify that an event with only required fields initializes valid defaults."""
    tenant_id = uuid4()
    raw_log = "<34>Oct 11 22:14:15 mymachine sshd: Failed password for root"

    event = UniversalLogEvent(
        tenant_id=tenant_id,
        raw_log=raw_log,
        detected_format=LogFormatEnum.SYSLOG,
    )

    assert event.event_id.startswith("evt_")
    assert event.tenant_id == tenant_id
    assert event.raw_log == raw_log
    assert event.detected_format == LogFormatEnum.SYSLOG
    assert event.severity == SeverityEnum.INFORMATIONAL
    assert event.parsed_by == ParsingTierEnum.RULE
    assert event.source is None
    assert event.destination is None
    assert event.security is None
    assert event.enrichment is None
    assert isinstance(event.attributes, dict)
    assert event.timestamp.tzinfo is not None
    assert event.ingested_at.tzinfo is not None


def test_universal_log_event_full_telemetry():
    """Verify comprehensive event with all telemetry layers."""
    tenant_id = uuid4()
    event_timestamp = datetime(2026, 10, 11, 22, 14, 15, tzinfo=UTC)

    source = SourceInfo(ip="192.168.1.50", hostname="mymachine", port=54321)
    destination = DestinationInfo(ip="10.0.0.1", hostname="auth-gw", port=22)
    security = SecurityContext(
        user="lonvick",
        process_name="su",
        process_id=4521,
        mitre_technique="T1110",
    )
    geoip = GeoIPContext(
        country="India",
        country_code="IN",
        city="Mumbai",
        latitude=19.076,
        longitude=72.8777,
    )
    enrichment = EnrichmentContext(
        geoip=geoip,
        threat_match=False,
        mitre_technique="T1110 - Brute Force",
        mitre_tactic="Credential Access",
    )

    event = UniversalLogEvent(
        tenant_id=tenant_id,
        timestamp=event_timestamp,
        raw_log="sample log text",
        detected_format=LogFormatEnum.SYSLOG,
        severity=SeverityEnum.CRITICAL,
        source=source,
        destination=destination,
        security=security,
        action="LOGIN_FAILED",
        parsed_by=ParsingTierEnum.RULE,
        attributes={"facility": "auth", "priority": 34},
        enrichment=enrichment,
    )

    assert event.severity == SeverityEnum.CRITICAL
    assert event.action == "LOGIN_FAILED"
    assert event.source is not None and event.source.ip == "192.168.1.50"
    assert event.destination is not None and event.destination.port == 22
    assert event.security is not None and event.security.user == "lonvick"
    assert event.enrichment is not None and event.enrichment.geoip is not None
    assert event.enrichment.geoip.country == "India"


def test_tenant_id_mandatory_for_isolation():
    """Verify that omitting tenant_id causes a validation error."""
    with pytest.raises(ValidationError):
        UniversalLogEvent(  # type: ignore[call-arg]
            raw_log="unauthorized log missing tenant",
            detected_format=LogFormatEnum.JSON,
        )


def test_tenant_id_must_be_valid_uuid():
    """Verify that invalid tenant identifiers are rejected."""
    with pytest.raises(ValidationError):
        UniversalLogEvent(
            tenant_id="not-a-valid-uuid",  # type: ignore[arg-type]
            raw_log="sample log",
            detected_format=LogFormatEnum.JSON,
        )


def test_json_serialization_matches_api_contract():
    """Verify JSON dumping matches the exact schema specified in API_CONTRACT.md."""
    tenant_id = UUID("f1e2d3c4-b5a6-7890-abcd-ef1234567890")
    event = UniversalLogEvent(
        event_id="evt_test_1234",
        tenant_id=tenant_id,
        raw_log="test log message",
        detected_format=LogFormatEnum.CEF,
        severity=SeverityEnum.WARNING,
        action="BLOCK",
        source=SourceInfo(ip="10.1.1.5"),
        attributes={"act": "BLOCK"},
    )

    dumped_json = event.model_dump_json()
    parsed_json = json.loads(dumped_json)

    assert parsed_json["event_id"] == "evt_test_1234"
    assert parsed_json["tenant_id"] == "f1e2d3c4-b5a6-7890-abcd-ef1234567890"
    assert parsed_json["detected_format"] == "CEF"
    assert parsed_json["severity"] == "WARNING"
    assert parsed_json["action"] == "BLOCK"
    assert parsed_json["source"]["ip"] == "10.1.1.5"
    assert parsed_json["destination"] is None
    assert parsed_json["attributes"] == {"act": "BLOCK"}


def test_source_and_destination_models():
    """Verify telemetry models accept valid data and reject invalid types."""
    src = SourceInfo(ip="127.0.0.1", port=8080)
    assert src.ip == "127.0.0.1"
    assert src.port == 8080
    assert src.hostname is None

    with pytest.raises(ValidationError):
        SourceInfo(port="not-a-port")  # type: ignore[arg-type]


def test_enrichment_context_defaults():
    """Verify default boolean flags in EnrichmentContext."""
    enrichment = EnrichmentContext()
    assert enrichment.threat_match is False
    assert enrichment.geoip is None
    assert enrichment.mitre_technique is None
    assert enrichment.mitre_tactic is None
