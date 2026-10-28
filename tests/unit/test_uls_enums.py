"""Unit tests for Universal Log Schema (ULS) enumeration types."""

import json

import pytest

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, SeverityEnum


def test_severity_enum_values():
    """Verify all RFC 5424 severity levels are defined and match string values."""
    expected_levels = [
        "EMERGENCY",
        "ALERT",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "NOTICE",
        "INFORMATIONAL",
        "DEBUG",
    ]
    for level in expected_levels:
        enum_val = SeverityEnum(level)
        assert enum_val == level
        assert isinstance(enum_val, str)


def test_log_format_enum_values():
    """Verify supported formats exist and evaluate as string-compatible enums."""
    formats = ["SYSLOG", "JSON", "CEF", "LEEF", "CLF", "XML", "UNSTRUCTURED"]
    for fmt in formats:
        enum_val = LogFormatEnum(fmt)
        assert enum_val == fmt
        assert isinstance(enum_val, str)


def test_parsing_tier_enum_values():
    """Verify 3-tier cascade values and fallback tier."""
    tiers = ["RULE", "TEMPLATE", "LLM", "FALLBACK"]
    for tier in tiers:
        enum_val = ParsingTierEnum(tier)
        assert enum_val == tier
        assert isinstance(enum_val, str)


def test_enum_json_serialization():
    """Verify that StrEnum instances serialize seamlessly to standard JSON."""
    data = {
        "format": LogFormatEnum.SYSLOG,
        "severity": SeverityEnum.CRITICAL,
        "tier": ParsingTierEnum.RULE,
    }
    serialized = json.dumps(data)
    deserialized = json.loads(serialized)

    assert deserialized == {
        "format": "SYSLOG",
        "severity": "CRITICAL",
        "tier": "RULE",
    }


def test_invalid_enum_instantiation_raises_value_error():
    """Verify that invalid enum strings raise ValueError."""
    with pytest.raises(ValueError):
        SeverityEnum("INVALID_SEVERITY")

    with pytest.raises(ValueError):
        LogFormatEnum("UNKNOWN_FORMAT")

    with pytest.raises(ValueError):
        ParsingTierEnum("TIER_99")
