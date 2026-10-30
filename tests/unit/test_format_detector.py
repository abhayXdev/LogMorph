"""Unit tests for the Format Detection Engine."""

import pytest

from logmorph.domain.uls import LogFormatEnum
from logmorph.engine.detector import detect_format
from logmorph.schemas.detection import DetectionResult


# ============================================================
# 1. CEF Detection
# ============================================================

class TestCEFDetection:
    def test_pure_cef_message(self):
        raw = "CEF:0|Security|Firewall|1.0|100|Traffic Denied|5|src=192.168.1.50 dst=10.0.0.1"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.CEF
        assert result.confidence >= 0.90

    def test_cef_with_syslog_header(self):
        """CEF wrapped in RFC 3164 syslog header — must still be detected as CEF, not Syslog."""
        raw = "<14>Mar 29 15:04:05 myhost CEF:0|Security|Firewall|1.0|100|Denied|5|src=1.2.3.4"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.CEF
        assert result.confidence >= 0.90


# ============================================================
# 2. LEEF Detection
# ============================================================

class TestLEEFDetection:
    def test_leef_v1(self):
        raw = "LEEF:1.0|Microsoft|MSExchange|2016|15345|src=10.50.1.1\tdst=2.10.20.20"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.LEEF
        assert result.confidence >= 0.90

    def test_leef_v2_with_syslog_prefix(self):
        raw = "<13>1 2026-06-06T05:34:55.000Z SERVER-1 - - - LEEF:2.0|PaloAlto|Firewall|10.1|TRAFFIC|"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.LEEF
        assert result.confidence >= 0.90


# ============================================================
# 3. JSON Detection
# ============================================================

class TestJSONDetection:
    def test_valid_json_object(self):
        raw = '{"timestamp": "2026-09-23T10:00:00Z", "level": "ERROR", "msg": "Timeout"}'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.JSON
        assert result.confidence >= 0.95

    def test_valid_json_array(self):
        raw = '[{"event": "login"}, {"event": "logout"}]'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.JSON
        assert result.confidence >= 0.95

    def test_invalid_json_starting_with_brace(self):
        """Malformed JSON that starts with { but isn't valid — should NOT be classified as JSON."""
        raw = "{this is not valid json at all}"
        result = detect_format(raw)
        assert result.detected_format != LogFormatEnum.JSON


# ============================================================
# 4. XML Detection
# ============================================================

class TestXMLDetection:
    def test_xml_with_declaration(self):
        raw = '<?xml version="1.0" encoding="UTF-8"?><event><type>alert</type></event>'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.XML
        assert result.confidence >= 0.90

    def test_xml_fragment_without_declaration(self):
        raw = '<event type="alert"><source>firewall</source></event>'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.XML
        assert result.confidence >= 0.70


# ============================================================
# 5. Syslog Detection
# ============================================================

class TestSyslogDetection:
    def test_syslog_rfc5424(self):
        raw = '<165>1 2026-10-11T22:14:15.003Z mymachine evntslog - ID47 [exampleSDID@32473 iut="3"] msg'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.SYSLOG
        assert result.sub_format == "RFC_5424"
        assert result.confidence >= 0.90

    def test_syslog_rfc3164_with_pri(self):
        raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.SYSLOG
        assert result.sub_format == "RFC_3164"
        assert result.confidence >= 0.85


# ============================================================
# 6. CLF Detection
# ============================================================

class TestCLFDetection:
    def test_common_log_format(self):
        raw = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.CLF
        assert result.confidence >= 0.85

    def test_combined_log_format(self):
        raw = '192.168.1.100 - - [10/Oct/2024:13:55:36 -0700] "POST /api/users HTTP/1.1" 201 512 "https://example.com" "Mozilla/5.0"'
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.CLF
        assert result.confidence >= 0.85


# ============================================================
# 7. Unstructured / Edge Cases
# ============================================================

class TestUnstructuredDetection:
    def test_plain_text_error_message(self):
        raw = "ERROR: Connection refused to database server at 10.0.0.5:5432"
        result = detect_format(raw)
        assert result.detected_format == LogFormatEnum.UNSTRUCTURED

    def test_empty_string_returns_unstructured(self):
        result = detect_format("")
        assert result.detected_format == LogFormatEnum.UNSTRUCTURED
        assert result.confidence <= 0.3

    def test_whitespace_only_returns_unstructured(self):
        result = detect_format("   \t\n  ")
        assert result.detected_format == LogFormatEnum.UNSTRUCTURED
        assert result.confidence <= 0.3


# ============================================================
# 8. Schema Validation
# ============================================================

class TestDetectionResultSchema:
    def test_detection_result_is_frozen(self):
        """DetectionResult should be immutable once created."""
        result = DetectionResult(
            detected_format=LogFormatEnum.JSON,
            confidence=0.99,
        )
        with pytest.raises(Exception):  # ValidationError for frozen model
            result.confidence = 0.5  # type: ignore[misc]

    def test_confidence_bounds(self):
        """Confidence must be between 0.0 and 1.0."""
        with pytest.raises(Exception):
            DetectionResult(detected_format=LogFormatEnum.JSON, confidence=1.5)
        with pytest.raises(Exception):
            DetectionResult(detected_format=LogFormatEnum.JSON, confidence=-0.1)
