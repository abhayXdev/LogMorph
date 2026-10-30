"""Comprehensive unit test suite for Tier 1 fast-path rules & regex parsers."""

import pytest

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, SeverityEnum
from logmorph.engine.parsers import (
    CefParser,
    ClfParser,
    JsonLogParser,
    LeefParser,
    SyslogParser,
    Tier1Dispatcher,
    XmlLogParser,
    parse_tier1,
)
from tests.fixtures.loader import load_fixture_lines


# ============================================================
# 1. JSON Parser Tests
# ============================================================

class TestJsonParser:
    def test_json_parser_success(self):
        raw = (
            '{"timestamp": "2026-10-30T03:15:20Z", "level": "ERROR", '
            '"service": "auth-svc", "sourceIPAddress": "198.51.100.5", '
            '"user": "alice", "action": "LOGIN_FAILED", "pid": 4120}'
        )
        parser = JsonLogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.JSON
        assert result.parsed_by == ParsingTierEnum.RULE
        assert result.raw_timestamp == "2026-10-30T03:15:20Z"
        assert result.severity == SeverityEnum.ERROR
        assert result.action == "LOGIN_FAILED"
        assert result.source is not None
        assert result.source.ip == "198.51.100.5"
        assert result.security is not None
        assert result.security.user == "alice"
        assert result.security.process_name == "auth-svc"
        assert result.security.process_id == 4120

    def test_json_parser_array_wrapping(self):
        raw = '[{"time": "2026-10-30T04:00:00Z", "level": "info", "msg": "server started"}]'
        parser = JsonLogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.raw_timestamp == "2026-10-30T04:00:00Z"
        assert result.severity == SeverityEnum.INFORMATIONAL

    def test_json_parser_syntax_error(self):
        raw = '{"broken": json without closing'
        parser = JsonLogParser()
        result = parser.parse(raw)

        assert result.success is False
        assert result.error_message is not None
        assert "JSON decoding error" in result.error_message


# ============================================================
# 2. Syslog Parser Tests (RFC 5424 & RFC 3164)
# ============================================================

class TestSyslogParser:
    def test_syslog_rfc5424_with_structured_data(self):
        raw = (
            '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 4512 ID47 '
            '[exampleSDID@32473 iut="3" eventSource="App"] BOMApplication alert message'
        )
        parser = SyslogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.SYSLOG
        assert result.raw_timestamp == "2003-10-11T22:14:15.003Z"
        assert result.severity == SeverityEnum.NOTICE  # 165 % 8 = 5 (Notice)
        assert result.source is not None
        assert result.source.hostname == "mymachine.example.com"
        assert result.security is not None
        assert result.security.process_name == "evntslog"
        assert result.security.process_id == 4512
        assert result.action == "ID47"
        assert "structured_data" in result.attributes
        assert result.attributes["structured_data"]["exampleSDID@32473"]["iut"] == "3"

    def test_syslog_rfc3164_with_pri(self):
        raw = '<86>Oct 12 04:02:18 server01 sshd[24123]: Failed password for invalid user admin from 192.168.1.105 port 51234 ssh2'
        parser = SyslogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.SYSLOG
        assert result.raw_timestamp == "Oct 12 04:02:18"
        assert result.severity == SeverityEnum.INFORMATIONAL  # 86 % 8 = 6 (Informational)
        assert result.source is not None
        assert result.source.hostname == "server01"
        assert result.source.ip == "192.168.1.105"
        assert result.source.port == 51234
        assert result.security is not None
        assert result.security.process_name == "sshd"
        assert result.security.process_id == 24123

    def test_syslog_rfc3164_no_pri(self):
        raw = 'Nov 03 14:22:01 workstation systemd[1]: Started Daily apt upgrade activities.'
        parser = SyslogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.raw_timestamp == "Nov 03 14:22:01"
        assert result.severity == SeverityEnum.INFORMATIONAL
        assert result.source is not None
        assert result.source.hostname == "workstation"
        assert result.security is not None
        assert result.security.process_name == "systemd"
        assert result.security.process_id == 1

    def test_syslog_invalid_syntax(self):
        raw = "Completely random non-syslog line"
        parser = SyslogParser()
        result = parser.parse(raw)

        assert result.success is False
        assert "does not match" in (result.error_message or "")


# ============================================================
# 3. Apache CLF / Combined Parser Tests
# ============================================================

class TestClfParser:
    def test_apache_common_log(self):
        raw = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
        parser = ClfParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.CLF
        assert result.raw_timestamp == "10/Oct/2000:13:55:36 -0700"
        assert result.severity == SeverityEnum.INFORMATIONAL
        assert result.action == "GET"
        assert result.source is not None
        assert result.source.ip == "127.0.0.1"
        assert result.security is not None
        assert result.security.user == "frank"
        assert result.attributes["status_code"] == 200
        assert result.attributes["bytes_sent"] == 2326
        assert result.attributes["format_type"] == "COMMON"

    def test_apache_combined_log_error_severity(self):
        raw = (
            '198.51.100.15 - - [22/Dec/2024:09:00:01 +0000] "DELETE /admin/config HTTP/1.1" '
            '500 142 "https://corp.intranet/" "curl/7.88.1"'
        )
        parser = ClfParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.severity == SeverityEnum.ERROR
        assert result.action == "DELETE"
        assert result.attributes["status_code"] == 500
        assert result.attributes["referer"] == "https://corp.intranet/"
        assert result.attributes["user_agent"] == "curl/7.88.1"
        assert result.attributes["format_type"] == "COMBINED"


# ============================================================
# 4. CEF Parser Tests
# ============================================================

class TestCefParser:
    def test_cef_standalone_event(self):
        raw = (
            "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|end|1|"
            "src=192.168.1.20 dst=10.0.0.10 spt=54321 dpt=443 proto=tcp act=allow"
        )
        parser = CefParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.CEF
        assert result.severity == SeverityEnum.NOTICE
        assert result.action == "allow"
        assert result.source is not None
        assert result.source.ip == "192.168.1.20"
        assert result.source.port == 54321
        assert result.destination is not None
        assert result.destination.ip == "10.0.0.10"
        assert result.destination.port == 443
        assert result.attributes["device_vendor"] == "Palo Alto Networks"
        assert result.attributes["device_product"] == "PAN-OS"

    def test_cef_syslog_wrapped_critical(self):
        raw = (
            "<14>Mar 29 15:04:05 firewall01 CEF:0|Security|Firewall|1.0|100|"
            "Traffic Denied|9|src=192.168.1.50 dst=10.0.0.1 spt=4521 dpt=80 act=drop"
        )
        parser = CefParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.severity == SeverityEnum.CRITICAL  # Score 9 -> CRITICAL
        assert result.action == "drop"
        assert result.source is not None
        assert result.source.ip == "192.168.1.50"


# ============================================================
# 5. LEEF Parser Tests
# ============================================================

class TestLeefParser:
    def test_leef_1_tab_delimited(self):
        raw = "LEEF:1.0|Microsoft|Active Directory|2019|4625|cat=Security\tusr=Administrator\tsrc=192.168.1.100\tdst=192.168.1.5\tmsg=An account failed to log on"
        parser = LeefParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.LEEF
        assert result.action == "Security"
        assert result.source is not None
        assert result.source.ip == "192.168.1.100"
        assert result.destination is not None
        assert result.destination.ip == "192.168.1.5"
        assert result.security is not None
        assert result.security.user == "Administrator"
        assert result.attributes["vendor"] == "Microsoft"
        assert result.attributes["event_id"] == "4625"

    def test_leef_2_custom_caret_delimiter(self):
        raw = "LEEF:2.0|Cisco|ASA|9.14|106015|^src=203.0.113.50^dst=198.51.100.25^spt=43210^dpt=22^cat=Deny^sev=8"
        parser = LeefParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.severity == SeverityEnum.CRITICAL  # sev=8
        assert result.source is not None
        assert result.source.ip == "203.0.113.50"
        assert result.source.port == 43210
        assert result.destination is not None
        assert result.destination.ip == "198.51.100.25"
        assert result.destination.port == 22
        assert result.action == "Deny"


# ============================================================
# 6. XML Parser Tests
# ============================================================

class TestXmlParser:
    def test_windows_security_event_xml(self):
        raw = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System>"
            '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
            "<EventID>4624</EventID>"
            "<Level>0</Level>"
            '<TimeCreated SystemTime="2026-10-30T03:15:20.123456Z"/>'
            "<Computer>DC01.corp.local</Computer>"
            "</System>"
            "<EventData>"
            '<Data Name="TargetUserName">jdoe</Data>'
            '<Data Name="LogonType">2</Data>'
            "</EventData>"
            "</Event>"
        )
        parser = XmlLogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.format == LogFormatEnum.XML
        assert result.raw_timestamp == "2026-10-30T03:15:20.123456Z"
        assert result.action == "4624"
        assert result.source is not None
        assert result.source.hostname == "DC01.corp.local"
        assert result.security is not None
        assert result.security.user == "jdoe"

    def test_generic_xml_alert(self):
        raw = '<alert><severity>critical</severity><message>Host compromised</message></alert>'
        parser = XmlLogParser()
        result = parser.parse(raw)

        assert result.success is True
        assert result.severity == SeverityEnum.CRITICAL
        assert result.attributes["message"] == "Host compromised"


# ============================================================
# 7. Tier 1 Dispatcher & Cascade Tests
# ============================================================

class TestTier1Dispatcher:
    def test_dispatcher_with_explicit_format(self):
        raw = '{"event": "ping", "status": "ok"}'
        result = parse_tier1(raw, detected_format=LogFormatEnum.JSON)
        assert result.success is True
        assert result.format == LogFormatEnum.JSON

    def test_dispatcher_with_auto_detection(self):
        raw = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /test HTTP/1.1" 200 120'
        result = parse_tier1(raw)  # detected_format=None -> auto-detect
        assert result.success is True
        assert result.format == LogFormatEnum.CLF

    def test_dispatcher_unstructured_triggers_tier2_fallback(self):
        raw = "java.lang.NullPointerException: string length is null"
        result = parse_tier1(raw, detected_format=LogFormatEnum.UNSTRUCTURED)

        assert result.success is False
        assert result.format == LogFormatEnum.UNSTRUCTURED
        assert "forwarding to Tier 2" in (result.error_message or "")


# ============================================================
# 8. Golden Corpus Full Suite Verification
# ============================================================

class TestGoldenCorpusTier1Parsing:
    """Verify that every single line in all 7 structured golden fixture files parses cleanly in Tier 1."""

    @pytest.mark.parametrize(
        "filename,expected_format",
        [
            ("syslog_rfc5424.log", LogFormatEnum.SYSLOG),
            ("syslog_rfc3164.log", LogFormatEnum.SYSLOG),
            ("apache_clf.log", LogFormatEnum.CLF),
            ("cef_events.log", LogFormatEnum.CEF),
            ("leef_events.log", LogFormatEnum.LEEF),
            ("json_events.jsonl", LogFormatEnum.JSON),
            ("xml_events.log", LogFormatEnum.XML),
        ],
    )
    def test_all_structured_fixtures_parse_in_tier1(
        self, filename: str, expected_format: LogFormatEnum
    ):
        lines = load_fixture_lines(filename)
        assert len(lines) > 0

        for idx, line in enumerate(lines):
            result = parse_tier1(line, detected_format=expected_format)
            assert result.success is True, (
                f"Failed to parse {filename} line {idx + 1}: {line}\n"
                f"Error: {result.error_message}"
            )
            assert result.format == expected_format
            assert result.parsed_by == ParsingTierEnum.RULE

    def test_unstructured_fixture_properly_falls_through_tier1(self):
        lines = load_fixture_lines("unstructured.log")
        assert len(lines) > 0

        for line in lines:
            result = parse_tier1(line, detected_format=LogFormatEnum.UNSTRUCTURED)
            # Unstructured MUST NOT be parsed by Tier 1 rules
            assert result.success is False
            assert "forwarding to Tier 2" in (result.error_message or "")
