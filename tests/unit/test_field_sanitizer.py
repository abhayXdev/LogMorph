"""Comprehensive unit test suite for Field Cleaning, Network Normalization, and PII Sanitization."""

import statistics
import time

from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.normalizers.sanitizer import (
    clean_attributes,
    clean_hostname,
    clean_ip,
    clean_mac,
    clean_text,
    is_luhn_valid,
    sanitize_parsed_result,
    scrub_pii,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.sanitization import (
    FieldCleaningConfig,
    SanitizationMaskType,
)


class TestTextAndControlCharCleaning:
    """Tests for stripping ANSI escape sequences, null bytes, zero-width characters, and control codes."""

    def test_strip_ansi_color_sequences(self):
        """Verify terminal color codes and cursor escape sequences are completely purged."""
        dirty = "\x1b[31;1mError:\x1b[0m \x1b[32mConnection refused\x1b[0m to port 443"
        cleaned = clean_text(dirty)
        assert cleaned == "Error: Connection refused to port 443"

    def test_strip_null_bytes_and_ascii_control_codes(self):
        """Verify null bytes (\x00) and ASCII control characters are stripped."""
        dirty = "user\x00root\x0blogin\x0cfail\x0e"
        cleaned = clean_text(dirty)
        assert cleaned == "userrootloginfail"

    def test_strip_zero_width_unicode_spaces(self):
        """Verify zero-width spaces (\u200b, \ufeff) are removed."""
        dirty = "token\u200bhidden\u200csecret\ufeffvalue"
        cleaned = clean_text(dirty)
        assert cleaned == "tokenhiddensecretvalue"

    def test_whitespace_trimming(self):
        """Verify leading, trailing, and newline whitespace is trimmed."""
        dirty = "   \n\t service cluster health ok \t\r\n  "
        cleaned = clean_text(dirty)
        assert cleaned == "service cluster health ok"

    def test_none_input_preservation(self):
        """Verify None input safely returns None without throwing."""
        assert clean_text(None) is None


class TestIpAndPortNormalization:
    """Tests for IPv4 and IPv6 canonicalization, port extraction, and RFC classification."""

    def test_ipv4_leading_zeroes_stripping(self):
        """IPv4 octet leading zeroes are stripped (192.168.001.001 -> 192.168.1.1)."""
        res = clean_ip("192.168.001.001")
        assert res is not None
        assert res.ip == "192.168.1.1"
        assert res.port is None
        assert res.is_ipv6 is False
        assert res.is_private is True
        assert res.is_public is False

    def test_ipv4_with_embedded_port(self):
        """Port is automatically parsed from IP:port strings."""
        res = clean_ip("10.0.0.5:8080")
        assert res is not None
        assert res.ip == "10.0.0.5"
        assert res.port == 8080
        assert res.is_private is True

    def test_ipv6_bracketed_with_port(self):
        """IPv6 bracketed notation with port is parsed and compressed."""
        res = clean_ip("[2001:0DB8:0000:0000:0000:0000:1428:57AB]:8443")
        assert res is not None
        assert res.ip == "2001:db8::1428:57ab"
        assert res.port == 8443
        assert res.is_ipv6 is True

    def test_public_internet_ip_classification(self):
        """Public internet IPs are classified as is_public=True."""
        res = clean_ip("8.8.8.8", port=53)
        assert res is not None
        assert res.ip == "8.8.8.8"
        assert res.port == 53
        assert res.is_public is True
        assert res.is_private is False
        assert res.is_loopback is False

    def test_loopback_ip_classification(self):
        """127.0.0.1 and ::1 are correctly identified as loopback."""
        res_v4 = clean_ip("127.0.0.1")
        assert res_v4 is not None
        assert res_v4.is_loopback is True
        assert res_v4.is_public is False

        res_v6 = clean_ip("::1")
        assert res_v6 is not None
        assert res_v6.is_loopback is True
        assert res_v6.is_public is False

    def test_multicast_ip_classification(self):
        """Multicast address ranges are correctly identified."""
        res = clean_ip("224.0.0.251")
        assert res is not None
        assert res.is_multicast is True
        assert res.is_public is False

    def test_invalid_ip_rejection(self):
        """Invalid IP addresses safely return None."""
        assert clean_ip("999.999.999.999") is None
        assert clean_ip("not.an.ip.address") is None
        assert clean_ip("-") is None
        assert clean_ip(None) is None

    def test_out_of_range_port_rejection(self):
        """Ports outside 1..65535 are discarded to None."""
        res = clean_ip("192.168.1.1:70000")
        assert res is not None
        assert res.ip == "192.168.1.1"
        assert res.port is None


class TestMacAddressNormalization:
    """Tests for MAC address canonicalization across vendor delimiter styles."""

    def test_cisco_dot_delimited_mac(self):
        """Cisco 3-group 4-digit format (001a.2b3c.4d5e) is converted to standard colon format."""
        assert clean_mac("001a.2b3c.4d5e") == "00:1a:2b:3c:4d:5e"

    def test_windows_hyphen_delimited_mac(self):
        """Windows hyphen notation (00-1A-2B-3C-4D-5E) is converted to lowercase colon format."""
        assert clean_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"

    def test_raw_hex_mac(self):
        """Raw 12-character hex string without delimiters is formatted correctly."""
        assert clean_mac("001A2B3C4D5E") == "00:1a:2b:3c:4d:5e"

    def test_invalid_mac_rejection(self):
        """MAC addresses with incorrect length or non-hex characters return None."""
        assert clean_mac("00:11:22") is None
        assert clean_mac("ZZ:YY:XX:WW:VV:UU") is None
        assert clean_mac(None) is None


class TestHostnameCleaning:
    """Tests for hostname and FQDN standardization."""

    def test_strip_trailing_root_domain_dot(self):
        """Trailing FQDN dot is stripped and string is lowercased."""
        assert clean_hostname("API.CORP.INTERNAL.") == "api.corp.internal"

    def test_strip_protocol_and_path_prefix(self):
        """Embedded URL protocols and paths are stripped."""
        assert clean_hostname("https://gateway.prod.cloud:8443/api/v1") == "gateway.prod.cloud"

    def test_invalid_hostname_sentinels(self):
        """Sentinel and empty hostname values return None."""
        assert clean_hostname("-") is None
        assert clean_hostname("nil") is None
        assert clean_hostname(None) is None


class TestLuhnAlgorithmAndCreditCardScrubbing:
    """Tests for Credit Card detection using strict Luhn algorithm validation."""

    def test_luhn_algorithm_validator(self):
        """Verify Luhn algorithm accepts valid cards and rejects non-Luhn serial numbers."""
        # Valid Visa
        assert is_luhn_valid("4532015112830366") is True
        # Valid Mastercard
        assert is_luhn_valid("5500000000000004") is True
        # Valid Amex
        assert is_luhn_valid("378282246310005") is True
        # Invalid checksum (random serial numbers)
        assert is_luhn_valid("1234567812345678") is False
        assert is_luhn_valid("4532015112830367") is False

    def test_credit_card_masking_with_luhn_check(self):
        """Valid credit cards are masked, while harmless numeric sequences are untouched."""
        text = "Customer paid with card 4532-0151-1283-0366 on order ID 1234-5678-1234-5678"
        sanitized, counts = scrub_pii(text)
        assert "4532-0151-1283-0366" not in sanitized
        assert "[REDACTED_CREDIT_CARD]" in sanitized
        # The non-Luhn order ID MUST remain untouched!
        assert "1234-5678-1234-5678" in sanitized
        assert counts[SanitizationMaskType.CREDIT_CARD.value] == 1


class TestSsnAndSecretTokenScrubbing:
    """Tests for SSN, API key, JWT, and password parameter sanitization."""

    def test_ssn_masking(self):
        """Valid US SSNs are redacted."""
        text = "Employee record: SSN 123-45-6789 verified"
        sanitized, counts = scrub_pii(text)
        assert "123-45-6789" not in sanitized
        assert "[REDACTED_SSN]" in sanitized
        assert counts[SanitizationMaskType.SSN.value] == 1

    def test_invalid_ssn_not_masked(self):
        """Invalid SSN patterns (e.g. area 000 or 666) are not masked."""
        text = "Batch tracking numbers: 000-45-6789 and 666-12-3456"
        sanitized, counts = scrub_pii(text)
        assert "000-45-6789" in sanitized
        assert "666-12-3456" in sanitized
        assert counts[SanitizationMaskType.SSN.value] == 0

    def test_nvidia_api_key_redaction(self):
        """NVIDIA NIM test and live API keys are redacted."""
        text = "Connected using key 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 securely"
        sanitized, counts = scrub_pii(text)
        assert "nvapi-" not in sanitized
        assert "[REDACTED_API_KEY]" in sanitized
        assert counts[SanitizationMaskType.API_KEY.value] == 1

    def test_openai_and_github_token_redaction(self):
        """OpenAI and GitHub tokens are redacted."""
        text = "OpenAI key sk-proj-1234567890abcdef1234567890abcdef12 and GitHub ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        sanitized, counts = scrub_pii(text)
        assert "sk-proj-" not in sanitized
        assert "ghp_" not in sanitized
        assert counts[SanitizationMaskType.API_KEY.value] == 2

    def test_jwt_redaction(self):
        """JWT tokens are redacted."""
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"Bearer token header: {jwt_token}"
        sanitized, counts = scrub_pii(text)
        assert jwt_token not in sanitized
        assert "[REDACTED_JWT]" in sanitized
        assert counts[SanitizationMaskType.JWT.value] == 1

    def test_password_parameter_redaction(self):
        """Key-value and URL query password parameters are redacted."""
        text = "GET /login?user=admin&password=SuperSecret123&client_secret=xyzSecret99 HTTP/1.1"
        sanitized, counts = scrub_pii(text)
        assert "SuperSecret123" not in sanitized
        assert "xyzSecret99" not in sanitized
        assert "password=[REDACTED]" in sanitized
        assert "client_secret=[REDACTED]" in sanitized
        assert counts[SanitizationMaskType.PASSWORD.value] == 2


class TestRecursiveAttributeAndParsedResultSanitization:
    """Tests for deep attribute cleaning, telemetry enrichment, and ParsedResult sanitization."""

    def test_clean_attributes_recursive(self):
        """Verify nested dictionaries and lists are cleansed recursively."""
        dirty_attrs = {
            " \x1b[31;1mquery_meta\x1b[0m ": {
                "user_token": "nvapi-1234567890abcdef1234567890abcdef123456",
                "nested_list": [" \x00clean_item\x00 ", "password=myPassword123!"],
            },
            "status_code": 200,
        }
        cleaned, report = clean_attributes(dirty_attrs)
        assert "query_meta" in cleaned
        assert cleaned["query_meta"]["user_token"] == "[REDACTED_API_KEY]"
        assert cleaned["query_meta"]["nested_list"][0] == "clean_item"
        assert cleaned["query_meta"]["nested_list"][1] == "password=[REDACTED]"
        assert cleaned["status_code"] == 200
        assert report.total_redactions == 2
        assert report.cleaned_fields_count >= 1

    def test_sanitize_parsed_result_full_pipeline(self):
        """Verify complete ParsedResult telemetry, endpoints, and attributes are sanitized."""
        raw_result = ParsedResult(
            success=True,
            format=LogFormatEnum.JSON,
            parsed_by=ParsingTierEnum.RULE,
            confidence=1.0,
            raw_timestamp="2026-10-30T10:00:00Z",
            severity=SeverityEnum.ERROR,
            action="login_failed",
            source=SourceInfo(ip=" 192.168.001.050:8080 ", hostname="DB-SERVER.CORP.", mac="001A.2B3C.4D5E"),
            destination=DestinationInfo(ip="8.8.8.8", hostname="DNS-RESOLVER", port=53),
            security=SecurityContext(user=" \x1b[32madmin\x1b[0m "),
            attributes={
                "message": "Auth failed for token nvapi-1234567890abcdef1234567890abcdef123456",
                "attempt": 1,
            },
        )

        cleaned_res, report = sanitize_parsed_result(raw_result)

        # Action uppercased and stripped
        assert cleaned_res.action == "LOGIN_FAILED"

        # Source telemetry cleaned and canonicalized
        assert cleaned_res.source is not None
        assert cleaned_res.source.ip == "192.168.1.50"
        assert cleaned_res.source.port == 8080
        assert cleaned_res.source.hostname == "db-server.corp"
        assert cleaned_res.source.mac == "00:1a:2b:3c:4d:5e"

        # Classification tags added to attributes
        assert cleaned_res.attributes["source_is_private"] is True
        assert cleaned_res.attributes["source_is_public"] is False
        assert cleaned_res.attributes["destination_is_public"] is True

        # Security context cleaned
        assert cleaned_res.security is not None
        assert cleaned_res.security.user == "admin"

        # Attribute message redacted
        assert "nvapi-" not in cleaned_res.attributes["message"]
        assert "[REDACTED_API_KEY]" in cleaned_res.attributes["message"]
        assert report.total_redactions == 1


class TestSanitizerPerformanceSLA:
    """High-throughput microsecond SLA assertions for the field sanitizer."""

    def test_sanitization_sub_50_microsecond_p99_sla(self) -> None:
        """Verify 1,000 text and attribute sanitizations achieve p50 < 30us and p99 < 60us."""
        dirty_samples: list[str] = [
            "\x1b[31;1mError: Database timeout\x1b[0m on 192.168.1.1:5432",
            "User authenticated with key nvapi-1234567890abcdef1234567890abcdef123456 successfully",
            "POST /api/v1/auth?password=SecretPassword123 from MAC 00-1A-2B-3C-4D-5E",
            "Valid customer transaction card 4532-0151-1283-0366 processed",
            "Clean baseline log without any secrets or escape sequences",
        ]

        # Warmup
        cfg = FieldCleaningConfig()
        for s in dirty_samples:
            for _ in range(50):
                clean_text(s)
                scrub_pii(s, cfg.mask_types)

        latencies_us: list[float] = []
        iterations = 1000

        for i in range(iterations):
            sample = dirty_samples[i % len(dirty_samples)]
            t0 = time.perf_counter_ns()
            t = clean_text(sample)
            assert t is not None
            scrub_pii(t, cfg.mask_types)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            latencies_us.append(elapsed_us)

        latencies_us.sort()
        p50 = statistics.median(latencies_us)
        p99 = latencies_us[int(iterations * 0.99)]

        # Senior SLA assertions: median under 35us, p99 under 70us
        assert p50 < 35.0, f"Sanitization median latency {p50:.2f}us exceeded 35us"
        assert p99 < 70.0, f"Sanitization p99 latency {p99:.2f}us exceeded 70us"
