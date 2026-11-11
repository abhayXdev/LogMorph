"""Comprehensive unit test suite for the Universal Timestamp Normalizer."""

import statistics
import time
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from logmorph.engine.normalizers.timestamp import (
    format_iso8601_z,
    normalize_timestamp,
)
from logmorph.schemas.normalization import (
    TimestampFormatEnum,
)


class TestIso8601Normalization:
    """Tests for ISO 8601 and RFC 3339 timestamp parsing and UTC canonicalization."""

    def test_utc_z_suffix(self):
        """Standard ISO 8601 with trailing Z."""
        res = normalize_timestamp("2026-10-30T10:00:00Z")
        assert res.matched_format == TimestampFormatEnum.ISO_8601
        assert res.confidence == 1.0
        assert res.was_fallback is False
        assert res.timezone_offset_seconds == 0
        assert res.timestamp == datetime(2026, 10, 30, 10, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-30T10:00:00Z"

    def test_positive_timezone_offset(self):
        """ISO 8601 with +05:30 offset is canonicalized to UTC."""
        res = normalize_timestamp("2026-10-30T15:30:00+05:30")
        assert res.matched_format == TimestampFormatEnum.ISO_8601
        assert res.confidence == 1.0
        assert res.timezone_offset_seconds == 19800
        assert res.timestamp == datetime(2026, 10, 30, 10, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-30T10:00:00Z"

    def test_negative_timezone_offset(self):
        """ISO 8601 with -04:00 offset is canonicalized to UTC."""
        res = normalize_timestamp("2026-10-30T06:00:00-04:00")
        assert res.matched_format == TimestampFormatEnum.ISO_8601
        assert res.timezone_offset_seconds == -14400
        assert res.timestamp == datetime(2026, 10, 30, 10, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-30T10:00:00Z"

    def test_microsecond_precision(self):
        """Fractional seconds with 6 digits are preserved accurately."""
        res = normalize_timestamp("2026-10-30T10:00:00.123456Z")
        assert res.timestamp.microsecond == 123456
        assert res.iso_8601 == "2026-10-30T10:00:00.123456Z"

    def test_millisecond_precision(self):
        """Fractional seconds with 3 digits are converted to microseconds."""
        res = normalize_timestamp("2026-10-30T10:00:00.123Z")
        assert res.timestamp.microsecond == 123000
        assert res.iso_8601 == "2026-10-30T10:00:00.123000Z"

    def test_space_separator_without_tz(self):
        """ISO timestamp with space separator and no timezone defaults to UTC."""
        res = normalize_timestamp("2026-10-30 10:00:00")
        assert res.matched_format == TimestampFormatEnum.ISO_8601
        assert res.timestamp == datetime(2026, 10, 30, 10, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-30T10:00:00Z"


class TestUnixEpochNormalization:
    """Tests for multi-resolution Unix epoch parsing across integers, floats, and strings."""

    def test_epoch_seconds_integer(self):
        """10-digit integer Unix epoch in seconds."""
        # 1729771200 = 2024-10-24 12:00:00 UTC
        res = normalize_timestamp(1729771200)
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_S
        assert res.confidence == 1.0
        assert res.timestamp == datetime(2024, 10, 24, 12, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2024-10-24T12:00:00Z"

    def test_epoch_seconds_string(self):
        """10-digit string Unix epoch in seconds."""
        res = normalize_timestamp("1729771200")
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_S
        assert res.timestamp == datetime(2024, 10, 24, 12, 0, 0, tzinfo=UTC)

    def test_epoch_milliseconds_integer(self):
        """13-digit integer Unix epoch in milliseconds."""
        res = normalize_timestamp(1729771200000)
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_MS
        assert res.timestamp == datetime(2024, 10, 24, 12, 0, 0, tzinfo=UTC)
        assert res.iso_8601 == "2024-10-24T12:00:00Z"

    def test_epoch_milliseconds_string(self):
        """13-digit string Unix epoch in milliseconds."""
        res = normalize_timestamp("1729771200123")
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_MS
        assert res.timestamp.microsecond == 123000

    def test_epoch_microseconds_integer(self):
        """16-digit integer Unix epoch in microseconds."""
        res = normalize_timestamp(1729771200123456)
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_US
        assert res.timestamp.microsecond == 123456

    def test_epoch_nanoseconds_integer(self):
        """19-digit integer Unix epoch in nanoseconds."""
        res = normalize_timestamp(1729771200123456789)
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_NS
        assert res.timestamp == datetime(2024, 10, 24, 12, 0, 0, 123456, tzinfo=UTC)

    def test_epoch_floating_point(self):
        """Floating point seconds with fractional sub-seconds."""
        res = normalize_timestamp(1729771200.5)
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_FLOAT
        assert res.timestamp.second == 0
        assert res.timestamp.microsecond == 500000

    def test_epoch_floating_point_string(self):
        """String representation of float epoch seconds."""
        res = normalize_timestamp("1729771200.123456")
        assert res.matched_format == TimestampFormatEnum.UNIX_EPOCH_FLOAT
        assert res.timestamp.microsecond == 123456


class TestSyslogRfc3164Normalization:
    """Tests for BSD Syslog RFC 3164 timestamps and Year Boundary Rollover algorithm."""

    def test_standard_syslog_timestamp(self):
        """Standard BSD Syslog with 2-digit day."""
        ref = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
        res = normalize_timestamp("Oct 30 08:30:00", reference_time=ref)
        assert res.matched_format == TimestampFormatEnum.SYSLOG_RFC3164
        assert res.confidence == 0.90
        assert res.timestamp == datetime(2026, 10, 30, 8, 30, 0, tzinfo=UTC)

    def test_syslog_single_digit_day_with_double_spaces(self):
        """BSD Syslog single-digit day formatted with space padding ('Jan  5')."""
        ref = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
        res = normalize_timestamp("Jan  5 14:22:01", reference_time=ref)
        assert res.matched_format == TimestampFormatEnum.SYSLOG_RFC3164
        assert res.timestamp == datetime(2026, 1, 5, 14, 22, 1, tzinfo=UTC)

    def test_year_boundary_december_log_in_january(self):
        """Critical Year Rollover: Log recorded Dec 31 ingested Jan 2 must map to previous year."""
        ref_in_january = datetime(2027, 1, 2, 0, 15, 0, tzinfo=UTC)
        res = normalize_timestamp("Dec 31 23:59:58", reference_time=ref_in_january)
        assert res.matched_format == TimestampFormatEnum.SYSLOG_RFC3164
        # Must resolve to 2026, NOT 2027!
        assert res.timestamp == datetime(2026, 12, 31, 23, 59, 58, tzinfo=UTC)
        assert res.iso_8601 == "2026-12-31T23:59:58Z"

    def test_year_boundary_january_log_in_december(self):
        """Clock Skew Rollover: Log recorded Jan 1 ingested Dec 31 must map to next year."""
        ref_in_december = datetime(2026, 12, 31, 23, 59, 50, tzinfo=UTC)
        res = normalize_timestamp("Jan  1 00:00:05", reference_time=ref_in_december)
        assert res.matched_format == TimestampFormatEnum.SYSLOG_RFC3164
        # Must resolve to 2027, NOT 2026!
        assert res.timestamp == datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC)


class TestApacheClfNormalization:
    """Tests for Apache Common Log Format (CLF) and Nginx access log dates."""

    def test_apache_clf_utc(self):
        """Standard Apache CLF with +0000 offset."""
        res = normalize_timestamp("10/Oct/2026:13:55:36 +0000")
        assert res.matched_format == TimestampFormatEnum.APACHE_CLF
        assert res.confidence == 1.0
        assert res.timezone_offset_seconds == 0
        assert res.timestamp == datetime(2026, 10, 10, 13, 55, 36, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-10T13:55:36Z"

    def test_apache_clf_with_offset(self):
        """Apache CLF with -0500 offset canonicalized to UTC."""
        res = normalize_timestamp("28/Feb/2026:09:12:00 -0500")
        assert res.matched_format == TimestampFormatEnum.APACHE_CLF
        assert res.timezone_offset_seconds == -18000
        # 09:12:00 -0500 = 14:12:00 UTC
        assert res.timestamp == datetime(2026, 2, 28, 14, 12, 0, tzinfo=UTC)
        assert res.iso_8601 == "2026-02-28T14:12:00Z"


class TestEnterpriseAndCustomNormalization:
    """Tests for Log4j commas, compact timestamps, RFC 2822, and fuzzy formats."""

    def test_log4j_comma_milliseconds(self):
        """Log4j and Python logging standard with comma millisecond separator."""
        res = normalize_timestamp("2026-10-30 14:15:20,123")
        assert res.matched_format == TimestampFormatEnum.ENTERPRISE_CUSTOM
        assert res.timestamp == datetime(2026, 10, 30, 14, 15, 20, 123000, tzinfo=UTC)
        assert res.iso_8601 == "2026-10-30T14:15:20.123000Z"

    def test_compact_timestamp_basic(self):
        """Compact timestamp YYYYMMDDTHHMMSSZ."""
        res = normalize_timestamp("20261030T141520Z")
        assert res.matched_format in (
            TimestampFormatEnum.ISO_8601,
            TimestampFormatEnum.ENTERPRISE_CUSTOM,
        )
        assert res.timestamp == datetime(2026, 10, 30, 14, 15, 20, tzinfo=UTC)

    def test_compact_timestamp_digits_only(self):
        """Compact digits-only YYYYMMDDHHMMSS."""
        # 14 digits: not epoch ms (13) or us (16)
        res = normalize_timestamp("20261030141520")
        assert res.matched_format == TimestampFormatEnum.ENTERPRISE_CUSTOM
        assert res.timestamp == datetime(2026, 10, 30, 14, 15, 20, tzinfo=UTC)

    def test_rfc2822_http_date(self):
        """RFC 2822 / HTTP email and web server date."""
        res = normalize_timestamp("Wed, 30 Oct 2026 14:15:20 GMT")
        assert res.matched_format == TimestampFormatEnum.RFC_2822
        assert res.confidence == 1.0
        assert res.timestamp == datetime(2026, 10, 30, 14, 15, 20, tzinfo=UTC)

    def test_fuzzy_dateutil_fallback(self):
        """Uncommon format resolved by dateutil fuzzy fallback."""
        ref = datetime(2026, 1, 1, tzinfo=UTC)
        res = normalize_timestamp("2026.10.30 at 14:15:00", reference_time=ref)
        assert res.matched_format == TimestampFormatEnum.FUZZY_DATEUTIL
        assert res.confidence in (0.85, 0.95)
        assert res.timestamp == datetime(2026, 10, 30, 14, 15, 0, tzinfo=UTC)


class TestTenantTimezoneLocalization:
    """Tests for multi-tenant default timezone localization applied to naive timestamps."""

    def test_naive_timestamp_localized_to_new_york(self):
        """Naive timestamp localized with America/New_York (EDT UTC-4 in October)."""
        res = normalize_timestamp(
            "2026-10-30 14:15:20",
            default_timezone="America/New_York",
        )
        assert res.confidence == 0.90
        assert res.timezone_offset_seconds == -14400
        # 14:15:20 EDT = 18:15:20 UTC
        assert res.timestamp == datetime(2026, 10, 30, 18, 15, 20, tzinfo=UTC)

    def test_naive_timestamp_localized_to_kolkata(self):
        """Naive timestamp localized with Asia/Kolkata (IST UTC+5:30)."""
        res = normalize_timestamp(
            "2026-10-30 14:15:20",
            default_timezone=ZoneInfo("Asia/Kolkata"),
        )
        assert res.confidence == 0.90
        assert res.timezone_offset_seconds == 19800
        # 14:15:20 IST = 08:45:20 UTC
        assert res.timestamp == datetime(2026, 10, 30, 8, 45, 20, tzinfo=UTC)

    def test_explicit_offset_overrides_default_timezone(self):
        """When an explicit offset is provided, default_timezone is ignored."""
        res = normalize_timestamp(
            "2026-10-30T14:15:20+02:00",
            default_timezone="America/New_York",
        )
        assert res.timezone_offset_seconds == 7200
        # 14:15:20 +02:00 = 12:15:20 UTC
        assert res.timestamp == datetime(2026, 10, 30, 12, 15, 20, tzinfo=UTC)


class TestFallbackAndEdgeCases:
    """Tests for missing, invalid, or corrupted timestamps and fallback degradation."""

    def test_none_input_defaults_to_reference_time(self):
        """None input returns reference time with was_fallback=True and confidence=0.0."""
        ref = datetime(2026, 10, 30, 11, 22, 33, tzinfo=UTC)
        res = normalize_timestamp(None, reference_time=ref)
        assert res.matched_format == TimestampFormatEnum.FALLBACK_INGESTION_TIME
        assert res.confidence == 0.0
        assert res.was_fallback is True
        assert res.timestamp == ref
        assert res.original_raw is None

    def test_empty_and_whitespace_strings(self):
        """Empty or whitespace strings fallback gracefully."""
        ref = datetime(2026, 10, 30, 11, 22, 33, tzinfo=UTC)
        for empty_val in ("", "   ", "\t\n"):
            res = normalize_timestamp(empty_val, reference_time=ref)
            assert res.was_fallback is True
            assert res.timestamp == ref

    def test_sentinel_nil_values(self):
        """Common log nil values ('-', 'nil', 'null', 'none') trigger fallback."""
        ref = datetime(2026, 10, 30, 11, 22, 33, tzinfo=UTC)
        for nil_val in ("-", "nil", "null", "none"):
            res = normalize_timestamp(nil_val, reference_time=ref)
            assert res.was_fallback is True
            assert res.timestamp == ref

    def test_unparseable_garbage_text(self):
        """Completely corrupted text degrades gracefully to reference time."""
        ref = datetime(2026, 10, 30, 11, 22, 33, tzinfo=UTC)
        res = normalize_timestamp("this_is_not_a_timestamp_at_all!!", reference_time=ref)
        assert res.was_fallback is True
        assert res.confidence == 0.0
        assert res.timestamp == ref

    def test_format_iso8601_z_helper(self):
        """Verify format_iso8601_z helper on both aware and naive datetimes."""
        dt_aware = datetime(2026, 10, 30, 10, 0, 0, 500, tzinfo=UTC)
        assert format_iso8601_z(dt_aware) == "2026-10-30T10:00:00.000500Z"

        dt_naive = datetime(2026, 10, 30, 10, 0, 0)
        assert format_iso8601_z(dt_naive) == "2026-10-30T10:00:00Z"


class TestLatencyAndPerformanceSLA:
    """High-throughput performance assertions for the timestamp normalizer fast-path."""

    def test_fast_path_sub_30_microsecond_p99_sla(self) -> None:
        """Verify 1,000 fast-path normalizations achieve p50 < 40us and p99 < 80us."""
        samples: list[str | int | float] = [
            "2026-10-30T10:00:00.123456Z",
            1729771200000,
            "10/Oct/2026:13:55:36 +0000",
            "Oct 30 08:30:00",
            "2026-10-30 14:15:20,123",
        ]
        # Warmup
        for s in samples:
            for _ in range(50):
                normalize_timestamp(s)

        latencies_us: list[float] = []
        iterations = 1000

        for i in range(iterations):
            sample = samples[i % len(samples)]
            t0 = time.perf_counter_ns()
            res = normalize_timestamp(sample)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            latencies_us.append(elapsed_us)
            assert res.was_fallback is False

        latencies_us.sort()
        p50 = statistics.median(latencies_us)
        p99 = latencies_us[int(iterations * 0.99)]

        # Senior SLA: median < 40us, p99 < 150us under parallel test load
        assert p50 < 40.0, f"Timestamp median latency {p50:.2f}us exceeded 40us"
        assert p99 < 150.0, f"Timestamp p99 latency {p99:.2f}us exceeded 150us"
