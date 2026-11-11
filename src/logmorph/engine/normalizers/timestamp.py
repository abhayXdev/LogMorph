"""Universal Timestamp Normalizer for heterogeneous log formats.

Normalizes arbitrary raw timestamp formats (ISO-8601, Unix epochs, BSD Syslog,
Apache CLF, enterprise log4j, RFC 2822) into canonical timezone-aware UTC datetime
objects and standardized ISO 8601 strings.
"""

import re
from datetime import UTC, datetime, tzinfo
from email.utils import parsedate_to_datetime
from typing import Any
from zoneinfo import ZoneInfo

from dateutil import parser as dateutil_parser  # type: ignore[import-untyped]

from logmorph.schemas.normalization import (
    TimestampFormatEnum,
    TimestampNormalizationResult,
)

# Month abbreviations mapping for fast BSD Syslog & CLF parsing
_MONTH_NAME_TO_INT: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

# Pre-compiled high-performance fast-path regular expressions
_RE_SYSLOG_RFC3164 = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$",
    re.IGNORECASE,
)

_RE_APACHE_CLF = re.compile(
    r"^(\d{1,2})/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$"
)

_RE_LOG4J_COMMA = re.compile(
    r"^(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}),(\d{1,6})(.*)$"
)

_RE_COMPACT_TIMESTAMP = re.compile(
    r"^(\d{4})(\d{2})(\d{2})[T_]?(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?$"
)


def format_iso8601_z(dt: datetime) -> str:
    """Format a timezone-aware datetime into canonical ISO 8601 UTC with 'Z' suffix.

    Args:
        dt: Timezone-aware or naive datetime. If naive, assumes UTC.

    Returns:
        ISO 8601 string, e.g. '2026-10-30T10:00:00Z' or '2026-10-30T10:00:00.123456Z'.
    """
    utc_dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)

    base = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
    if utc_dt.microsecond > 0:
        return f"{base}.{utc_dt.microsecond:06d}Z"
    return f"{base}Z"


def _resolve_tz(tz: str | tzinfo | None) -> tzinfo:
    """Resolve a timezone input (string name, ZoneInfo, or tzinfo) to a valid tzinfo."""
    if tz is None:
        return UTC
    if isinstance(tz, tzinfo):
        return tz
    if isinstance(tz, str):
        try:
            return ZoneInfo(tz)
        except Exception:
            return UTC
    return UTC


def _extract_offset_seconds(dt: datetime) -> int:
    """Safely extract integer timezone offset in seconds from a datetime."""
    offset = dt.utcoffset()
    return int(offset.total_seconds()) if offset is not None else 0


def _resolve_rfc3164_year_rollover(
    month: int,
    day: int,
    hour: int,
    minute: int,
    second: int,
    microsecond: int,
    ref_dt: datetime,
) -> datetime:
    """Construct a candidate timestamp resolving the BSD Syslog missing year rollover.

    RFC 3164 omits the calendar year. When logs are ingested across the December -> January
    boundary, a naive current-year assumption can misplace logs by ~365 days.
    """
    candidate_year = ref_dt.year
    try:
        candidate = datetime(
            candidate_year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tzinfo=ref_dt.tzinfo,
        )
    except ValueError:
        # Handle leap year edge case (e.g. Feb 29 on non-leap reference year)
        candidate = datetime(
            candidate_year,
            month,
            min(day, 28),
            hour,
            minute,
            second,
            microsecond,
            tzinfo=ref_dt.tzinfo,
        )

    delta_seconds = (candidate - ref_dt).total_seconds()

    # If candidate is more than 30 days in the future (e.g. Dec log ingested in Jan),
    # roll back to the previous year.
    if delta_seconds > 30 * 86400:
        candidate = candidate.replace(year=candidate_year - 1)
    # If candidate is more than 335 days in the past (e.g. Jan log ingested in late Dec with clock skew),
    # roll forward to the next year.
    elif delta_seconds < -335 * 86400:
        candidate = candidate.replace(year=candidate_year + 1)

    return candidate


def _parse_numeric_epoch(
    num_val: float,
    is_float: bool,
    original_raw: Any,
) -> TimestampNormalizationResult | None:
    """Evaluate if a numeric value corresponds to a valid Unix epoch timestamp."""
    abs_val = abs(num_val)

    # 1. Epoch Nanoseconds: 10^17 <= |val| < 10^20 (18-19 digits)
    if 1e17 <= abs_val < 1e20:
        sec = int(num_val // 1_000_000_000)
        ns = int(num_val % 1_000_000_000)
        us = ns // 1_000
        dt = datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=us)
        return TimestampNormalizationResult(
            timestamp=dt,
            iso_8601=format_iso8601_z(dt),
            original_raw=original_raw,
            matched_format=TimestampFormatEnum.UNIX_EPOCH_NS,
            confidence=1.0,
            was_fallback=False,
            timezone_offset_seconds=0,
        )

    # 2. Epoch Microseconds: 10^14 <= |val| < 10^17 (15-16 digits)
    if 1e14 <= abs_val < 1e17:
        sec = int(num_val // 1_000_000)
        us = int(num_val % 1_000_000)
        dt = datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=us)
        return TimestampNormalizationResult(
            timestamp=dt,
            iso_8601=format_iso8601_z(dt),
            original_raw=original_raw,
            matched_format=TimestampFormatEnum.UNIX_EPOCH_US,
            confidence=1.0,
            was_fallback=False,
            timezone_offset_seconds=0,
        )

    # 3. Epoch Milliseconds: 10^11 <= |val| < 10^14 (12-13 digits)
    if 1e11 <= abs_val < 1e14:
        sec = int(num_val // 1_000)
        ms = int(num_val % 1_000)
        dt = datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=ms * 1_000)
        return TimestampNormalizationResult(
            timestamp=dt,
            iso_8601=format_iso8601_z(dt),
            original_raw=original_raw,
            matched_format=TimestampFormatEnum.UNIX_EPOCH_MS,
            confidence=1.0,
            was_fallback=False,
            timezone_offset_seconds=0,
        )

    # 4. Epoch Seconds: 10^8 <= |val| < 10^11 (9-10 digits, covering 1973 to 2286)
    if 1e8 <= abs_val < 1e11:
        dt = datetime.fromtimestamp(num_val, tz=UTC)
        matched = (
            TimestampFormatEnum.UNIX_EPOCH_FLOAT
            if is_float
            else TimestampFormatEnum.UNIX_EPOCH_S
        )
        return TimestampNormalizationResult(
            timestamp=dt,
            iso_8601=format_iso8601_z(dt),
            original_raw=original_raw,
            matched_format=matched,
            confidence=1.0,
            was_fallback=False,
            timezone_offset_seconds=0,
        )

    # 5. Low-range floating-point epoch seconds (e.g. historical or fractional epochs)
    if is_float and 0.0 <= abs_val < 1e8:
        dt = datetime.fromtimestamp(num_val, tz=UTC)
        return TimestampNormalizationResult(
            timestamp=dt,
            iso_8601=format_iso8601_z(dt),
            original_raw=original_raw,
            matched_format=TimestampFormatEnum.UNIX_EPOCH_FLOAT,
            confidence=1.0,
            was_fallback=False,
            timezone_offset_seconds=0,
        )

    return None


def normalize_timestamp(
    raw_timestamp: str | int | float | None,
    reference_time: datetime | None = None,
    default_timezone: str | ZoneInfo | tzinfo | None = None,
) -> TimestampNormalizationResult:
    """Normalize arbitrary raw timestamps into canonical timezone-aware UTC datetime.

    Args:
        raw_timestamp: Candidate raw timestamp extracted from log parser.
        reference_time: Ingestion or anchor datetime used for year rollover and fallbacks.
        default_timezone: Optional default timezone to apply to naive timestamps (defaults to UTC).

    Returns:
        TimestampNormalizationResult containing canonical UTC datetime, ISO 8601 string,
        matched format tag, confidence score, and fallback status.
    """
    ref_dt = reference_time.astimezone(UTC) if reference_time else datetime.now(UTC)
    resolved_default_tz = _resolve_tz(default_timezone)

    # Gate 0: Guard against None, empty strings, whitespace, or sentinel nil values
    if raw_timestamp is None:
        return TimestampNormalizationResult(
            timestamp=ref_dt,
            iso_8601=format_iso8601_z(ref_dt),
            original_raw=None,
            matched_format=TimestampFormatEnum.FALLBACK_INGESTION_TIME,
            confidence=0.0,
            was_fallback=True,
            timezone_offset_seconds=0,
        )

    # Handle numeric input directly
    if isinstance(raw_timestamp, (int, float)):
        res = _parse_numeric_epoch(float(raw_timestamp), isinstance(raw_timestamp, float), raw_timestamp)
        if res is not None:
            return res

    str_val = str(raw_timestamp).strip()
    if not str_val or str_val in ("-", "nil", "null", "none"):
        return TimestampNormalizationResult(
            timestamp=ref_dt,
            iso_8601=format_iso8601_z(ref_dt),
            original_raw=raw_timestamp,
            matched_format=TimestampFormatEnum.FALLBACK_INGESTION_TIME,
            confidence=0.0,
            was_fallback=True,
            timezone_offset_seconds=0,
        )

    # Gate 1: Check 14-digit compact timestamps (YYYYMMDDHHMMSS) starting with 19xx or 20xx
    if len(str_val) == 14 and str_val.isdigit() and (str_val.startswith("19") or str_val.startswith("20")):
        compact_match = _RE_COMPACT_TIMESTAMP.match(str_val)
        if compact_match:
            y, m, d, hh, mm, ss, us_str, tz_str = compact_match.groups()
            microsecond = int(us_str.ljust(6, "0")[:6]) if us_str else 0
            iso_candidate = f"{y}-{m}-{d}T{hh}:{mm}:{ss}"
            if microsecond > 0:
                iso_candidate += f".{microsecond:06d}"
            if tz_str:
                iso_candidate += tz_str
            try:
                dt = datetime.fromisoformat(iso_candidate)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=resolved_default_tz)
                    offset = _extract_offset_seconds(dt)
                    utc_dt = dt.astimezone(UTC)
                    confidence = 0.90 if resolved_default_tz != UTC else 1.0
                else:
                    offset = _extract_offset_seconds(dt)
                    utc_dt = dt.astimezone(UTC)
                    confidence = 1.0

                return TimestampNormalizationResult(
                    timestamp=utc_dt,
                    iso_8601=format_iso8601_z(utc_dt),
                    original_raw=raw_timestamp,
                    matched_format=TimestampFormatEnum.ENTERPRISE_CUSTOM,
                    confidence=confidence,
                    was_fallback=False,
                    timezone_offset_seconds=offset,
                )
            except (ValueError, TypeError):
                pass

    # Gate 2: Check stringified numeric epochs (e.g. "1729771200", "1729771200000", "1729771200.123")
    if str_val.isdigit() or (str_val.startswith("-") and str_val[1:].isdigit()):
        res = _parse_numeric_epoch(float(str_val), False, raw_timestamp)
        if res is not None:
            return res
    elif "." in str_val:
        try:
            num = float(str_val)
            res = _parse_numeric_epoch(num, True, raw_timestamp)
            if res is not None:
                return res
        except ValueError:
            pass

    # Gate 3: Fast-Path Enterprise Log4j / Comma-separated Milliseconds
    # e.g. '2026-10-30 14:15:20,123' or '2026/10/30 14:15:20,123'
    if "," in str_val:
        comma_match = _RE_LOG4J_COMMA.match(str_val)
        if comma_match:
            base_part, ms_part, tz_part = comma_match.groups()
            normalized_str = f"{base_part.replace('/', '-')}.{ms_part}{tz_part}"
            try:
                dt = datetime.fromisoformat(normalized_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=resolved_default_tz)
                    offset = _extract_offset_seconds(dt)
                    utc_dt = dt.astimezone(UTC)
                    confidence = 0.90 if resolved_default_tz != UTC else 1.0
                else:
                    offset = _extract_offset_seconds(dt)
                    utc_dt = dt.astimezone(UTC)
                    confidence = 1.0

                return TimestampNormalizationResult(
                    timestamp=utc_dt,
                    iso_8601=format_iso8601_z(utc_dt),
                    original_raw=raw_timestamp,
                    matched_format=TimestampFormatEnum.ENTERPRISE_CUSTOM,
                    confidence=confidence,
                    was_fallback=False,
                    timezone_offset_seconds=offset,
                )
            except (ValueError, TypeError):
                pass

    # Gate 4: Fast-Path C-Accelerated ISO 8601 / RFC 3339
    # Python 3.11 fromisoformat supports: '2026-10-30T10:00:00Z', '2026-10-30 10:00:00+05:30', etc.
    try:
        dt = datetime.fromisoformat(str_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=resolved_default_tz)
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            confidence = 0.90 if resolved_default_tz != UTC else 1.0
        else:
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            confidence = 1.0

        return TimestampNormalizationResult(
            timestamp=utc_dt,
            iso_8601=format_iso8601_z(utc_dt),
            original_raw=raw_timestamp,
            matched_format=TimestampFormatEnum.ISO_8601,
            confidence=confidence,
            was_fallback=False,
            timezone_offset_seconds=offset,
        )
    except (ValueError, TypeError):
        pass

    # Gate 4: Fast-Path BSD Syslog RFC 3164 (e.g. 'Oct 30 08:30:00', 'Jan  5 14:22:01')
    syslog_match = _RE_SYSLOG_RFC3164.match(str_val)
    if syslog_match:
        mon_str, day_str, hr_str, min_str, sec_str, us_str = syslog_match.groups()
        month = _MONTH_NAME_TO_INT[mon_str.lower()]
        day = int(day_str)
        hour = int(hr_str)
        minute = int(min_str)
        second = int(sec_str)
        microsecond = int(us_str.ljust(6, "0")[:6]) if us_str else 0

        candidate_dt = _resolve_rfc3164_year_rollover(
            month=month,
            day=day,
            hour=hour,
            minute=minute,
            second=second,
            microsecond=microsecond,
            ref_dt=ref_dt,
        )
        if candidate_dt.tzinfo is None or candidate_dt.tzinfo == UTC:
            candidate_dt = candidate_dt.replace(tzinfo=resolved_default_tz)
        offset = _extract_offset_seconds(candidate_dt)
        utc_dt = candidate_dt.astimezone(UTC)

        return TimestampNormalizationResult(
            timestamp=utc_dt,
            iso_8601=format_iso8601_z(utc_dt),
            original_raw=raw_timestamp,
            matched_format=TimestampFormatEnum.SYSLOG_RFC3164,
            confidence=0.90,  # Inferred year
            was_fallback=False,
            timezone_offset_seconds=offset,
        )

    # Gate 5: Fast-Path Apache Common Log Format (e.g. '10/Oct/2026:13:55:36 +0000')
    clf_match = _RE_APACHE_CLF.match(str_val)
    if clf_match:
        try:
            dt = datetime.strptime(str_val, "%d/%b/%Y:%H:%M:%S %z")
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            return TimestampNormalizationResult(
                timestamp=utc_dt,
                iso_8601=format_iso8601_z(utc_dt),
                original_raw=raw_timestamp,
                matched_format=TimestampFormatEnum.APACHE_CLF,
                confidence=1.0,
                was_fallback=False,
                timezone_offset_seconds=offset,
            )
        except (ValueError, TypeError):
            pass

    # Gate 6: Fast-Path Compact Timestamps (e.g. '20261030T141520Z', '20261030141520')
    compact_match = _RE_COMPACT_TIMESTAMP.match(str_val)
    if compact_match:
        y, m, d, hh, mm, ss, us_str, tz_str = compact_match.groups()
        microsecond = int(us_str.ljust(6, "0")[:6]) if us_str else 0
        iso_candidate = f"{y}-{m}-{d}T{hh}:{mm}:{ss}"
        if microsecond > 0:
            iso_candidate += f".{microsecond:06d}"
        if tz_str:
            iso_candidate += tz_str
        try:
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=resolved_default_tz)
                offset = _extract_offset_seconds(dt)
                utc_dt = dt.astimezone(UTC)
                confidence = 0.90 if resolved_default_tz != UTC else 1.0
            else:
                offset = _extract_offset_seconds(dt)
                utc_dt = dt.astimezone(UTC)
                confidence = 1.0

            return TimestampNormalizationResult(
                timestamp=utc_dt,
                iso_8601=format_iso8601_z(utc_dt),
                original_raw=raw_timestamp,
                matched_format=TimestampFormatEnum.ENTERPRISE_CUSTOM,
                confidence=confidence,
                was_fallback=False,
                timezone_offset_seconds=offset,
            )
        except (ValueError, TypeError):
            pass

    # Gate 7: RFC 2822 / HTTP Date Format (e.g. 'Wed, 30 Oct 2026 14:15:20 GMT')
    try:
        dt = parsedate_to_datetime(str_val)
        if dt is not None and isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=resolved_default_tz)
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            return TimestampNormalizationResult(
                timestamp=utc_dt,
                iso_8601=format_iso8601_z(utc_dt),
                original_raw=raw_timestamp,
                matched_format=TimestampFormatEnum.RFC_2822,
                confidence=1.0,
                was_fallback=False,
                timezone_offset_seconds=offset,
            )
    except (ValueError, TypeError, IndexError):
        pass

    # Gate 8: Resilient Fallback to python-dateutil parser
    try:
        dt = dateutil_parser.parse(str_val, default=ref_dt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=resolved_default_tz)
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            confidence = 0.85
        else:
            offset = _extract_offset_seconds(dt)
            utc_dt = dt.astimezone(UTC)
            confidence = 0.95

        return TimestampNormalizationResult(
            timestamp=utc_dt,
            iso_8601=format_iso8601_z(utc_dt),
            original_raw=raw_timestamp,
            matched_format=TimestampFormatEnum.FUZZY_DATEUTIL,
            confidence=confidence,
            was_fallback=False,
            timezone_offset_seconds=offset,
        )
    except Exception:
        pass

    # Gate 9: Graceful Terminal Fallback
    return TimestampNormalizationResult(
        timestamp=ref_dt,
        iso_8601=format_iso8601_z(ref_dt),
        original_raw=raw_timestamp,
        matched_format=TimestampFormatEnum.FALLBACK_INGESTION_TIME,
        confidence=0.0,
        was_fallback=True,
        timezone_offset_seconds=0,
    )
