"""Field cleaning, endpoint normalization, and sensitive compliance data sanitization engine."""

import ipaddress
import re
from collections import Counter
from typing import Any

from logmorph.domain.uls import DestinationInfo, SecurityContext, SourceInfo
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.sanitization import (
    CleanedIP,
    FieldCleaningConfig,
    SanitizationMaskType,
    SanitizationReport,
)

# Pre-compiled high-performance regular expressions
_RE_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_RE_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_RE_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Network endpoint regexes
_RE_IPV4_WITH_PORT = re.compile(r"^(?:https?://)?([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::(\d{1,5}))?$")
_RE_IPV6_WITH_PORT = re.compile(r"^(?:https?://)?\[([0-9a-fA-F:]+)\](?::(\d{1,5}))?$")

# PII & Secret Detection Regexes
_RE_CREDIT_CARD_CANDIDATE = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b"
)
_RE_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_RE_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
_RE_NVIDIA_API_KEY = re.compile(r"\bnvapi-[a-zA-Z0-9_-]{32,}\b")
_RE_OPENAI_API_KEY = re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,}\b")
_RE_GITHUB_TOKEN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b")
_RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_BEARER_TOKEN = re.compile(r"(?i)\b(?:bearer\s+)([a-zA-Z0-9_\-\.]{24,})\b")
_RE_CREDENTIAL_PARAM = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|client_secret|api_key|apikey|access_token)\s*([:=])\s*([^\s,;\"'}{&]+)"
)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

# Default immutable cleaning configuration
DEFAULT_CLEANING_CONFIG = FieldCleaningConfig()


def clean_text(
    val: str | None,
    strip_ansi: bool = True,
    strip_control_chars: bool = True,
) -> str | None:
    """Purge ANSI escape sequences, null bytes, zero-width spaces, and control characters.

    Args:
        val: Input string to cleanse.
        strip_ansi: Whether to remove ANSI terminal sequences.
        strip_control_chars: Whether to remove null bytes and ASCII control characters.

    Returns:
        Cleaned and stripped string, or None if input was None.
    """
    if val is None:
        return None

    cleaned = val
    if strip_ansi:
        cleaned = _RE_ANSI_ESCAPE.sub("", cleaned)
    if strip_control_chars:
        cleaned = _RE_ZERO_WIDTH.sub("", cleaned)
        cleaned = _RE_CONTROL_CHARS.sub("", cleaned)

    return cleaned.strip()


def is_luhn_valid(candidate: str) -> bool:
    """Validate credit card candidate digits using the standard Luhn Algorithm (Mod 10).

    Args:
        candidate: Numeric string candidate with or without spaces/hyphens.

    Returns:
        True if digits satisfy the Luhn checksum and primary card length/prefix requirements.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Standard prefix check (Visa: 4, Mastercard: 51-55/22-27, Amex: 34/37, Discover: 6011)
    prefix2 = int(f"{digits[0]}{digits[1]}")
    prefix4 = int(f"{digits[0]}{digits[1]}{digits[2]}{digits[3]}") if len(digits) >= 4 else 0
    valid_prefix = (
        digits[0] == 4  # Visa
        or (51 <= prefix2 <= 55) or (2221 <= prefix4 <= 2720)  # Mastercard
        or prefix2 in (34, 37)  # Amex
        or prefix4 == 6011 or (644 <= int(str(prefix4)[:3]) <= 649) or prefix2 == 65  # Discover
        or (300 <= int(str(prefix4)[:3]) <= 305) or prefix2 in (36, 38)  # Diners
        or (3528 <= prefix4 <= 3589)  # JCB
    )
    if not valid_prefix:
        return False

    total = sum(
        (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 1 else d
        for i, d in enumerate(reversed(digits))
    )
    return total % 10 == 0


def clean_ip(raw_ip: str | None, port: int | None = None) -> CleanedIP | None:
    """Normalize and classify an IP address candidate, extracting embedded ports.

    Args:
        raw_ip: Raw IP string, possibly containing URL prefixes or attached ports.
        port: Explicit port passed separately (overrides embedded port if provided).

    Returns:
        CleanedIP model with standardized IP string and RFC classification, or None if invalid.
    """
    if raw_ip is None:
        return None

    cleaned_str = clean_text(raw_ip)
    if not cleaned_str or cleaned_str in ("-", "nil", "null", "none"):
        return None

    extracted_port = port
    ip_candidate = cleaned_str

    # 1. Check for IPv6 bracketed port: e.g. [2001:db8::1]:8443
    ipv6_match = _RE_IPV6_WITH_PORT.match(cleaned_str)
    if ipv6_match:
        ip_candidate = ipv6_match.group(1)
        if extracted_port is None and ipv6_match.group(2):
            extracted_port = int(ipv6_match.group(2))
    else:
        # 2. Check for IPv4 with port: e.g. 192.168.1.1:8080
        ipv4_match = _RE_IPV4_WITH_PORT.match(cleaned_str)
        if ipv4_match:
            ip_candidate = ipv4_match.group(1)
            if extracted_port is None and ipv4_match.group(2):
                extracted_port = int(ipv4_match.group(2))

    # Validate port bounds
    if extracted_port is not None and not (1 <= extracted_port <= 65535):
        extracted_port = None

    # Canonicalize IPv4 leading zeroes before strict validation
    if "." in ip_candidate and ":" not in ip_candidate:
        parts = ip_candidate.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            ip_candidate = ".".join(str(int(p)) for p in parts)

    # Parse and validate IP through Python's standard ipaddress library
    try:
        ip_obj = ipaddress.ip_address(ip_candidate)
    except ValueError:
        return None

    is_ipv6 = ip_obj.version == 6
    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_multicast = ip_obj.is_multicast
    is_public = not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
    )

    return CleanedIP(
        ip=str(ip_obj),
        port=extracted_port,
        is_ipv6=is_ipv6,
        is_private=is_private,
        is_loopback=is_loopback,
        is_multicast=is_multicast,
        is_public=is_public,
    )


def clean_mac(raw_mac: str | None) -> str | None:
    """Format arbitrary MAC address variants into canonical lowercase colon-separated notation.

    Args:
        raw_mac: Candidate MAC string (e.g. '001A.2B3C.4D5E', '00-1A-...', '001A2B3C4D5E').

    Returns:
        Standardized MAC string '00:1a:2b:3c:4d:5e', or None if invalid.
    """
    if raw_mac is None:
        return None

    cleaned = clean_text(raw_mac)
    if not cleaned or cleaned in ("-", "nil", "null", "none"):
        return None

    hex_chars = "".join(re.findall(r"[0-9a-fA-F]", cleaned))
    if len(hex_chars) != 12:
        return None

    lowered = hex_chars.lower()
    return f"{lowered[0:2]}:{lowered[2:4]}:{lowered[4:6]}:{lowered[6:8]}:{lowered[8:10]}:{lowered[10:12]}"


def clean_hostname(raw_host: str | None) -> str | None:
    """Clean and standardize hostnames and FQDNs.

    Args:
        raw_host: Candidate hostname or FQDN string.

    Returns:
        Cleaned lowercase hostname without protocol prefixes or trailing root dots.
    """
    if raw_host is None:
        return None

    cleaned = clean_text(raw_host)
    if not cleaned or cleaned in ("-", "nil", "null", "none"):
        return None

    # Strip protocol prefix if mistakenly attached
    host = re.sub(r"^(?:https?|ftp|tcp|udp)://", "", cleaned, flags=re.IGNORECASE)
    # Strip path or query if included
    host = host.split("/")[0].split("?")[0]
    # Strip port if present on hostname (e.g. webserver:8080)
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]

    # Strip trailing FQDN root dot: e.g. 'api.corp.internal.' -> 'api.corp.internal'
    host = host.rstrip(".").lower()
    return host if host else None


def scrub_pii(
    text: str,
    mask_types: set[SanitizationMaskType] | None = None,
) -> tuple[str, Counter[str]]:
    """Scrub sensitive compliance PII and secret tokens from a text string.

    Args:
        text: Input string to scan and redact.
        mask_types: Active set of secret categories to mask (defaults to all standard categories).

    Returns:
        Tuple of (sanitized_text, Counter of redaction counts by category).
    """
    if not text:
        return text, Counter()

    active_masks = mask_types if mask_types is not None else DEFAULT_CLEANING_CONFIG.mask_types
    redactions: Counter[str] = Counter()
    current_text = text

    # 1. Bearer Tokens & API Keys
    if SanitizationMaskType.API_KEY in active_masks:
        def _replace_nvidia_key(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.API_KEY.value] += 1
            return "[REDACTED_API_KEY]"

        current_text = _RE_NVIDIA_API_KEY.sub(_replace_nvidia_key, current_text)

        def _replace_openai_key(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.API_KEY.value] += 1
            return "[REDACTED_API_KEY]"

        current_text = _RE_OPENAI_API_KEY.sub(_replace_openai_key, current_text)

        def _replace_github_token(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.API_KEY.value] += 1
            return "[REDACTED_API_KEY]"

        current_text = _RE_GITHUB_TOKEN.sub(_replace_github_token, current_text)

        def _replace_aws_key(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.API_KEY.value] += 1
            return "[REDACTED_API_KEY]"

        current_text = _RE_AWS_KEY.sub(_replace_aws_key, current_text)

        def _replace_bearer_token(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.API_KEY.value] += 1
            return "Bearer [REDACTED_API_KEY]"

        current_text = _RE_BEARER_TOKEN.sub(_replace_bearer_token, current_text)

    # 2. JSON Web Tokens (JWT)
    if SanitizationMaskType.JWT in active_masks:
        def _replace_jwt(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.JWT.value] += 1
            return "[REDACTED_JWT]"

        current_text = _RE_JWT.sub(_replace_jwt, current_text)

    # 3. Credit Cards (with strict Luhn algorithm validation)
    if SanitizationMaskType.CREDIT_CARD in active_masks:
        def _replace_cc(m: re.Match[str]) -> str:
            val = m.group(0)
            if is_luhn_valid(val):
                redactions[SanitizationMaskType.CREDIT_CARD.value] += 1
                return "[REDACTED_CREDIT_CARD]"
            return val

        current_text = _RE_CREDIT_CARD_CANDIDATE.sub(_replace_cc, current_text)

    # 4. Social Security Numbers (SSN)
    if SanitizationMaskType.SSN in active_masks:
        def _replace_ssn(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.SSN.value] += 1
            return "[REDACTED_SSN]"

        current_text = _RE_SSN.sub(_replace_ssn, current_text)

    # 5. Password & Secret Key-Value parameters
    if SanitizationMaskType.PASSWORD in active_masks:
        def _replace_cred_param(m: re.Match[str]) -> str:
            key_name, sep = m.group(1), m.group(2)
            redactions[SanitizationMaskType.PASSWORD.value] += 1
            return f"{key_name}{sep}[REDACTED]"

        current_text = _RE_CREDENTIAL_PARAM.sub(_replace_cred_param, current_text)

    # 6. Emails (optional)
    if SanitizationMaskType.EMAIL in active_masks:
        def _replace_email(m: re.Match[str]) -> str:
            redactions[SanitizationMaskType.EMAIL.value] += 1
            return "[REDACTED_EMAIL]"

        current_text = _RE_EMAIL.sub(_replace_email, current_text)

    return current_text, redactions


def clean_attributes(
    attrs: dict[str, Any],
    config: FieldCleaningConfig | None = None,
) -> tuple[dict[str, Any], SanitizationReport]:
    """Recursively clean nested attributes dictionaries, stripping artifacts and scrubbing PII.

    Args:
        attrs: Raw attributes dictionary extracted during parsing.
        config: Active field cleaning and sanitization configuration.

    Returns:
        Tuple of (cleansed attributes dictionary, SanitizationReport telemetry).
    """
    cfg = config or DEFAULT_CLEANING_CONFIG
    redactions: Counter[str] = Counter()
    cleaned_fields = 0

    def _clean_val(val: Any) -> Any:
        nonlocal cleaned_fields
        if isinstance(val, str):
            # 1. Strip ANSI and control chars
            t = clean_text(val, strip_ansi=cfg.strip_ansi, strip_control_chars=cfg.strip_control_chars) or ""
            if t != val:
                cleaned_fields += 1
            # 2. Mask PII if enabled
            if cfg.mask_pii:
                t, red = scrub_pii(t, mask_types=cfg.mask_types)
                redactions.update(red)
            return t
        elif isinstance(val, dict):
            return {
                clean_text(str(k), strip_ansi=cfg.strip_ansi, strip_control_chars=cfg.strip_control_chars) or str(k): _clean_val(v)
                for k, v in val.items()
            }
        elif isinstance(val, list):
            return [_clean_val(item) for item in val]
        return val

    cleaned_dict = {
        clean_text(str(k), strip_ansi=cfg.strip_ansi, strip_control_chars=cfg.strip_control_chars) or str(k): _clean_val(v)
        for k, v in attrs.items()
    }

    report = SanitizationReport(
        redacted_counts=dict(redactions),
        total_redactions=sum(redactions.values()),
        cleaned_fields_count=cleaned_fields,
    )
    return cleaned_dict, report


def clean_source_info(
    source: SourceInfo | None,
    config: FieldCleaningConfig | None = None,
) -> tuple[SourceInfo | None, CleanedIP | None]:
    """Clean and validate endpoint telemetry for an event source origin."""
    if source is None:
        return None, None

    cfg = config or DEFAULT_CLEANING_CONFIG
    cleaned_ip_meta = clean_ip(source.ip, port=source.port) if cfg.normalize_ips else None
    ip_val = cleaned_ip_meta.ip if cleaned_ip_meta else clean_text(source.ip, cfg.strip_ansi, cfg.strip_control_chars)
    port_val = cleaned_ip_meta.port if cleaned_ip_meta else source.port
    host_val = clean_hostname(source.hostname) if cfg.normalize_hostnames else source.hostname
    mac_val = clean_mac(source.mac) if cfg.normalize_macs else source.mac

    cleaned_source = SourceInfo(
        ip=ip_val,
        hostname=host_val,
        port=port_val,
        mac=mac_val,
    )
    return cleaned_source, cleaned_ip_meta


def clean_destination_info(
    dest: DestinationInfo | None,
    config: FieldCleaningConfig | None = None,
) -> tuple[DestinationInfo | None, CleanedIP | None]:
    """Clean and validate endpoint telemetry for an event target destination."""
    if dest is None:
        return None, None

    cfg = config or DEFAULT_CLEANING_CONFIG
    cleaned_ip_meta = clean_ip(dest.ip, port=dest.port) if cfg.normalize_ips else None
    ip_val = cleaned_ip_meta.ip if cleaned_ip_meta else clean_text(dest.ip, cfg.strip_ansi, cfg.strip_control_chars)
    port_val = cleaned_ip_meta.port if cleaned_ip_meta else dest.port
    host_val = clean_hostname(dest.hostname) if cfg.normalize_hostnames else dest.hostname
    mac_val = clean_mac(dest.mac) if cfg.normalize_macs else dest.mac

    cleaned_dest = DestinationInfo(
        ip=ip_val,
        hostname=host_val,
        port=port_val,
        mac=mac_val,
    )
    return cleaned_dest, cleaned_ip_meta


def clean_security_context(
    sec: SecurityContext | None,
    config: FieldCleaningConfig | None = None,
) -> tuple[SecurityContext | None, Counter[str]]:
    """Clean identity and security context, scrubbing credential leaks."""
    if sec is None:
        return None, Counter()

    cfg = config or DEFAULT_CLEANING_CONFIG
    redactions: Counter[str] = Counter()

    user_val = clean_text(sec.user, cfg.strip_ansi, cfg.strip_control_chars)
    if user_val and cfg.mask_pii:
        user_val, red = scrub_pii(user_val, cfg.mask_types)
        redactions.update(red)

    proc_val = clean_text(sec.process_name, cfg.strip_ansi, cfg.strip_control_chars)

    cleaned_sec = SecurityContext(
        user=user_val,
        process_name=proc_val,
        process_id=sec.process_id,
        threat_id=clean_text(sec.threat_id, cfg.strip_ansi, cfg.strip_control_chars),
        mitre_technique=clean_text(sec.mitre_technique, cfg.strip_ansi, cfg.strip_control_chars),
    )
    return cleaned_sec, redactions


def sanitize_parsed_result(
    result: ParsedResult,
    config: FieldCleaningConfig | None = None,
) -> tuple[ParsedResult, SanitizationReport]:
    """Clean and sanitize all telemetry, security context, and attributes in a ParsedResult.

    Args:
        result: Raw ParsedResult returned from the cascade orchestrator.
        config: Optional configuration override.

    Returns:
        Tuple of (clean ParsedResult, SanitizationReport audit telemetry).
    """
    cfg = config or DEFAULT_CLEANING_CONFIG
    cleaned_source, src_ip_meta = clean_source_info(result.source, cfg)
    cleaned_dest, dst_ip_meta = clean_destination_info(result.destination, cfg)
    cleaned_sec, sec_redactions = clean_security_context(result.security, cfg)
    cleaned_attrs, report = clean_attributes(result.attributes, cfg)

    # Merge security context redactions into report
    merged_counts = dict(report.redacted_counts)
    for k, v in sec_redactions.items():
        merged_counts[k] = merged_counts.get(k, 0) + v

    total_redactions = sum(merged_counts.values())

    # Attach network classification telemetry to attributes if available
    if src_ip_meta:
        cleaned_attrs["source_is_private"] = src_ip_meta.is_private
        cleaned_attrs["source_is_public"] = src_ip_meta.is_public
    if dst_ip_meta:
        cleaned_attrs["destination_is_private"] = dst_ip_meta.is_private
        cleaned_attrs["destination_is_public"] = dst_ip_meta.is_public

    cleaned_action = clean_text(result.action, cfg.strip_ansi, cfg.strip_control_chars)
    if cleaned_action:
        cleaned_action = cleaned_action.upper()

    final_report = SanitizationReport(
        redacted_counts=merged_counts,
        total_redactions=total_redactions,
        cleaned_fields_count=report.cleaned_fields_count,
    )

    cleaned_result = ParsedResult(
        success=result.success,
        format=result.format,
        parsed_by=result.parsed_by,
        confidence=result.confidence,
        raw_timestamp=result.raw_timestamp,
        severity=result.severity,
        action=cleaned_action,
        source=cleaned_source,
        destination=cleaned_dest,
        security=cleaned_sec,
        attributes=cleaned_attrs,
        error_message=clean_text(result.error_message, cfg.strip_ansi, cfg.strip_control_chars),
    )

    return cleaned_result, final_report
