"""Deterministic parser for IBM Security QRadar LEEF (Log Event Extended Format) events."""

import re
from typing import Any

from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import BaseParser, ParsedResult

# Regex matching start of LEEF header with optional leading syslog wrapper
_RE_LEEF_START = re.compile(r"LEEF:(?P<version>\d+(?:\.\d+)?)\|")


class LeefParser(BaseParser):
    """High-speed parser for IBM QRadar LEEF 1.0 and 2.0 formatted events."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.LEEF,
                error_message="Empty raw log payload",
            )

        stripped = raw_log.strip()
        start_match = _RE_LEEF_START.search(stripped)
        if not start_match:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.LEEF,
                error_message="Log line does not contain valid LEEF header",
            )

        syslog_prefix = stripped[: start_match.start()].strip() or None
        leef_body = stripped[start_match.start() :]

        # Split pipe fields
        parts = leef_body.split("|")
        if len(parts) < 6:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.LEEF,
                error_message=f"Insufficient pipe-delimited fields in LEEF header ({len(parts)} < 6)",
            )

        leef_version = parts[0].replace("LEEF:", "")
        vendor = parts[1]
        product = parts[2]
        version = parts[3]
        event_id = parts[4]

        # Determine delimiter and extension payload
        # LEEF 2.0 may define delimiter in parts[5] if parts has >= 7 fields, or inline in parts[5]
        delimiter = "\t"
        extension_str = ""

        if len(parts) >= 7 and len(parts[5]) <= 4 and "=" not in parts[5]:
            delim_field = parts[5]
            if delim_field.startswith("0x") or delim_field.startswith("x"):
                try:
                    delimiter = chr(int(delim_field.replace("0x", "").replace("x", ""), 16))
                except ValueError:
                    delimiter = delim_field
            elif delim_field:
                delimiter = delim_field
            extension_str = "|".join(parts[6:])
        else:
            remainder = "|".join(parts[5:])
            if remainder.startswith("^"):
                delimiter = "^"
                remainder = remainder[1:]
            elif remainder.startswith("\t"):
                delimiter = "\t"
                remainder = remainder[1:]
            extension_str = remainder

        # Parse key-value attributes
        attributes: dict[str, Any] = {
            "leef_version": leef_version,
            "vendor": vendor,
            "product": product,
            "product_version": version,
            "event_id": event_id,
        }

        raw_pairs = extension_str.split(delimiter)
        for pair in raw_pairs:
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            k = k.strip()
            v = v.strip()
            if k:
                attributes[k] = v

        # Extract ULS entities
        src_ip = attributes.get("src")
        src_port_str = attributes.get("spt")
        src_port = int(src_port_str) if src_port_str and src_port_str.isdigit() else None
        src_host = attributes.get("shost") or attributes.get("identSrc")

        source = (
            SourceInfo(ip=src_ip, hostname=src_host, port=src_port)
            if (src_ip or src_host or src_port)
            else None
        )

        dst_ip = attributes.get("dst")
        dst_port_str = attributes.get("dpt")
        dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else None
        dst_host = attributes.get("dhost") or attributes.get("identHostName")

        destination = (
            DestinationInfo(ip=dst_ip, hostname=dst_host, port=dst_port)
            if (dst_ip or dst_host or dst_port)
            else None
        )

        user = attributes.get("usr") or attributes.get("accountName")
        security = (
            SecurityContext(user=user, threat_id=event_id or None)
            if (user or event_id)
            else None
        )

        # Severity
        sev_str = attributes.get("sev")
        severity = SeverityEnum.INFORMATIONAL
        if sev_str and sev_str.isdigit():
            score = int(sev_str)
            if score >= 8:
                severity = SeverityEnum.CRITICAL
            elif score >= 5:
                severity = SeverityEnum.WARNING
            elif score >= 3:
                severity = SeverityEnum.NOTICE
            else:
                severity = SeverityEnum.INFORMATIONAL

        action = attributes.get("cat") or event_id
        raw_ts = attributes.get("devTime")

        return ParsedResult(
            success=True,
            format=LogFormatEnum.LEEF,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            action=action,
            source=source,
            destination=destination,
            security=security,
            attributes=attributes,
        )
