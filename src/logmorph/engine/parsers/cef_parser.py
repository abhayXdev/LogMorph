"""Deterministic parser for ArcSight Common Event Format (CEF) logs."""

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

# Regex matching CEF header with optional syslog wrapper prefix
_RE_CEF_HEADER = re.compile(
    r"^(?:(?P<syslog_prefix>.*?)\s+)?"
    r"CEF:(?P<cef_version>\d+)\|"
    r"(?P<vendor>(?:\\\||[^|])*)\|"
    r"(?P<product>(?:\\\||[^|])*)\|"
    r"(?P<version>(?:\\\||[^|])*)\|"
    r"(?P<signature_id>(?:\\\||[^|])*)\|"
    r"(?P<name>(?:\\\||[^|])*)\|"
    r"(?P<severity>(?:\\\||[^|])*)\|"
    r"(?P<extension>.*)$"
)

# Regex capturing key=value extensions respecting quotes and escaped characters
_RE_CEF_EXT = re.compile(
    r'(?P<key>[a-zA-Z0-9_]+)=(?P<val>"(?:\\.|[^"\\])*"|(?:(?![a-zA-Z0-9_]+=)\S)+)'
)


def _unescape_cef_str(val: str) -> str:
    """Unescape escaped CEF characters like \\= -> = and \\| -> | and \\\\ -> \\."""
    return val.replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\")


class CefParser(BaseParser):
    """High-speed parser for ArcSight CEF formatted events."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.CEF,
                error_message="Empty raw log payload",
            )

        match = _RE_CEF_HEADER.match(raw_log.strip())
        if not match:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.CEF,
                error_message="Log line does not match ArcSight CEF header grammar",
            )

        vendor = _unescape_cef_str(match.group("vendor"))
        product = _unescape_cef_str(match.group("product"))
        version = _unescape_cef_str(match.group("version"))
        signature_id = _unescape_cef_str(match.group("signature_id"))
        name = _unescape_cef_str(match.group("name"))
        sev_raw = _unescape_cef_str(match.group("severity")).strip()
        extension_str = match.group("extension")
        syslog_prefix = match.group("syslog_prefix")

        # Map CEF severity (0-10 or text) to RFC 5424 SeverityEnum
        severity = SeverityEnum.INFORMATIONAL
        if sev_raw.isdigit():
            score = int(sev_raw)
            if score >= 9:
                severity = SeverityEnum.CRITICAL
            elif score >= 7:
                severity = SeverityEnum.ERROR
            elif score >= 4:
                severity = SeverityEnum.WARNING
            elif score >= 1:
                severity = SeverityEnum.NOTICE
            else:
                severity = SeverityEnum.INFORMATIONAL
        else:
            sev_lower = sev_raw.lower()
            if sev_lower in ("critical", "very-high", "high"):
                severity = SeverityEnum.CRITICAL
            elif sev_lower in ("medium", "warn", "warning"):
                severity = SeverityEnum.WARNING
            elif sev_lower in ("low", "info", "notice"):
                severity = SeverityEnum.NOTICE

        # Parse key-value extensions
        extensions: dict[str, str] = {}
        for ext_match in _RE_CEF_EXT.finditer(extension_str):
            k = ext_match.group("key")
            v = ext_match.group("val")
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            extensions[k] = _unescape_cef_str(v)

        # 1. Source telemetry
        src_ip = extensions.get("src")
        src_port_str = extensions.get("spt")
        src_port = int(src_port_str) if src_port_str and src_port_str.isdigit() else None
        src_host = extensions.get("shost")
        src_mac = extensions.get("smac")

        source = (
            SourceInfo(ip=src_ip, hostname=src_host, port=src_port, mac=src_mac)
            if (src_ip or src_host or src_port or src_mac)
            else None
        )

        # 2. Destination telemetry
        dst_ip = extensions.get("dst")
        dst_port_str = extensions.get("dpt")
        dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else None
        dst_host = extensions.get("dhost")
        dst_mac = extensions.get("dmac")

        destination = (
            DestinationInfo(ip=dst_ip, hostname=dst_host, port=dst_port, mac=dst_mac)
            if (dst_ip or dst_host or dst_port or dst_mac)
            else None
        )

        # 3. Security context
        user = extensions.get("suser") or extensions.get("duser") or extensions.get("usr")
        process_name = extensions.get("app") or extensions.get("sproc")
        process_id_str = extensions.get("spid")
        process_id = int(process_id_str) if process_id_str and process_id_str.isdigit() else None

        security = (
            SecurityContext(
                user=user,
                process_name=process_name,
                process_id=process_id,
                threat_id=signature_id or None,
            )
            if (user or process_name or process_id or signature_id)
            else None
        )

        # 4. Action
        action = extensions.get("act") or name

        # 5. Candidate raw timestamp
        raw_ts = (
            extensions.get("rt")
            or extensions.get("end")
            or extensions.get("start")
            or (syslog_prefix.split()[1] if syslog_prefix and len(syslog_prefix.split()) > 1 else None)
        )

        # Attributes preserved
        attributes: dict[str, Any] = {
            "device_vendor": vendor,
            "device_product": product,
            "device_version": version,
            "device_event_class_id": signature_id,
            "event_name": name,
            "cef_version": int(match.group("cef_version")),
            **extensions,
        }

        return ParsedResult(
            success=True,
            format=LogFormatEnum.CEF,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            action=action,
            source=source,
            destination=destination,
            security=security,
            attributes=attributes,
        )
