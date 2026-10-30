"""High-speed deterministic JSON log parser."""

import json
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

# Common severity level aliases
_SEVERITY_MAP: dict[str, SeverityEnum] = {
    "emergency": SeverityEnum.EMERGENCY,
    "emerg": SeverityEnum.EMERGENCY,
    "alert": SeverityEnum.ALERT,
    "critical": SeverityEnum.CRITICAL,
    "crit": SeverityEnum.CRITICAL,
    "error": SeverityEnum.ERROR,
    "err": SeverityEnum.ERROR,
    "warning": SeverityEnum.WARNING,
    "warn": SeverityEnum.WARNING,
    "notice": SeverityEnum.NOTICE,
    "informational": SeverityEnum.INFORMATIONAL,
    "info": SeverityEnum.INFORMATIONAL,
    "debug": SeverityEnum.DEBUG,
}

_TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "eventTime", "datetime", "date")
_SEVERITY_KEYS = ("level", "severity", "log_level", "status")
_SRC_IP_KEYS = ("sourceIPAddress", "client_ip", "remote_addr", "src_ip", "src")
_DST_IP_KEYS = ("dst_ip", "dest_ip", "destination_ip", "dst", "server_ip")
_USER_KEYS = ("user", "username", "remote_user", "principalId")
_ACTION_KEYS = ("action", "eventName", "event", "method")


class JsonLogParser(BaseParser):
    """Fast-path parser for structured JSON logs."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.JSON,
                error_message="Empty raw log payload",
            )

        try:
            data = json.loads(raw_log.strip())
        except (json.JSONDecodeError, ValueError) as e:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.JSON,
                error_message=f"JSON decoding error: {e}",
            )

        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                data = data[0]
            else:
                return ParsedResult(
                    success=False,
                    format=LogFormatEnum.JSON,
                    error_message="JSON array does not contain valid event object",
                )

        if not isinstance(data, dict):
            return ParsedResult(
                success=False,
                format=LogFormatEnum.JSON,
                error_message="Parsed JSON payload is not a dictionary object",
            )

        # 1. Timestamp extraction
        raw_ts: str | None = None
        for k in _TIMESTAMP_KEYS:
            if k in data and data[k]:
                raw_ts = str(data[k])
                break

        # 2. Severity extraction
        sev = SeverityEnum.INFORMATIONAL
        for k in _SEVERITY_KEYS:
            if k in data and data[k] is not None:
                val = str(data[k]).strip().lower()
                if val in _SEVERITY_MAP:
                    sev = _SEVERITY_MAP[val]
                    break

        # 3. Source extraction
        src_ip: str | None = None
        for k in _SRC_IP_KEYS:
            if k in data and data[k]:
                src_ip = str(data[k])
                break
        src_host = str(data["host"]) if "host" in data and data["host"] else None
        if not src_host and "hostname" in data and data["hostname"]:
            src_host = str(data["hostname"])

        src_port: int | None = None
        if "src_port" in data:
            try:
                src_port = int(data["src_port"])
            except (ValueError, TypeError):
                pass

        source = (
            SourceInfo(ip=src_ip, hostname=src_host, port=src_port)
            if (src_ip or src_host or src_port)
            else None
        )

        # 4. Destination extraction
        dst_ip: str | None = None
        for k in _DST_IP_KEYS:
            if k in data and data[k]:
                dst_ip = str(data[k])
                break
        dst_port: int | None = None
        if "dst_port" in data:
            try:
                dst_port = int(data["dst_port"])
            except (ValueError, TypeError):
                pass
        dst_host = str(data["dst_host"]) if "dst_host" in data and data["dst_host"] else None

        destination = (
            DestinationInfo(ip=dst_ip, hostname=dst_host, port=dst_port)
            if (dst_ip or dst_host or dst_port)
            else None
        )

        # 5. Security & User extraction
        user: str | None = None
        for k in _USER_KEYS:
            if k in data and data[k]:
                user = str(data[k])
                break

        # Check nested AWS userIdentity
        if not user and isinstance(data.get("userIdentity"), dict):
            ident = data["userIdentity"]
            user = ident.get("principalId") or ident.get("userName") or ident.get("arn")

        process_name = str(data.get("service") or data.get("process") or "") or None
        process_id: int | None = None
        if "pid" in data:
            try:
                process_id = int(data["pid"])
            except (ValueError, TypeError):
                pass

        security = (
            SecurityContext(user=user, process_name=process_name, process_id=process_id)
            if (user or process_name or process_id)
            else None
        )

        # 6. Action extraction
        action: str | None = None
        for k in _ACTION_KEYS:
            if k in data and data[k]:
                action = str(data[k])
                break

        # 7. Attributes (preserve all data)
        attributes: dict[str, Any] = dict(data)

        return ParsedResult(
            success=True,
            format=LogFormatEnum.JSON,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=sev,
            action=action,
            source=source,
            destination=destination,
            security=security,
            attributes=attributes,
        )
