"""Deterministic parser for Apache / Nginx Common and Combined log formats."""

import re
from typing import Any

from logmorph.domain.uls import (
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import BaseParser, ParsedResult

# Regex matching Apache Common Log Format (CLF) and Combined Log Format
_RE_CLF = re.compile(
    r"^(?P<remote_host>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<remote_user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


class ClfParser(BaseParser):
    """High-speed parser for Apache / Nginx Common and Combined HTTP access logs."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.CLF,
                error_message="Empty raw log payload",
            )

        match = _RE_CLF.match(raw_log.strip())
        if not match:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.CLF,
                error_message="Log line does not match Apache Common or Combined grammar",
            )

        groups = match.groupdict()

        remote_host = groups["remote_host"]
        remote_user = groups["remote_user"]
        raw_ts = groups["timestamp"]
        method = groups["method"]
        path = groups["path"]
        protocol = groups["protocol"]
        status_code = int(groups["status"])
        bytes_str = groups["bytes"]
        bytes_sent = int(bytes_str) if bytes_str.isdigit() else 0
        referer = groups.get("referer")
        user_agent = groups.get("user_agent")

        # Map HTTP status code to RFC 5424 severity level
        if status_code >= 500:
            severity = SeverityEnum.ERROR
        elif status_code >= 400:
            severity = SeverityEnum.WARNING
        else:
            severity = SeverityEnum.INFORMATIONAL

        # Endpoint telemetry
        source = SourceInfo(ip=remote_host)

        # Security context (authenticated remote user)
        security = (
            SecurityContext(user=remote_user)
            if remote_user != "-"
            else None
        )

        is_combined = referer is not None or user_agent is not None
        attributes: dict[str, Any] = {
            "format_type": "COMBINED" if is_combined else "COMMON",
            "ident": groups["ident"] if groups["ident"] != "-" else None,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status_code": status_code,
            "bytes_sent": bytes_sent,
        }
        if referer is not None:
            attributes["referer"] = referer
        if user_agent is not None:
            attributes["user_agent"] = user_agent

        return ParsedResult(
            success=True,
            format=LogFormatEnum.CLF,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            action=method,
            source=source,
            security=security,
            attributes=attributes,
        )
