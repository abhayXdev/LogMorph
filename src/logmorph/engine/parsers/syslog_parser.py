"""Deterministic parser for Syslog RFC 5424 and RFC 3164 formats."""

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

# RFC 5424 severity code mapping (0 to 7)
_RFC_SEVERITY_TABLE: list[SeverityEnum] = [
    SeverityEnum.EMERGENCY,  # 0
    SeverityEnum.ALERT,  # 1
    SeverityEnum.CRITICAL,  # 2
    SeverityEnum.ERROR,  # 3
    SeverityEnum.WARNING,  # 4
    SeverityEnum.NOTICE,  # 5
    SeverityEnum.INFORMATIONAL,  # 6
    SeverityEnum.DEBUG,  # 7
]

# RFC 5424 regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [REMAINDER]
_RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)"
    r"(?:\s+(?P<remainder>.*))?$"
)

# RFC 3164 regex: [<PRI>] TIMESTAMP HOSTNAME TAG[PID]: MSG
_MONTHS = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_RE_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>\s*)?"
    r"(?P<timestamp>" + _MONTHS + r"\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>[^:\s\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

# Helper regex to discover IPs and ports inside syslog free text
_RE_SRC_IP = re.compile(r"(?:from|SRC=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_RE_DST_IP = re.compile(r"DST=\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_RE_SRC_PORT = re.compile(r"(?:port|SPT=)\s*(\d{1,5})")
_RE_DST_PORT = re.compile(r"DPT=\s*(\d{1,5})")
_RE_STRUCTURED_DATA = re.compile(r"\[([^\s\]]+)(?:\s+([^\]]*))?\]")
_RE_SD_PARAMS = re.compile(r'(\S+)="([^"]*)"')


class SyslogParser(BaseParser):
    """High-speed parser supporting both IETF RFC 5424 and BSD RFC 3164 Syslog messages."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.SYSLOG,
                error_message="Empty raw log payload",
            )

        stripped = raw_log.strip()

        # Attempt RFC 5424 first
        m_5424 = _RE_RFC5424.match(stripped)
        if m_5424:
            return self._parse_rfc5424(m_5424, stripped)

        # Attempt RFC 3164
        m_3164 = _RE_RFC3164.match(stripped)
        if m_3164:
            return self._parse_rfc3164(m_3164, stripped)

        return ParsedResult(
            success=False,
            format=LogFormatEnum.SYSLOG,
            error_message="Log line does not match RFC 5424 or RFC 3164 syslog grammar",
        )

    def _parse_rfc5424(self, match: re.Match[str], raw_log: str) -> ParsedResult:
        pri = int(match.group("pri"))
        severity = _RFC_SEVERITY_TABLE[pri % 8] if 0 <= pri <= 191 else SeverityEnum.INFORMATIONAL
        facility = pri // 8 if 0 <= pri <= 191 else None

        raw_ts = match.group("timestamp")
        hostname = match.group("hostname")
        src_host = hostname if hostname != "-" else None

        app_name = match.group("app_name")
        process_name = app_name if app_name != "-" else None

        procid_str = match.group("procid")
        process_id: int | None = None
        if procid_str != "-" and procid_str.isdigit():
            process_id = int(procid_str)

        msgid = match.group("msgid")
        remainder = match.group("remainder") or ""

        # Parse structured data and message body
        structured_data: dict[str, dict[str, str]] = {}
        message_body = remainder

        if remainder.startswith("["):
            # Extract structured data elements
            sd_matches = list(_RE_STRUCTURED_DATA.finditer(remainder))
            if sd_matches:
                last_end = 0
                for sdm in sd_matches:
                    sd_id = sdm.group(1)
                    sd_params_str = sdm.group(2) or ""
                    params = dict(_RE_SD_PARAMS.findall(sd_params_str))
                    structured_data[sd_id] = params
                    last_end = sdm.end()

                message_body = remainder[last_end:].strip()
                # Strip leading BOM marker if present in message body
                if message_body.startswith("BOM"):
                    message_body = message_body[3:]
        elif remainder.startswith("-"):
            message_body = remainder[1:].strip()

        # Discover IPs inside message body if available
        src_ip = None
        m_src = _RE_SRC_IP.search(message_body)
        if m_src:
            src_ip = m_src.group(1)

        source = (
            SourceInfo(ip=src_ip, hostname=src_host)
            if (src_ip or src_host)
            else None
        )

        security = (
            SecurityContext(process_name=process_name, process_id=process_id)
            if (process_name or process_id)
            else None
        )

        attributes: dict[str, Any] = {
            "rfc": "RFC_5424",
            "facility": facility,
            "version": int(match.group("version")),
            "msgid": msgid if msgid != "-" else None,
            "message": message_body,
        }
        if structured_data:
            attributes["structured_data"] = structured_data

        return ParsedResult(
            success=True,
            format=LogFormatEnum.SYSLOG,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            action=msgid if msgid != "-" else None,
            source=source,
            security=security,
            attributes=attributes,
        )

    def _parse_rfc3164(self, match: re.Match[str], raw_log: str) -> ParsedResult:
        pri_str = match.group("pri")
        if pri_str:
            pri = int(pri_str)
            severity = _RFC_SEVERITY_TABLE[pri % 8] if 0 <= pri <= 191 else SeverityEnum.INFORMATIONAL
            facility = pri // 8 if 0 <= pri <= 191 else None
        else:
            severity = SeverityEnum.INFORMATIONAL
            facility = None

        raw_ts = match.group("timestamp")
        hostname = match.group("hostname")
        tag = match.group("tag")

        pid_str = match.group("pid")
        process_id = int(pid_str) if pid_str and pid_str.isdigit() else None
        msg = match.group("msg") or ""

        # Extract IPs from message
        src_ip = None
        m_src = _RE_SRC_IP.search(msg)
        if m_src:
            src_ip = m_src.group(1)

        dst_ip = None
        m_dst = _RE_DST_IP.search(msg)
        if m_dst:
            dst_ip = m_dst.group(1)

        src_port = None
        m_spt = _RE_SRC_PORT.search(msg)
        if m_spt:
            src_port = int(m_spt.group(1))

        dst_port = None
        m_dpt = _RE_DST_PORT.search(msg)
        if m_dpt:
            dst_port = int(m_dpt.group(1))

        source = (
            SourceInfo(ip=src_ip, hostname=hostname, port=src_port)
            if (src_ip or hostname or src_port)
            else None
        )

        destination = (
            DestinationInfo(ip=dst_ip, port=dst_port)
            if (dst_ip or dst_port)
            else None
        )

        security = SecurityContext(
            process_name=tag,
            process_id=process_id,
        )

        attributes: dict[str, Any] = {
            "rfc": "RFC_3164",
            "facility": facility,
            "tag": tag,
            "message": msg,
        }

        return ParsedResult(
            success=True,
            format=LogFormatEnum.SYSLOG,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            source=source,
            destination=destination,
            security=security,
            attributes=attributes,
        )
