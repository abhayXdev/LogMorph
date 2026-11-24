"""Deterministic parser for structured XML logs and Windows Event Viewer logs."""

import xml.etree.ElementTree as ET
from typing import Any

from logmorph.domain.uls import (
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import BaseParser, ParsedResult

# Windows Event Level to Severity mapping
_WIN_EVENT_LEVEL_MAP: dict[str, SeverityEnum] = {
    "1": SeverityEnum.CRITICAL,  # Critical
    "2": SeverityEnum.ERROR,  # Error
    "3": SeverityEnum.WARNING,  # Warning
    "4": SeverityEnum.INFORMATIONAL,  # Information
    "0": SeverityEnum.INFORMATIONAL,  # LogAlways / Audit Success
}


def _clean_tag(elem_tag: str) -> str:
    """Strip XML namespace prefix from tag if present."""
    if "}" in elem_tag:
        return elem_tag.split("}", 1)[1]
    return elem_tag


class XmlLogParser(BaseParser):
    """Secure parser for XML log events including Windows Security Auditing schemas."""

    def parse(self, raw_log: str) -> ParsedResult:
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.XML,
                error_message="Empty raw log payload",
            )

        stripped = raw_log.strip()
        try:
            root = ET.fromstring(stripped)
        except (ET.ParseError, ValueError) as e:
            return ParsedResult(
                success=False,
                format=LogFormatEnum.XML,
                error_message=f"XML parsing syntax error: {e}",
            )

        root_tag = _clean_tag(root.tag)
        attributes: dict[str, Any] = {"root_tag": root_tag, **root.attrib}

        raw_ts: str | None = None
        severity = SeverityEnum.INFORMATIONAL
        source_host: str | None = None
        user: str | None = None
        action: str | None = root.attrib.get("type") or root_tag

        # Detect Windows Event Viewer structure (<Event> with <System> and <EventData>)
        if root_tag.lower() == "event":
            for child in root:
                child_tag = _clean_tag(child.tag)
                if child_tag == "System":
                    for sys_elem in child:
                        stag = _clean_tag(sys_elem.tag)
                        if stag == "EventID":
                            action = sys_elem.text
                            attributes["event_id"] = sys_elem.text
                        elif stag == "TimeCreated":
                            raw_ts = sys_elem.attrib.get("SystemTime")
                        elif stag == "Computer":
                            source_host = sys_elem.text
                        elif stag == "Level":
                            lvl = (sys_elem.text or "").strip()
                            if lvl in _WIN_EVENT_LEVEL_MAP:
                                severity = _WIN_EVENT_LEVEL_MAP[lvl]
                elif child_tag == "EventData":
                    event_data: dict[str, str] = {}
                    for data_elem in child:
                        dname = data_elem.attrib.get("Name")
                        if dname:
                            event_data[dname] = data_elem.text or ""
                            if dname == "TargetUserName":
                                user = data_elem.text
                    attributes["event_data"] = event_data
        else:
            # Generic XML event extraction
            for elem in root:
                etag = _clean_tag(elem.tag).lower()
                text = (elem.text or "").strip()
                if etag in ("severity", "level"):
                    sval = text.lower()
                    if "crit" in sval:
                        severity = SeverityEnum.CRITICAL
                    elif "err" in sval:
                        severity = SeverityEnum.ERROR
                    elif "warn" in sval:
                        severity = SeverityEnum.WARNING
                    elif "info" in sval:
                        severity = SeverityEnum.INFORMATIONAL
                elif etag in ("time", "timestamp", "datetime"):
                    raw_ts = text
                elif etag in ("user", "username"):
                    user = text
                elif etag in ("host", "hostname", "computer"):
                    source_host = text
                elif etag in ("action", "event"):
                    action = text

                attributes[etag] = text or elem.attrib

        source = SourceInfo(hostname=source_host) if source_host else None
        security = SecurityContext(user=user) if user else None

        return ParsedResult(
            success=True,
            format=LogFormatEnum.XML,
            parsed_by=ParsingTierEnum.RULE,
            raw_timestamp=raw_ts,
            severity=severity,
            action=action,
            source=source,
            security=security,
            attributes=attributes,
        )
