"""Format Detection Engine — classifies raw log strings into LogFormatEnum."""

import json
import re

from logmorph.domain.uls import LogFormatEnum
from logmorph.schemas.detection import DetectionResult

# ---------- Compiled Regex Patterns (module-level for performance) ----------

# CEF: can appear after an optional syslog header
_RE_CEF = re.compile(r"CEF:\d+\|")

# LEEF: can appear after an optional syslog header (e.g., LEEF:1.0| or LEEF:2.0|)
_RE_LEEF = re.compile(r"LEEF:\d+(?:\.\d+)?\|")

# XML: declaration or root element tag
_RE_XML_DECL = re.compile(r"^<\?xml\s", re.IGNORECASE)
_RE_XML_TAG = re.compile(r"^<[a-zA-Z][a-zA-Z0-9_:.\-]*[\s/>]")

# Syslog RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
_RE_SYSLOG_5424 = re.compile(
    r"^<(\d{1,3})>"
    r"(\d+)\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
)

# Syslog RFC 3164: <PRI>Mmm dd HH:MM:SS
_MONTHS = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_RE_SYSLOG_3164_PRI = re.compile(
    r"^<(\d{1,3})>\s*" + _MONTHS + r"\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\s"
)
_RE_SYSLOG_3164_NO_PRI = re.compile(
    r"^" + _MONTHS + r"\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\s"
)

# CLF/Combined: IP ident user [timestamp] "METHOD path proto" status bytes
_RE_CLF = re.compile(
    r"^\S+\s+\S+\s+\S+\s+"
    r"\[[^\]]+\]\s+"
    r'"[A-Z]+\s+\S+\s+[^"]*"\s+'
    r"\d{3}\s"
)

# Max characters to scan for CEF/LEEF signature (they may be preceded by a syslog header)
_SCAN_WINDOW = 500


def detect_format(raw_log: str) -> DetectionResult:
    """Classify a raw log string into a LogFormatEnum with confidence scoring.

    Detection priority (most specific → least specific):
    1. CEF  (prefix scan)
    2. LEEF (prefix scan)
    3. JSON (structural parse)
    4. XML  (declaration/tag check)
    5. Syslog RFC 5424 (PRI + version)
    6. Syslog RFC 3164 (PRI + BSD timestamp)
    7. CLF  (Apache access log pattern)
    8. UNSTRUCTURED (fallback)
    """
    if not raw_log or not raw_log.strip():
        return DetectionResult(
            detected_format=LogFormatEnum.UNSTRUCTURED,
            confidence=0.1,
        )

    stripped = raw_log.strip()
    scan_window = stripped[:_SCAN_WINDOW]

    # --- 1. CEF ---
    if _RE_CEF.search(scan_window):
        return DetectionResult(
            detected_format=LogFormatEnum.CEF,
            confidence=0.95,
        )

    # --- 2. LEEF ---
    if _RE_LEEF.search(scan_window):
        return DetectionResult(
            detected_format=LogFormatEnum.LEEF,
            confidence=0.95,
        )

    # --- 3. JSON ---
    if stripped[0] in ("{", "["):
        try:
            json.loads(stripped)
            return DetectionResult(
                detected_format=LogFormatEnum.JSON,
                confidence=0.99,
            )
        except (json.JSONDecodeError, ValueError):
            pass  # Not valid JSON; fall through to next checks

    # --- 4. XML ---
    if _RE_XML_DECL.match(stripped):
        return DetectionResult(
            detected_format=LogFormatEnum.XML,
            confidence=0.95,
            sub_format="XML_DECLARATION",
        )
    if _RE_XML_TAG.match(stripped):
        return DetectionResult(
            detected_format=LogFormatEnum.XML,
            confidence=0.80,
            sub_format="XML_FRAGMENT",
        )

    # --- 5. Syslog RFC 5424 ---
    m_5424 = _RE_SYSLOG_5424.match(stripped)
    if m_5424:
        pri = int(m_5424.group(1))
        if 0 <= pri <= 191:
            return DetectionResult(
                detected_format=LogFormatEnum.SYSLOG,
                confidence=0.95,
                sub_format="RFC_5424",
            )

    # --- 6. Syslog RFC 3164 ---
    m_3164_pri = _RE_SYSLOG_3164_PRI.match(stripped)
    if m_3164_pri:
        pri = int(m_3164_pri.group(1))
        if 0 <= pri <= 191:
            return DetectionResult(
                detected_format=LogFormatEnum.SYSLOG,
                confidence=0.90,
                sub_format="RFC_3164",
            )

    m_3164_no_pri = _RE_SYSLOG_3164_NO_PRI.match(stripped)
    if m_3164_no_pri:
        return DetectionResult(
            detected_format=LogFormatEnum.SYSLOG,
            confidence=0.75,
            sub_format="RFC_3164_NO_PRI",
        )

    # --- 7. CLF / Combined ---
    if _RE_CLF.match(stripped):
        sub = "COMBINED" if stripped.count('"') >= 6 else "COMMON"
        return DetectionResult(
            detected_format=LogFormatEnum.CLF,
            confidence=0.92,
            sub_format=sub,
        )

    # --- 8. UNSTRUCTURED (fallback) ---
    return DetectionResult(
        detected_format=LogFormatEnum.UNSTRUCTURED,
        confidence=0.3,
    )
