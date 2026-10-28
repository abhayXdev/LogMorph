"""Universal Log Schema (ULS) domain models and enumerations."""

from enum import StrEnum


class SeverityEnum(StrEnum):
    """Standardized log severity levels based on RFC 5424."""

    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


class LogFormatEnum(StrEnum):
    """Supported source log formats identified by the detection engine."""

    SYSLOG = "SYSLOG"
    JSON = "JSON"
    CEF = "CEF"
    LEEF = "LEEF"
    CLF = "CLF"
    XML = "XML"
    UNSTRUCTURED = "UNSTRUCTURED"


class ParsingTierEnum(StrEnum):
    """Execution tiers of the 3-Tier Adaptive Parsing Cascade."""

    RULE = "RULE"
    TEMPLATE = "TEMPLATE"
    LLM = "LLM"
    FALLBACK = "FALLBACK"
