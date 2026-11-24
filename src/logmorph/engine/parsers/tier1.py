"""Tier 1 Cascade Router & Dispatch Engine for deterministic fast-path parsers."""

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum
from logmorph.engine.detector import detect_format
from logmorph.engine.parsers.base import BaseParser, ParsedResult
from logmorph.engine.parsers.cef_parser import CefParser
from logmorph.engine.parsers.clf_parser import ClfParser
from logmorph.engine.parsers.json_parser import JsonLogParser
from logmorph.engine.parsers.leef_parser import LeefParser
from logmorph.engine.parsers.syslog_parser import SyslogParser
from logmorph.engine.parsers.xml_parser import XmlLogParser


class Tier1Dispatcher:
    """Orchestrates Tier 1 fast-path parser selection based on detected log format."""

    def __init__(self) -> None:
        self._parsers: dict[LogFormatEnum, BaseParser] = {
            LogFormatEnum.JSON: JsonLogParser(),
            LogFormatEnum.SYSLOG: SyslogParser(),
            LogFormatEnum.CLF: ClfParser(),
            LogFormatEnum.CEF: CefParser(),
            LogFormatEnum.LEEF: LeefParser(),
            LogFormatEnum.XML: XmlLogParser(),
        }

    def get_parser(self, format_name: LogFormatEnum) -> BaseParser | None:
        """Retrieve the dedicated parser instance for a given format."""
        return self._parsers.get(format_name)

    def parse(self, raw_log: str, detected_format: LogFormatEnum | None = None) -> ParsedResult:
        """Route raw log to its corresponding Tier 1 parser.

        If detected_format is omitted, the format detection engine will classify the log first.
        If format is UNSTRUCTURED or parsing fails, returns ParsedResult with success=False
        to signal clean fall-through to Tier 2 (Drain3 template mining).
        """
        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=detected_format or LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.RULE,
                error_message="Empty raw log line",
            )

        if detected_format is None:
            detected_format = detect_format(raw_log).detected_format

        parser = self._parsers.get(detected_format)
        if not parser:
            return ParsedResult(
                success=False,
                format=detected_format,
                parsed_by=ParsingTierEnum.RULE,
                error_message=(
                    f"Format '{detected_format}' is not supported by Tier 1 rules; "
                    "forwarding to Tier 2 template miner."
                ),
            )

        return parser.parse(raw_log)


# Module-level singleton dispatcher
_tier1_dispatcher = Tier1Dispatcher()


def parse_tier1(raw_log: str, detected_format: LogFormatEnum | None = None) -> ParsedResult:
    """Convenience function to parse a raw log using the Tier 1 fast-path cascade."""
    return _tier1_dispatcher.parse(raw_log, detected_format)
